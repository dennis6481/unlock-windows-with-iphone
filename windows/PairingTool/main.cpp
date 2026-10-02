// Created by Rui MA on 26 Sep 2026

#include "EnrollmentStore.h"
#include "EnrollmentSession.h"
#include "EnrollmentChannel.h"
#include "SavedCredentialIpc.h"

#include <Windows.h>
#include <cctype>
#include <iostream>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace unlock_windows::enrollment;
using unlock_windows::phone_approval::EnrollmentRecord;
using unlock_windows::phone_approval::EnrollmentStore;

struct EnrollmentAborted final : std::runtime_error {
    explicit EnrollmentAborted(ExitCode value)
        : std::runtime_error("Enrollment cancelled, expired or console changed"), code(value) {}
    ExitCode code;
};

std::uint8_t hexDigit(char value) {
    if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<std::uint8_t>(value - 'A' + 10);
    throw std::invalid_argument("Public key contains a non-hex character");
}

std::vector<std::uint8_t> parsePublicKey(std::wstring_view encoded) {
    std::string normalized;
    for (const wchar_t value : encoded) {
        if (value > 127) throw std::invalid_argument("Public key contains a non-ASCII character");
        if (!std::isspace(static_cast<unsigned char>(value))) normalized += static_cast<char>(value);
    }
    if (normalized.size() != 130) throw std::invalid_argument("Public key must contain exactly 130 hex digits");
    std::vector<std::uint8_t> result;
    for (std::size_t index = 0; index < normalized.size(); index += 2)
        result.push_back(static_cast<std::uint8_t>((hexDigit(normalized[index]) << 4) | hexDigit(normalized[index + 1])));
    EnrollmentStore::validatePublicKey(result);
    return result;
}

std::wstring clipboardText() {
    require(OpenClipboard(nullptr), "OpenClipboard");
    struct Clipboard final { ~Clipboard() { CloseClipboard(); } } clipboard;
    const HANDLE handle = GetClipboardData(CF_UNICODETEXT);
    if (!handle) throw std::runtime_error("Clipboard does not contain Unicode text");
    const auto text = static_cast<const wchar_t*>(GlobalLock(handle));
    if (!text) throw std::runtime_error("Could not lock clipboard text");
    const std::wstring result(text);
    GlobalUnlock(handle);
    return result;
}

ULONGLONG number(std::wstring_view value) {
    if (value.empty() || value.find_first_not_of(L"0123456789") != std::wstring_view::npos)
        throw std::invalid_argument("Invalid numeric enrollment argument");
    return std::stoull(std::wstring(value));
}

bool sameRecord(const std::optional<EnrollmentRecord>& left, const std::optional<EnrollmentRecord>& right) {
    if (left.has_value() != right.has_value()) return false;
    return !left || (left->publicKey == right->publicKey && left->accountSid == right->accountSid);
}

void reloadEnrollment() {
    unlock_windows::saved_credential::Packet response;
    unlock_windows::saved_credential::CallDiagnostics diagnostics;
    if (!unlock_windows::saved_credential::call(
            unlock_windows::saved_credential::Operation::reloadPhoneEnrollment,
            unlock_windows::saved_credential::SensitiveBytes{}, response, 2000, &diagnostics) ||
        response.result != unlock_windows::saved_credential::Result::success) {
        const std::wstring stage(unlock_windows::saved_credential::callStageName(diagnostics.stage));
        const std::wstring check(diagnostics.serverCheck);
        throw std::runtime_error("Service enrollment reload failed: Win32=" + std::to_string(diagnostics.win32Error) +
            ", stage=" + std::string(stage.begin(), stage.end()) + ", check=" + std::string(check.begin(), check.end()) +
            ", result=" + std::to_string(static_cast<DWORD>(response.result)));
    }
}

class EnrollmentWriter final {
public:
    EnrollmentWriter() {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1, &descriptor, nullptr), "Enrollment writer mutex ACL");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        mutex_.value = CreateMutexW(&attributes, TRUE, L"Global\\UnlockWindowsWithIPhone-EnrollmentWriter");
        const DWORD error = GetLastError();
        LocalFree(descriptor);
        if (!mutex_.value) { SetLastError(error); require(FALSE, "CreateMutexW(enrollment writer)"); }
        if (error == ERROR_ALREADY_EXISTS) {
            const DWORD wait = WaitForSingleObject(mutex_.value, 0);
            if (wait == WAIT_TIMEOUT) { busy_ = true; return; }
            if (wait == WAIT_FAILED) require(FALSE, "WaitForSingleObject(enrollment writer)");
            if (wait == WAIT_ABANDONED) {
                ReleaseMutex(mutex_.value);
                throw std::runtime_error("Previous enrollment writer exited without releasing its mutex; retry explicitly");
            }
        }
        owned_ = true;
    }
    ~EnrollmentWriter() { if (owned_) ReleaseMutex(mutex_.value); }
    bool busy() const { return busy_; }
private:
    Handle mutex_;
    bool owned_ = false;
    bool busy_ = false;
};

class Confirmation final {
public:
    Console target;
    ULONGLONG deadline = 0;
    HANDLE cancel = nullptr;
    HANDLE parent = nullptr;
    std::wstring text;
    bool remove = false;
    EnrollmentChannel* channel = nullptr;
    std::function<void(std::vector<std::uint8_t>)> candidate;

    ExitCode check() {
        if (invalidated_) return result_;
        if (GetTickCount64() >= deadline) return invalidate(ExitCode::expired);
        for (const HANDLE handle : {cancel, parent}) {
            if (!handle) continue;
            const DWORD wait = WaitForSingleObject(handle, 0);
            if (wait == WAIT_FAILED) require(FALSE, "WaitForSingleObject(enrollment lifetime)");
            if (wait == WAIT_OBJECT_0) return invalidate(ExitCode::cancelled);
        }
        const auto console = queryConsole();
        if (console.locked || console.session != target.session || console.sid != target.sid)
            return invalidate(ExitCode::invalidated);
        return ExitCode::saved;
    }
    void requireValid() {
        if (const auto code = check(); code != ExitCode::saved) throw EnrollmentAborted(code);
    }
    ExitCode run() {
        if (const auto code = check(); code != ExitCode::saved) return code;
        WNDCLASSW windowClass{};
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.lpszClassName = L"UnlockWindowsEnrollmentConfirmation";
        windowClass.lpfnWndProc = procedure;
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        require(RegisterClassW(&windowClass), "RegisterClassW(enrollment confirmation)");
        window_ = CreateWindowExW(WS_EX_TOPMOST, windowClass.lpszClassName,
            remove ? L"Remove phone enrollment" : L"Confirm phone enrollment",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 660, 360,
            nullptr, nullptr, windowClass.hInstance, this);
        require(window_ != nullptr, "CreateWindowExW(enrollment confirmation)");
        try {
            textWindow_ = CreateWindowExW(0, L"STATIC", text.c_str(), WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
                20, 20, 610, 230, window_, nullptr, windowClass.hInstance, nullptr);
            require(textWindow_ != nullptr, "CreateWindowExW(enrollment text)");
            confirmButton_ = CreateWindowExW(0, L"BUTTON", remove ? L"Remove enrollment" : L"Fingerprints match - confirm",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON | (channel ? WS_DISABLED : 0),
                20, 265, 350, 32, window_, reinterpret_cast<HMENU>(1), windowClass.hInstance, nullptr);
            require(confirmButton_ != nullptr, "CreateWindowExW(enrollment confirm)");
            require(CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                410, 265, 180, 32, window_, reinterpret_cast<HMENU>(2), windowClass.hInstance, nullptr) != nullptr,
                "CreateWindowExW(enrollment cancel)");
            require(WTSRegisterSessionNotification(window_, NOTIFY_FOR_ALL_SESSIONS), "WTSRegisterSessionNotification");
            registered_ = true;
            if (!SetTimer(window_, 1, 250, nullptr)) require(FALSE, "SetTimer(enrollment confirmation)");
            ShowWindow(window_, SW_SHOW);
            SetForegroundWindow(window_);
            if (channel) { requireValid(); channel->announceReady(); }
            MSG message{};
            BOOL received;
            while ((received = GetMessageW(&message, nullptr, 0, 0)) > 0) {
                if (!IsDialogMessageW(window_, &message)) {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            if (received == -1) require(FALSE, "GetMessageW(enrollment confirmation)");
            cleanup();
            if (!error_.empty()) throw std::runtime_error(error_);
            return result_;
        } catch (...) { cleanup(); throw; }
    }
private:
    void pollCandidate() {
        if (!channel || candidateReceived_) return;
        std::vector<std::uint8_t> key;
        if (!channel->receiveKey(key)) return;
        requireValid();
        candidate(std::move(key));
        requireValid();
        candidateReceived_ = true;
        require(SetWindowTextW(textWindow_, text.c_str()), "SetWindowTextW(enrollment fingerprint)");
        EnableWindow(confirmButton_, TRUE);
        SetForegroundWindow(window_);
    }
    ExitCode invalidate(ExitCode code) { invalidated_ = true; result_ = code; return code; }
    void cleanup() {
        if (registered_) {
            registered_ = false;
            if (!WTSUnRegisterSessionNotification(window_))
                error_ += " WTSUnRegisterSessionNotification failed: " + std::to_string(GetLastError());
        }
        if (window_) { DestroyWindow(window_); window_ = nullptr; }
    }
    void finish(ExitCode code) { result_ = code; PostQuitMessage(0); }
    static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* self = reinterpret_cast<Confirmation*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Confirmation*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(window, message, wparam, lparam);
        try {
            switch (message) {
            case WM_COMMAND:
                if (LOWORD(wparam) == 1 && (!self->channel || self->candidateReceived_)) self->finish(self->check());
                else if (LOWORD(wparam) == 2) self->finish(self->invalidate(ExitCode::cancelled));
                return 0;
            case WM_TIMER:
                if (self->check() != ExitCode::saved) self->finish(self->result_);
                else self->pollCandidate();
                return 0;
            case WM_WTSSESSION_CHANGE:
                if ((static_cast<DWORD>(lparam) == self->target.session &&
                        (wparam == WTS_SESSION_LOCK || wparam == WTS_SESSION_LOGOFF ||
                         wparam == WTS_CONSOLE_DISCONNECT || wparam == WTS_REMOTE_CONNECT)) ||
                    WTSGetActiveConsoleSessionId() != self->target.session)
                    self->finish(self->invalidate(ExitCode::invalidated));
                else if (self->check() != ExitCode::saved) self->finish(self->result_);
                return 0;
            case WM_POWERBROADCAST:
                if (wparam == PBT_APMSUSPEND) self->finish(self->invalidate(ExitCode::invalidated));
                return TRUE;
            case WM_QUERYENDSESSION: self->finish(self->invalidate(ExitCode::invalidated)); return TRUE;
            case WM_CLOSE: self->finish(self->invalidate(ExitCode::cancelled)); return 0;
            }
        } catch (const EnrollmentAborted& aborted) {
            self->finish(self->invalidate(aborted.code));
            return 0;
        } catch (const std::exception& error) {
            self->error_ = error.what();
            self->finish(self->invalidate(ExitCode::error));
            return 0;
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }
    HWND window_ = nullptr;
    HWND textWindow_ = nullptr;
    HWND confirmButton_ = nullptr;
    bool candidateReceived_ = false;
    bool registered_ = false;
    bool invalidated_ = false;
    ExitCode result_ = ExitCode::cancelled;
    std::string error_;
};

ExitCode enroll(int argc, wchar_t* argv[], bool bluetooth) {
    if (!elevatedAdmin()) throw std::runtime_error("Run PairingTool as an elevated administrator");
    EnrollmentWriter writer;
    if (writer.busy()) return ExitCode::busy;
    EnrollmentStore store;
    Confirmation confirmation;
    confirmation.target = queryConsole();
    if (confirmation.target.locked) return ExitCode::invalidated;
    DWORD processSession = 0;
    require(ProcessIdToSessionId(GetCurrentProcessId(), &processSession), "ProcessIdToSessionId");
    if (processSession != confirmation.target.session) return ExitCode::invalidated;
    confirmation.deadline = GetTickCount64() + kPairingLifetime;
    Handle cancel;
    Handle parent;
    std::unique_ptr<EnrollmentChannel> channel;
    bool replace = false;
    std::vector<std::uint8_t> publicKey;
    const bool clear = bluetooth ? argc == 9 && std::wstring_view(argv[3]) == L"remove" :
        argc == 2 && std::wstring_view(argv[1]) == L"--clear";
    if (bluetooth) {
        if (argc != 9) throw std::invalid_argument("Invalid Bluetooth enrollment arguments");
        if (clear) {
            if (std::wstring_view(argv[2]) != L"clear") throw std::invalid_argument("Invalid removal arguments");
        }
        const std::wstring_view mode(argv[3]);
        if (mode != L"first" && mode != L"replace" && mode != L"remove") throw std::invalid_argument("Invalid enrollment mode");
        replace = mode == L"replace";
        if (number(argv[4]) != confirmation.target.session || std::wstring_view(argv[5]) != confirmation.target.sid)
            return ExitCode::invalidated;
        confirmation.deadline = number(argv[6]);
        const auto now = GetTickCount64();
        if (confirmation.deadline <= now) return ExitCode::expired;
        if (confirmation.deadline - now > kPairingLifetime) throw std::invalid_argument("Invalid pairing deadline");
        const std::wstring_view event(argv[7]);
        const std::wstring_view prefix(kCancelPrefix);
        if (!event.starts_with(prefix) || event.size() != prefix.size() + 32 ||
            event.substr(prefix.size()).find_first_not_of(L"0123456789abcdef") != std::wstring_view::npos)
            throw std::invalid_argument("Invalid pairing cancellation event");
        cancel.value = OpenEventW(SYNCHRONIZE, FALSE, argv[7]);
        require(cancel.value != nullptr, "OpenEventW(pairing cancellation)");
        const auto pid = number(argv[8]);
        if (pid == 0 || pid > MAXDWORD) throw std::invalid_argument("Invalid pairing parent PID");
        DWORD parentSession = 0;
        require(ProcessIdToSessionId(static_cast<DWORD>(pid), &parentSession), "ProcessIdToSessionId(pairing parent)");
        if (parentSession != confirmation.target.session) return ExitCode::invalidated;
        parent.value = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
        require(parent.value != nullptr, "OpenProcess(pairing parent)");
        Handle parentToken;
        require(OpenProcessToken(parent.value, TOKEN_QUERY, &parentToken.value), "OpenProcessToken(pairing parent)");
        DWORD tokenBytes = 0;
        GetTokenInformation(parentToken.value, TokenUser, nullptr, 0, &tokenBytes);
        require(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "GetTokenInformation(pairing parent size)");
        std::vector<BYTE> tokenData(tokenBytes);
        require(GetTokenInformation(parentToken.value, TokenUser, tokenData.data(), tokenBytes, &tokenBytes),
            "GetTokenInformation(pairing parent)");
        if (sidText(reinterpret_cast<TOKEN_USER*>(tokenData.data())->User.Sid) != confirmation.target.sid)
            throw std::runtime_error("Pairing parent does not belong to the target console user");
        confirmation.cancel = cancel.value;
        confirmation.parent = parent.value;
        if (!clear) {
            channel = std::make_unique<EnrollmentChannel>(argv[2], confirmation.target.sid, static_cast<DWORD>(pid));
            confirmation.channel = channel.get();
        }
    } else if (!clear) {
        const std::wstring_view command(argv[1]);
        const bool clipboard = command == L"--key-clipboard";
        const bool hex = command == L"--key-hex";
        const int expected = clipboard ? 2 : 3;
        if ((!clipboard && !hex) || argc < expected || argc > expected + 1)
            throw std::invalid_argument("Usage: --key-hex <key> [--replace], --key-clipboard [--replace], or --clear");
        replace = argc == expected + 1;
        if (replace && std::wstring_view(argv[expected]) != L"--replace") throw std::invalid_argument("Expected --replace");
        publicKey = parsePublicKey(clipboard ? clipboardText() : std::wstring(argv[2]));
    }
    if (const auto code = confirmation.check(); code != ExitCode::saved) return code;
    const auto original = store.load();
    bool alreadyRegistered = false;
    if (clear && !original) {
        MessageBoxW(nullptr, L"No phone is registered.", L"Phone enrollment", MB_OK | MB_ICONINFORMATION);
        return ExitCode::rejected;
    }
    confirmation.remove = clear;
    const auto accountText = L"Target Windows account: " + confirmation.target.account + L"\r\n\r\n";
    confirmation.text = accountText;
    auto prepareCandidate = [&] {
        EnrollmentStore::validatePublicKey(publicKey);
        alreadyRegistered = original && original->accountSid == confirmation.target.sid && original->publicKey == publicKey;
        if (!alreadyRegistered && ((original && !replace) || (!original && replace))) {
            MessageBoxW(nullptr, original ? L"A phone is already registered. Select Replace phone on Windows."
                : L"No phone is registered. Select Pair phone on Windows.", L"Phone enrollment", MB_OK | MB_ICONWARNING);
            throw EnrollmentAborted(ExitCode::rejected);
        }
        confirmation.text = accountText + L"Compare every group with the fingerprint on your iPhone:\r\n\r\n" +
            groupedFingerprint(EnrollmentStore::fingerprint(publicKey)) + L"\r\n\r\n" +
            (alreadyRegistered ? L"This phone is already registered. The enrollment file will not be rewritten.\r\n" :
                replace ? L"REPLACE: the previously registered phone will no longer be accepted.\r\n" : L"First phone enrollment.\r\n") +
            L"Only confirm if the complete fingerprints match.";
    };
    if (clear) {
        if (!bluetooth) {
            std::cout << "Type REMOVE to continue: ";
            std::string word;
            std::getline(std::cin, word);
            if (word != "REMOVE") return ExitCode::cancelled;
        }
        confirmation.text += L"Remove the registered phone key? Phone approval will stop working.";
    } else if (channel) {
        confirmation.text += L"Waiting for your iPhone.\r\n\r\nSelect Register to Windows in the iPhone app.\r\n"
            L"The complete fingerprint will appear here when the public key arrives.\r\n\r\n"
            L"This pairing expires two minutes after clicking Pair phone on Windows.";
        confirmation.candidate = [&](std::vector<std::uint8_t> key) {
            publicKey = std::move(key);
            prepareCandidate();
        };
    } else prepareCandidate();
    const auto accepted = confirmation.run();
    if (accepted != ExitCode::saved) return accepted;
    auto beforeCommit = [&] {
        confirmation.requireValid();
        if (!sameRecord(original, store.load())) throw std::runtime_error("Enrollment changed during confirmation; start again");
    };
    beforeCommit();
    reloadEnrollment();
    beforeCommit();
    if (alreadyRegistered) return ExitCode::alreadyRegistered;
    if (clear) store.remove();
    else store.save({publicKey, confirmation.target.sid}, beforeCommit);
    try { reloadEnrollment(); }
    catch (const std::exception& error) {
        const std::string message = std::string(clear ? "Enrollment removed, service reload failed. "
            : "Enrollment saved, service reload failed. ") + error.what();
        MessageBoxW(nullptr, std::wstring(message.begin(), message.end()).c_str(), L"Phone enrollment", MB_OK | MB_ICONERROR);
        return ExitCode::savedReloadFailed;
    }
    return ExitCode::saved;
}
}

int wmain(int argc, wchar_t* argv[]) {
    const bool bluetooth = argc >= 2 && std::wstring_view(argv[1]) == L"--bluetooth";
    try {
        if (bluetooth && GetConsoleWindow()) require(FreeConsole(), "FreeConsole");
        if (argc < 2) throw std::invalid_argument("Specify --key-hex, --key-clipboard or --clear");
        const auto result = enroll(argc, argv, bluetooth);
        if (!bluetooth) std::cout << "Enrollment exit code: " << static_cast<DWORD>(result) << '\n';
        return static_cast<int>(result);
    } catch (const EnrollmentAborted& error) {
        OutputDebugStringW((L"PairingTool: enrollment ended, exit code=" +
            std::to_wstring(static_cast<DWORD>(error.code)) + L"\n").c_str());
        return static_cast<int>(error.code);
    } catch (const std::exception& error) {
        std::cerr << "[PairingTool] " << error.what() << '\n';
        const std::string message(error.what());
        MessageBoxW(nullptr, std::wstring(message.begin(), message.end()).c_str(), L"Phone enrollment failed", MB_OK | MB_ICONERROR);
        return static_cast<int>(ExitCode::error);
    }
}
