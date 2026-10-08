// Created by Rui MA on 26 Sep 2026

#include "EnrollmentStore.h"
#include "../DesktopApp/DesktopApp.h"
#include "EnrollmentSession.h"
#include "EnrollmentChannel.h"
#include "../Resources/resource.h"
#include "../Resources/DesktopUi.h"
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
        mutex_.value = CreateMutexW(&attributes, TRUE, unlock_windows::phone_approval::kEnrollmentWriterMutex);
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
    std::wstring fingerprint;
    std::wstring notice;
    const wchar_t* actionLabel = L"Pair iPhone";
    bool replacement = false;
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
        unlock_windows::desktop_ui::initialize();
        window_ = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_PHONE_PAIRING),
            nullptr, procedure, reinterpret_cast<LPARAM>(this));
        require(window_ != nullptr, "CreateDialogParamW(phone pairing)");
        try {
            if (!error_.empty()) throw std::runtime_error(error_);
            require(WTSRegisterSessionNotification(window_, NOTIFY_FOR_ALL_SESSIONS), "WTSRegisterSessionNotification");
            registered_ = true;
            if (!SetTimer(window_, 1, 250, nullptr)) require(FALSE, "SetTimer(enrollment confirmation)");
            unlock_windows::desktop_ui::centerOnActiveMonitor(window_);
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
    void update() {
        require(SetDlgItemTextW(window_, IDC_UI_MESSAGE, text.c_str()), "SetDlgItemTextW(pairing instructions)");
        require(SetDlgItemTextW(window_, IDC_UI_FINGERPRINT, fingerprint.c_str()), "SetDlgItemTextW(fingerprint)");
        require(SetDlgItemTextW(window_, IDC_UI_NOTICE, notice.c_str()), "SetDlgItemTextW(pairing notice)");
        require(SetDlgItemTextW(window_, IDOK, actionLabel), "SetDlgItemTextW(pairing action)");
        EnableWindow(GetDlgItem(window_, IDOK), !channel || candidateReceived_);
    }
    void pollCandidate() {
        if (!channel || candidateReceived_) return;
        std::vector<std::uint8_t> key;
        if (!channel->receiveKey(key)) return;
        requireValid();
        candidate(std::move(key));
        requireValid();
        candidateReceived_ = true;
        update();
        unlock_windows::desktop_ui::defaultButton(window_, replacement ? IDCANCEL : IDOK);
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
    static INT_PTR CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* self = reinterpret_cast<Confirmation*>(GetWindowLongPtrW(window, DWLP_USER));
        if (message == WM_INITDIALOG) {
            self = reinterpret_cast<Confirmation*>(lparam);
            self->window_ = window;
            SetWindowLongPtrW(window, DWLP_USER, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return FALSE;
        try {
            switch (message) {
            case WM_INITDIALOG:
                self->appearance_.apply(window, IDC_UI_TITLE);
                SetWindowTextW(window, self->remove ? L"Remove paired iPhone" : L"Pair iPhone");
                SetDlgItemTextW(window, IDC_UI_TITLE, self->remove ? L"Remove paired iPhone" : L"Pair your iPhone");
                SetDlgItemTextW(window, IDC_UI_ACCOUNT, (L"Windows account: " + self->target.account).c_str());
                self->update();
                unlock_windows::desktop_ui::defaultButton(window,
                    self->remove || self->replacement || self->channel ? IDCANCEL : IDOK);
                return FALSE;
            case WM_DPICHANGED:
                unlock_windows::desktop_ui::scheduleDpiAppearance(window, HIWORD(wparam));
                return FALSE;
            case unlock_windows::desktop_ui::kApplyDpiAppearance:
                self->appearance_.apply(window, IDC_UI_TITLE, static_cast<UINT>(wparam));
                return TRUE;
            case WM_CTLCOLORSTATIC:
                if (reinterpret_cast<HWND>(lparam) == GetDlgItem(window, IDC_UI_FINGERPRINT) ||
                    reinterpret_cast<HWND>(lparam) == GetDlgItem(window, IDC_UI_ACCOUNT))
                    return unlock_windows::desktop_ui::readOnlyBackground(wparam);
                return FALSE;
            case WM_COMMAND:
                if (LOWORD(wparam) == IDOK && (!self->channel || self->candidateReceived_)) self->finish(self->check());
                else if (LOWORD(wparam) == IDCANCEL) self->finish(self->invalidate(ExitCode::cancelled));
                return TRUE;
            case WM_TIMER:
                if (self->check() != ExitCode::saved) self->finish(self->result_);
                else self->pollCandidate();
                return TRUE;
            case WM_WTSSESSION_CHANGE:
                if ((static_cast<DWORD>(lparam) == self->target.session &&
                        (wparam == WTS_SESSION_LOCK || wparam == WTS_SESSION_LOGOFF ||
                         wparam == WTS_CONSOLE_DISCONNECT || wparam == WTS_REMOTE_CONNECT)) ||
                    WTSGetActiveConsoleSessionId() != self->target.session)
                    self->finish(self->invalidate(ExitCode::invalidated));
                else if (self->check() != ExitCode::saved) self->finish(self->result_);
                return TRUE;
            case WM_POWERBROADCAST:
                if (wparam == PBT_APMSUSPEND) self->finish(self->invalidate(ExitCode::invalidated));
                return TRUE;
            case WM_QUERYENDSESSION: self->finish(self->invalidate(ExitCode::invalidated)); return TRUE;
            case WM_CLOSE: self->finish(self->invalidate(ExitCode::cancelled)); return TRUE;
            }
        } catch (const EnrollmentAborted& aborted) {
            self->finish(self->invalidate(aborted.code));
            return TRUE;
        } catch (const std::exception& error) {
            self->error_ = error.what();
            self->finish(self->invalidate(ExitCode::error));
            return TRUE;
        }
        return FALSE;
    }
    HWND window_ = nullptr;
    unlock_windows::desktop_ui::DialogAppearance appearance_;
    bool candidateReceived_ = false;
    bool registered_ = false;
    bool invalidated_ = false;
    ExitCode result_ = ExitCode::cancelled;
    std::string error_;
};

ExitCode enroll(wchar_t* argv[], const unlock_windows::desktop_app::Launch& launch) {
    const bool bluetooth = launch.role == unlock_windows::desktop_app::Role::bluetoothEnrollment;
    if (!elevatedAdmin()) throw std::runtime_error("Run the enrollment role as an elevated administrator");
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
    const bool clear = bluetooth ? std::wstring_view(argv[3]) == L"remove" : launch.clear;
    if (bluetooth) {
        if (clear) {
            if (std::wstring_view(argv[2]) != L"clear") throw std::invalid_argument("Invalid removal arguments");
        }
        const std::wstring_view mode(argv[3]);
        if (mode != L"pair" && mode != L"remove") throw std::invalid_argument("Invalid enrollment mode");
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
        replace = launch.replace;
        publicKey = parsePublicKey(launch.clipboard ? clipboardText() : std::wstring(argv[2]));
    }
    if (const auto code = confirmation.check(); code != ExitCode::saved) return code;
    const auto original = store.load();
    bool alreadyRegistered = false;
    if (clear && !original) {
        MessageBoxW(nullptr, L"No phone is registered.", L"Phone enrollment", MB_OK | MB_ICONINFORMATION);
        return ExitCode::rejected;
    }
    confirmation.remove = clear;
    auto prepareCandidate = [&] {
        EnrollmentStore::validatePublicKey(publicKey);
        const auto action = classifyCandidate(original, publicKey, confirmation.target.sid);
        alreadyRegistered = action == CandidateAction::alreadyRegistered;
        if (!bluetooth && !alreadyRegistered && ((original && !replace) || (!original && replace))) {
            MessageBoxW(nullptr, original ? L"A different iPhone is registered. Use --replace to replace it explicitly."
                : L"No iPhone is registered. Omit --replace for first pairing.", L"Pair iPhone", MB_OK | MB_ICONWARNING);
            throw EnrollmentAborted(ExitCode::rejected);
        }
        confirmation.replacement = action == CandidateAction::replace;
        confirmation.actionLabel = alreadyRegistered ? L"Confirm" : L"Pair iPhone";
        confirmation.text = L"Compare all eight fingerprint groups below with your iPhone.\r\nOnly continue if every group matches.";
        confirmation.fingerprint = groupedFingerprint(EnrollmentStore::fingerprint(publicKey));
        confirmation.notice = alreadyRegistered ? L"This iPhone is already paired. Your registration will not change." :
            confirmation.replacement ? L"Pairing this iPhone will replace the current registration. The previously paired iPhone will no longer unlock this PC." :
            L"This iPhone will be the only phone allowed to approve unlocking this PC.";
    };
    if (clear) {
        if (!bluetooth) {
            std::cout << "Type REMOVE to continue: ";
            std::string word;
            std::getline(std::cin, word);
            if (word != "REMOVE") return ExitCode::cancelled;
        }
        confirmation.actionLabel = L"Remove";
        confirmation.text = L"Remove this PC's paired iPhone registration? You will need to pair an iPhone again to use phone unlock.";
        confirmation.notice = L"This iPhone will no longer unlock this PC. Your saved Windows password will not be removed.";
    } else if (channel) {
        confirmation.text = L"Open the iPhone app and choose its Windows registration action. Keep your iPhone nearby.";
        confirmation.fingerprint = L"Waiting for your iPhone...";
        confirmation.notice = L"Pairing expires two minutes after choosing Pair iPhone on this PC. You can cancel without changing the current registration.";
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

int unlock_windows::desktop_app::runEnrollment(wchar_t* argv[], const Launch& launch) {
    const bool bluetooth = launch.role == Role::bluetoothEnrollment;
    try {
        const auto result = enroll(argv, launch);
        if (!bluetooth) std::cout << "Enrollment exit code: " << static_cast<DWORD>(result) << '\n';
        return static_cast<int>(result);
    } catch (const EnrollmentAborted& error) {
        OutputDebugStringW((L"Enrollment role: enrollment ended, exit code=" +
            std::to_wstring(static_cast<DWORD>(error.code)) + L"\n").c_str());
        return static_cast<int>(error.code);
    } catch (const std::exception& error) {
        std::cerr << "[Unlock with iPhone] " << error.what() << '\n';
        const std::string message(error.what());
        MessageBoxW(nullptr, std::wstring(message.begin(), message.end()).c_str(), L"Phone enrollment failed", MB_OK | MB_ICONERROR);
        return static_cast<int>(ExitCode::error);
    }
}
