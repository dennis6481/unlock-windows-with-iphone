// Created by Rui MA on 26 Sep 2026

#include "EnrollmentStore.h"
#include "../DesktopApp/DesktopApp.h"
#include "EnrollmentSession.h"
#include "EnrollmentChannel.h"
#include "../Resources/resource.h"
#include "../DesktopApp/DesktopApplication.h"
#include "../DesktopApp/DesktopNotifications.h"
#include "../DesktopApp/Dashboard/Pages/PageControls.h"
#include <microsoft.ui.xaml.window.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <winrt/Windows.System.h>
#include <commctrl.h>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>
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

struct EnrollmentView final {
    DWORD session = 0xffffffff;
    std::wstring account, text, fingerprint, notice;
    std::wstring action = L"Pair iPhone";
    bool remove = false;
    bool destructive = false;
    bool canConfirm = false;
    bool waiting = false;
    bool busy = false;
};

struct EnrollmentUi final {
    std::mutex mutex;
    std::condition_variable wake;
    EnrollmentView view;
    bool present = false;
    bool changed = false;
    bool started = false;
    bool tick = false;
    bool confirmed = false;
    bool done = false;
    std::optional<ExitCode> cancellation;
    ExitCode result = ExitCode::cancelled;
    std::wstring message, title, displayError;
    unlock_windows::desktop_app::NoticeSeverity severity = unlock_windows::desktop_app::NoticeSeverity::error;

    void cancel(ExitCode code) {
        std::lock_guard lock(mutex);
        if (!done && !cancellation) cancellation = code;
        wake.notify_all();
    }
    void publish(EnrollmentView value) {
        std::lock_guard lock(mutex);
        view = std::move(value);
        present = changed = true;
        wake.notify_all();
    }
    void notice(std::wstring value, std::wstring caption,
        unlock_windows::desktop_app::NoticeSeverity kind = unlock_windows::desktop_app::NoticeSeverity::error) {
        OutputDebugStringW((caption + L": " + value + L"\n").c_str());
        std::lock_guard lock(mutex);
        message = std::move(value);
        title = std::move(caption);
        severity = kind;
    }
};

class Confirmation final {
public:
    explicit Confirmation(EnrollmentUi& ui) : ui_(ui) {}
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
        {
            std::lock_guard lock(ui_.mutex);
            if (ui_.cancellation) return invalidate(*ui_.cancellation);
        }
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
        update();
        {
            std::unique_lock lock(ui_.mutex);
            ui_.wake.wait(lock, [&] { return ui_.started || ui_.cancellation.has_value(); });
        }
        requireValid();
        if (channel) channel->announceReady();
        for (;;) {
            std::unique_lock lock(ui_.mutex);
            ui_.wake.wait(lock, [&] { return ui_.tick || ui_.confirmed || ui_.cancellation.has_value(); });
            const bool accepted = std::exchange(ui_.confirmed, false);
            ui_.tick = false;
            lock.unlock();
            if (const auto code = check(); code != ExitCode::saved) return code;
            pollCandidate();
            if (!accepted || (channel && !candidateReceived_)) continue;
            requireValid();
            update(true);
            return ExitCode::saved;
        }
    }
private:
    void update(bool busy = false) {
        EnrollmentView view;
        view.session = target.session;
        view.account = target.account;
        view.text = text;
        view.fingerprint = fingerprint;
        view.notice = notice;
        view.action = actionLabel;
        view.remove = remove;
        view.destructive = remove || replacement;
        view.canConfirm = !busy && (!channel || candidateReceived_);
        view.waiting = channel && !candidateReceived_;
        view.busy = busy;
        ui_.publish(std::move(view));
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
    }
    ExitCode invalidate(ExitCode code) { invalidated_ = true; result_ = code; return code; }
    EnrollmentUi& ui_;
    bool candidateReceived_ = false;
    bool invalidated_ = false;
    ExitCode result_ = ExitCode::cancelled;
};

class EnrollmentWindow final : public std::enable_shared_from_this<EnrollmentWindow> {
public:
    explicit EnrollmentWindow(std::shared_ptr<EnrollmentUi> ui) : ui_(std::move(ui)) {}
    ~EnrollmentWindow() {
        try {
            ui_->cancel(ExitCode::error);
            cleanup();
            if (window_ && !closed_) window_.Close();
        }
        catch (...) { unlock_windows::desktop_app::showNativeUiError(L"Could not release the pairing window.",
            unlock_windows::desktop_app::dashboard_ui::currentException(), L"Phone enrollment failed"); }
    }
    void show() {
        using namespace winrt;
        using namespace Microsoft::UI::Xaml;
        using namespace Microsoft::UI::Xaml::Controls;
        using unlock_windows::desktop_app::dashboard_ui::text;
        window_ = Window{};
        appWindow_ = window_.AppWindow();
        appWindow_.TitleBar().PreferredTheme(Microsoft::UI::Windowing::TitleBarTheme::UseDefaultAppMode);
        check_hresult(window_.as<IWindowNative>()->get_WindowHandle(&hwnd_));
        const auto dpi = GetDpiForWindow(hwnd_);
        appWindow_.Resize({MulDiv(600, dpi, 96), MulDiv(570, dpi, 96)});
        const auto appIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_UNLOCK_APP));
        if (!appIcon) throw_last_error();
        SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(appIcon));
        SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(appIcon));
        StackPanel content;
        content.Margin({28, 24, 28, 24});
        content.Spacing(16);
        title_ = text(L"Pair your iPhone", 24);
        account_ = text(L"", 18);
        instructions_ = text(L"");
        content.Children().Append(title_);
        content.Children().Append(account_);
        content.Children().Append(instructions_);
        progress_ = ProgressRing{};
        progress_.Width(28);
        progress_.Height(28);
        progress_.HorizontalAlignment(HorizontalAlignment::Left);
        content.Children().Append(progress_);
        fingerprint_ = TextBox{};
        fingerprint_.Header(box_value(L"iPhone fingerprint"));
        fingerprint_.IsReadOnly(true);
        fingerprint_.AcceptsReturn(true);
        fingerprint_.TextWrapping(TextWrapping::Wrap);
        fingerprint_.FontFamily(Microsoft::UI::Xaml::Media::FontFamily(L"Consolas"));
        content.Children().Append(fingerprint_);
        notice_ = InfoBar{};
        notice_.IsClosable(false);
        content.Children().Append(notice_);
        StackPanel actions;
        actions.Orientation(Orientation::Horizontal);
        actions.HorizontalAlignment(HorizontalAlignment::Right);
        actions.Spacing(12);
        action_ = Button{};
        action_.Style(Application::Current().Resources().Lookup(box_value(L"AccentButtonStyle")).as<Style>());
        cancel_ = Button{};
        cancel_.Content(box_value(L"Cancel"));
        const auto weak = weak_from_this();
        content.Loaded([weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) {
                try { self->focusAction(); }
                catch (...) { self->displayFailure(); }
            }
        });
        action_.Click([weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) self->accept();
        });
        cancel_.Click([weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) self->ui_->cancel(ExitCode::cancelled);
        });
        Input::KeyboardAccelerator escape;
        escape.Key(Windows::System::VirtualKey::Escape);
        escape.Invoked([weak](const auto&, const auto& args) {
            args.Handled(true);
            if (const auto self = weak.lock()) {
                bool done;
                { std::lock_guard lock(self->ui_->mutex); done = self->ui_->done; }
                if (done) self->accept();
                else self->ui_->cancel(ExitCode::cancelled);
            }
        });
        content.KeyboardAccelerators().Append(escape);
        actions.Children().Append(action_);
        actions.Children().Append(cancel_);
        content.Children().Append(actions);
        ScrollViewer scroll;
        scroll.HorizontalScrollBarVisibility(ScrollBarVisibility::Disabled);
        scroll.Content(content);
        window_.Content(scroll);
        closingToken_ = appWindow_.Closing([weak](const auto&, const auto& args) {
            if (const auto self = weak.lock()) {
                args.Cancel(true);
                bool done;
                { std::lock_guard lock(self->ui_->mutex); done = self->ui_->done; }
                if (!done) self->ui_->cancel(ExitCode::cancelled);
                else {
                    try { self->close(); }
                    catch (...) { self->displayFailure(); }
                }
            }
        });
        closedToken_ = window_.Closed([weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) {
                self->closed_ = true;
                self->ui_->cancel(ExitCode::cancelled);
            }
        });
        require(SetWindowSubclass(hwnd_, procedure, 1, reinterpret_cast<DWORD_PTR>(this)), "SetWindowSubclass(pairing)");
        subclassed_ = true;
        require(WTSRegisterSessionNotification(hwnd_, NOTIFY_FOR_ALL_SESSIONS), "WTSRegisterSessionNotification");
        registered_ = true;
        dispatcher_ = window_.DispatcherQueue();
        timer_ = dispatcher_.CreateTimer();
        timer_.Interval(std::chrono::milliseconds(250));
        timerToken_ = timer_.Tick([weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) {
                try { self->poll(); }
                catch (...) { self->displayFailure(); }
            }
        });
        poll();
        if (closed_) return;
        window_.Activate();
        timer_.Start();
        {
            std::lock_guard lock(ui_->mutex);
            ui_->started = true;
            ui_->wake.notify_all();
        }
    }
    void cleanup() {
        if (registered_) {
            registered_ = false;
            require(WTSUnRegisterSessionNotification(hwnd_), "WTSUnRegisterSessionNotification(pairing)");
        }
        if (subclassed_) {
            subclassed_ = false;
            require(RemoveWindowSubclass(hwnd_, procedure, 1), "RemoveWindowSubclass(pairing)");
        }
        if (appWindow_ && closingToken_.value) appWindow_.Closing(closingToken_);
        closingToken_ = {};
        if (window_ && closedToken_.value) window_.Closed(closedToken_);
        closedToken_ = {};
        if (timer_) { timer_.Stop(); timer_.Tick(timerToken_); timer_ = nullptr; }
    }
private:
    void focusAction() {
        bool safe;
        {
            std::lock_guard lock(ui_->mutex);
            safe = !ui_->done && (ui_->view.destructive || !ui_->view.canConfirm);
        }
        (safe ? cancel_ : action_).Focus(winrt::Microsoft::UI::Xaml::FocusState::Programmatic);
    }
    void accept() {
        try {
            bool done;
            {
                std::lock_guard lock(ui_->mutex);
                done = ui_->done;
                if (!done && ui_->view.canConfirm && !ui_->cancellation && !ui_->confirmed) {
                    ui_->confirmed = true;
                    ui_->wake.notify_all();
                } else if (!done) return;
            }
            if (done) close();
            else action_.IsEnabled(false);
        } catch (...) { displayFailure(); }
    }
    void poll() {
        using namespace winrt;
        using namespace Microsoft::UI::Xaml;
        using namespace Microsoft::UI::Xaml::Controls;
        EnrollmentView view;
        std::wstring message, title, displayError;
        unlock_windows::desktop_app::NoticeSeverity severity;
        bool changed, done;
        {
            std::lock_guard lock(ui_->mutex);
            view = ui_->view;
            changed = std::exchange(ui_->changed, false);
            done = ui_->done;
            message = ui_->message;
            title = ui_->title;
            displayError = ui_->displayError;
            severity = ui_->severity;
            ui_->tick = true;
            ui_->wake.notify_all();
        }
        if (!displayError.empty()) {
            if (done) {
                if (!message.empty() && !resultShown_) {
                    resultShown_ = true;
                    unlock_windows::desktop_app::showNativeUiError(message, displayError, title);
                }
                close();
            }
            return;
        }
        if (done && (closed_ || message.empty())) { close(); return; }
        if (closed_) return;
        if (changed) {
            window_.Title(view.remove ? L"Remove paired iPhone" : L"Pair iPhone");
            title_.Text(view.remove ? L"Remove paired iPhone" : L"Pair your iPhone");
            account_.Text(L"Windows account: " + view.account);
            instructions_.Text(view.busy ? L"Applying your confirmed operation..." : view.text);
            fingerprint_.Text(view.fingerprint);
            fingerprint_.Visibility(view.remove ? Visibility::Collapsed : Visibility::Visible);
            progress_.IsActive(view.waiting || view.busy);
            progress_.Visibility(view.waiting || view.busy ? Visibility::Visible : Visibility::Collapsed);
            notice_.Severity(view.destructive ? InfoBarSeverity::Warning : InfoBarSeverity::Informational);
            notice_.Title(L"");
            notice_.Message(view.notice);
            notice_.IsOpen(!view.notice.empty());
            action_.Content(box_value(view.action));
            action_.IsEnabled(view.canConfirm);
            if (!view.busy) focusAction();
        }
        if (done && !resultShown_) {
            resultShown_ = true;
            window_.Title(title);
            title_.Text(title);
            account_.Visibility(view.account.empty() ? Visibility::Collapsed : Visibility::Visible);
            fingerprint_.Visibility(view.fingerprint.empty() ? Visibility::Collapsed : Visibility::Visible);
            instructions_.Text(L"The operation has finished. Close this window to return to the desktop app.");
            progress_.IsActive(false);
            progress_.Visibility(Visibility::Collapsed);
            notice_.Severity(unlock_windows::desktop_app::dashboard_ui::infoBarSeverity(severity));
            notice_.Message(message);
            notice_.IsOpen(true);
            action_.Content(box_value(L"Close"));
            action_.IsEnabled(true);
            cancel_.Visibility(Visibility::Collapsed);
        }
    }
    void close() {
        cleanup();
        if (!closed_) { window_.Close(); closed_ = true; }
        winrt::Microsoft::UI::Xaml::Application::Current().Exit();
    }
    void displayFailure() {
        const auto error = unlock_windows::desktop_app::dashboard_ui::currentException();
        std::wstring message;
        bool done, alreadyFailed;
        {
            std::lock_guard lock(ui_->mutex);
            alreadyFailed = !ui_->displayError.empty();
            ui_->displayError += error + L"\n";
            done = ui_->done;
            message = ui_->message;
        }
        ui_->cancel(ExitCode::error);
        if (!alreadyFailed) unlock_windows::desktop_app::showNativeUiError(
            message.empty() ? L"The pairing interface could not continue." : message, error, L"Phone enrollment failed");
        else OutputDebugStringW((L"Pairing UI cleanup failed: " + error + L"\n").c_str());
        if (done && !message.empty()) resultShown_ = true;
        if (done) winrt::Microsoft::UI::Xaml::Application::Current().Exit();
    }
    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam,
        UINT_PTR, DWORD_PTR data) {
        auto* self = reinterpret_cast<EnrollmentWindow*>(data);
        if (message == WM_NCDESTROY) {
            self->registered_ = false;
            self->subclassed_ = false;
            self->hwnd_ = nullptr;
        } else if (message == WM_WTSSESSION_CHANGE) {
            DWORD session;
            { std::lock_guard lock(self->ui_->mutex); session = self->ui_->view.session; }
            if ((static_cast<DWORD>(lparam) == session &&
                    (wparam == WTS_SESSION_LOCK || wparam == WTS_SESSION_LOGOFF ||
                     wparam == WTS_CONSOLE_DISCONNECT || wparam == WTS_REMOTE_CONNECT)) ||
                WTSGetActiveConsoleSessionId() != session) self->ui_->cancel(ExitCode::invalidated);
        } else if ((message == WM_POWERBROADCAST && wparam == PBT_APMSUSPEND) || message == WM_QUERYENDSESSION) {
            self->ui_->cancel(ExitCode::invalidated);
        }
        return DefSubclassProc(hwnd, message, wparam, lparam);
    }
    std::shared_ptr<EnrollmentUi> ui_;
    winrt::Microsoft::UI::Xaml::Window window_{nullptr};
    winrt::Microsoft::UI::Windowing::AppWindow appWindow_{nullptr};
    winrt::Microsoft::UI::Xaml::Controls::TextBlock title_{nullptr}, account_{nullptr}, instructions_{nullptr};
    winrt::Microsoft::UI::Xaml::Controls::TextBox fingerprint_{nullptr};
    winrt::Microsoft::UI::Xaml::Controls::InfoBar notice_{nullptr};
    winrt::Microsoft::UI::Xaml::Controls::ProgressRing progress_{nullptr};
    winrt::Microsoft::UI::Xaml::Controls::Button action_{nullptr}, cancel_{nullptr};
    winrt::Microsoft::UI::Dispatching::DispatcherQueue dispatcher_{nullptr};
    winrt::Microsoft::UI::Dispatching::DispatcherQueueTimer timer_{nullptr};
    winrt::event_token timerToken_{}, closingToken_{}, closedToken_{};
    HWND hwnd_ = nullptr;
    bool registered_ = false, subclassed_ = false, closed_ = false, resultShown_ = false;
};
ExitCode enroll(wchar_t* argv[], const unlock_windows::desktop_app::Launch& launch, EnrollmentUi& ui) {
    const bool bluetooth = launch.role == unlock_windows::desktop_app::Role::bluetoothEnrollment;
    if (!elevatedAdmin()) throw std::runtime_error("Run the enrollment role as an elevated administrator");
    EnrollmentWriter writer;
    if (writer.busy()) return ExitCode::busy;
    EnrollmentStore store;
    Confirmation confirmation(ui);
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
        ui.notice(L"No phone is registered.", L"Phone enrollment", unlock_windows::desktop_app::NoticeSeverity::information);
        return ExitCode::rejected;
    }
    confirmation.remove = clear;
    auto prepareCandidate = [&] {
        EnrollmentStore::validatePublicKey(publicKey);
        const auto action = classifyCandidate(original, publicKey, confirmation.target.sid);
        alreadyRegistered = action == CandidateAction::alreadyRegistered;
        if (!bluetooth && !alreadyRegistered && ((original && !replace) || (!original && replace))) {
            ui.notice(original ? L"A different iPhone is registered. Use --replace to replace it explicitly."
                : L"No iPhone is registered. Omit --replace for first pairing.", L"Pair iPhone", unlock_windows::desktop_app::NoticeSeverity::warning);
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
        ui.notice(std::wstring(message.begin(), message.end()), L"Phone enrollment");
        return ExitCode::savedReloadFailed;
    }
    return ExitCode::saved;
}
}

int unlock_windows::desktop_app::runEnrollment(wchar_t* argv[], const Launch& launch) {
    const bool bluetooth = launch.role == Role::bluetoothEnrollment;
    auto ui = std::make_shared<EnrollmentUi>();
    std::thread worker;
    bool uiStarted = false;
    try {
        worker = std::thread([ui, argv, launch] {
            ExitCode result;
            try { result = enroll(argv, launch, *ui); }
            catch (const EnrollmentAborted& error) {
                result = error.code;
                OutputDebugStringW((L"Enrollment role: enrollment ended, exit code=" +
                    std::to_wstring(static_cast<DWORD>(result)) + L"\n").c_str());
            } catch (...) {
                const auto message = dashboard_ui::currentException();
                std::cerr << "[Unlock with iPhone] " << winrt::to_string(message) << '\n';
                ui->notice(message, L"Phone enrollment failed");
                result = ExitCode::error;
            }
            std::lock_guard lock(ui->mutex);
            ui->result = result;
            ui->done = true;
            OutputDebugStringW((L"Enrollment role completed, exit code=" +
                std::to_wstring(static_cast<DWORD>(result)) + L"\n").c_str());
            ui->wake.notify_all();
        });
        bool show;
        {
            std::unique_lock lock(ui->mutex);
            ui->wake.wait(lock, [&] { return ui->present || ui->done; });
            show = !ui->done || !ui->message.empty();
        }
        if (show) {
            winrt::init_apartment(winrt::apartment_type::single_threaded);
            struct Apartment final { ~Apartment() { winrt::uninit_apartment(); } } apartment;
            auto window = std::make_shared<EnrollmentWindow>(ui);
            winrt::com_ptr<DesktopApplication> app;
            uiStarted = true;
            winrt::Microsoft::UI::Xaml::Application::Start([&](const auto&) {
                app = winrt::make_self<DesktopApplication>([window] { window->show(); });
            });
            {
                std::lock_guard lock(ui->mutex);
                if (!ui->done) throw std::runtime_error("The WinUI message loop ended before pairing cleanup completed");
            }
            window->cleanup();
            app = nullptr;
            window.reset();
        }
        worker.join();
    } catch (...) {
        const auto error = dashboard_ui::currentException();
        ui->cancel(ExitCode::error);
        if (worker.joinable()) worker.join();
        std::wstring message;
        {
            std::lock_guard lock(ui->mutex);
            ui->displayError += error + L"\n";
            message = ui->message;
        }
        if (uiStarted) showNativeUiError(message.empty() ? L"The pairing interface could not continue." : message,
            error, L"Phone enrollment failed");
        else showStartupError(error, L"Phone enrollment failed");
    }
    const auto result = ui->displayError.empty() || ui->result == ExitCode::savedReloadFailed
        ? ui->result : ExitCode::error;
    if (!bluetooth) std::cout << "Enrollment exit code: " << static_cast<DWORD>(result) << '\n';
    return static_cast<int>(result);
}
