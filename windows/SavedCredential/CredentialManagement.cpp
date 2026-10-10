// Created by Rui MA on 30 Sep 2026

#include "SavedCredentialIpc.h"
#include "../DesktopApp/DesktopApp.h"
#include "../DesktopApp/DesktopApplication.h"
#include "../DesktopApp/DesktopNotifications.h"
#include "../DesktopApp/Dashboard/Pages/PageControls.h"
#include "../Resources/resource.h"
#include "../Enrollment/EnrollmentSession.h"
#include <microsoft.ui.xaml.window.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <cstring>
#include <array>
#include <memory>

namespace {
using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Controls;
using namespace unlock_windows::saved_credential;
using namespace unlock_windows::desktop_app;
using namespace unlock_windows::desktop_app::dashboard_ui;

struct PasswordBuffer final {
    std::array<wchar_t, kMaxPasswordChars + 1> value{};
    ~PasswordBuffer() { SecureZeroMemory(value.data(), sizeof(value)); }
};

StatusPayload readStatus() {
    Packet response;
    CallDiagnostics diagnostics;
    if (!call(Operation::status, SensitiveBytes{}, response, 2000, &diagnostics))
        throw std::runtime_error("Saved credential IPC failed at " + std::string(to_string(callStageName(diagnostics.stage))) +
            " (Win32 " + std::to_string(diagnostics.win32Error) + ").");
    if (response.result == Result::rejected)
        throw std::runtime_error("The service could not verify the installed target's Windows account. Retry account verification.");
    StatusPayload status;
    if (response.result != Result::success || !decodeStatus(response.payload.value.data(), response.payload.value.size(), status))
        throw std::runtime_error("The service returned an error or malformed Windows identity status.");
    if (diagnostics.stage == CallStage::replyAcknowledgment)
        throw std::runtime_error("Password status reply acknowledgment failed (Win32 " + std::to_string(diagnostics.win32Error) + "). Choose Retry.");
    return status;
}

class PasswordWindow final : public std::enable_shared_from_this<PasswordWindow> {
public:
    PasswordWindow(bool setup, Operation operation) : setup_(setup), requested_(operation) {}
    int result() const { return result_; }

    void show() {
        const auto weak = weak_from_this();
        window_ = Window{};
        window_.Title(L"Saved Windows password");
        const auto appWindow = window_.AppWindow();
        appWindow.TitleBar().PreferredTheme(Microsoft::UI::Windowing::TitleBarTheme::UseDefaultAppMode);
        HWND hwnd = nullptr;
        check_hresult(window_.as<IWindowNative>()->get_WindowHandle(&hwnd));
        const auto dpi = GetDpiForWindow(hwnd);
        appWindow.Resize({MulDiv(560, dpi, 96), MulDiv(480, dpi, 96)});
        const auto appIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_UNLOCK_APP));
        if (!appIcon) throw_last_error();
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(appIcon));
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(appIcon));
        root_ = StackPanel{};
        root_.Spacing(16);
        root_.Margin({28, 24, 28, 24});
        root_.Children().Append(text(L"Saved Windows password", 24));
        account_ = text(L"Windows account: loading...", 18);
        root_.Children().Append(account_);
        root_.Children().Append(text(L"Save a local encrypted copy of the actual Microsoft Account password for the displayed console user. This does not change your account password or create an unlock approval."));
        status_ = text(L"Loading account information...");
        root_.Children().Append(status_);
        notice_ = InfoBar{};
        root_.Children().Append(notice_);
        password_ = PasswordBox{};
        password_.Header(box_value(L"Microsoft Account password"));
        password_.MaxLength(static_cast<std::int32_t>(kMaxPasswordChars));
        password_.PasswordChanged([weak](const auto&, const auto&) {
            if (const auto self = weak.lock(); self && !self->stopped_) self->applyState();
        });
        root_.Children().Append(password_);
        submit_ = Button{};
        submit_.Style(Application::Current().Resources().Lookup(box_value(L"AccentButtonStyle")).as<Style>());
        submit_.Click([weak](const auto&, const auto&) {
            if (const auto self = weak.lock(); self && !self->stopped_) {
                try {
                    if (!self->snapshot_) self->refresh();
                    else if (self->requested_ == Operation::clearCredential) self->confirmRemoval();
                    else self->save();
                } catch (...) { self->uiError(); }
            }
        });
        StackPanel actions;
        actions.Orientation(Orientation::Horizontal);
        actions.Spacing(12);
        actions.HorizontalAlignment(HorizontalAlignment::Right);
        actions.Children().Append(submit_);
        Button cancel;
        cancel.Content(box_value(L"Cancel"));
        cancel.Click([weak](const auto&, const auto&) { if (const auto self = weak.lock()) self->close(); });
        actions.Children().Append(cancel);
        root_.Children().Append(actions);
        ScrollViewer scroll;
        scroll.HorizontalScrollBarVisibility(ScrollBarVisibility::Disabled);
        scroll.Content(root_);
        window_.Content(scroll);
        closedToken_ = window_.Closed([weak](const auto&, const auto&) { if (const auto self = weak.lock()) self->stop(); });
        window_.Activate();
        refresh();
    }

    void close() {
        if (stopped_) return;
        password_.Password(L"");
        window_.Close();
    }

    void stop() {
        if (stopped_) return;
        stopped_ = true;
        if (work_) work_.Cancel();
        if (confirmation_) confirmation_.Hide();
        password_.Password(L"");
        if (window_ && closedToken_.value) window_.Closed(closedToken_);
        Application::Current().Exit();
    }

private:
    void notice(const std::wstring& message, InfoBarSeverity severity) {
        notice_.Severity(severity);
        notice_.Message(message);
        notice_.IsOpen(true);
    }

    void uiError() {
        const auto message = currentException();
        busy_ = false;
        snapshot_.reset();
        applyState();
        notice(message, InfoBarSeverity::Error);
    }

    Operation saveOperation() const {
        return requested_ == Operation::status
            ? (snapshot_->credentialPresent ? Operation::updateCredential : Operation::setCredential) : requested_;
    }

    void applyState() {
        const bool ready = snapshot_.has_value() && !busy_ && !stopped_;
        const bool removal = requested_ == Operation::clearCredential;
        const bool compatible = snapshot_ && (requested_ == Operation::status || removal ||
            (requested_ == Operation::updateCredential) == snapshot_->credentialPresent);
        password_.Visibility(removal ? Visibility::Collapsed : Visibility::Visible);
        password_.IsEnabled(ready && compatible);
        submit_.Content(box_value(hstring(removal ? L"Remove saved password"
            : (requested_ == Operation::updateCredential || (requested_ == Operation::status && snapshot_ && snapshot_->credentialPresent))
                ? L"Update password" : L"Save password")));
        submit_.IsEnabled(ready && compatible && (removal ? snapshot_->credentialPresent : !password_.Password().empty()));
        if (!snapshot_) {
            submit_.Content(box_value(hstring(busy_ ? L"Loading..." : L"Retry")));
            submit_.IsEnabled(!busy_ && !stopped_);
            account_.Text(L"Windows account: not yet verified");
            status_.Text(busy_ ? L"Loading account information..." : L"Account information could not be verified. Choose Retry.");
            return;
        }
        const auto& name = snapshot_->identity.qualifiedUserName;
        const auto separator = name.find_last_of(L'\\');
        account_.Text(L"Windows account: " + name.substr(separator == std::wstring::npos ? 0 : separator + 1));
        status_.Text(!compatible ? L"Saved password status changed. Close this window and choose the current operation from the Password page."
            : !snapshot_->credentialPresent ? L"No password copy is saved."
            : snapshot_->credentialMatches ? L"An encrypted password copy is saved on this PC."
            : L"Update the saved copy for this verified Windows identity before continuing setup.");
    }

    void refresh() {
        if (busy_ || stopped_) return;
        busy_ = true;
        snapshot_.reset();
        notice_.IsOpen(false);
        applyState();
        work_ = perform(weak_from_this(), window_.DispatcherQueue(), Operation::status, std::nullopt, SensitiveBytes{}, setup_);
    }

    void save() {
        if (busy_ || stopped_ || !snapshot_) return;
        PasswordBuffer password;
        std::uint32_t bytes = 0;
        {
            const auto input = password_.Password();
            if (input.empty()) return;
            if (input.size() >= password.value.size()) throw hresult_error(E_FAIL, L"The password is too long.");
            bytes = static_cast<std::uint32_t>(input.size() * sizeof(wchar_t));
            std::memcpy(password.value.data(), input.c_str(), bytes);
        }
        password_.Password(L"");
        SensitiveBytes request;
        request.value.resize(kNonceSize + sizeof(bytes) + bytes);
        std::memcpy(request.value.data(), snapshot_->snapshotNonce.data(), kNonceSize);
        std::memcpy(request.value.data() + kNonceSize, &bytes, sizeof(bytes));
        std::memcpy(request.value.data() + kNonceSize + sizeof(bytes), password.value.data(), bytes);
        begin(saveOperation(), std::move(request));
    }

    void begin(Operation operation, SensitiveBytes request) {
        if (busy_ || stopped_ || !snapshot_) return;
        busy_ = true;
        notice_.IsOpen(false);
        applyState();
        work_ = perform(weak_from_this(), window_.DispatcherQueue(), operation, snapshot_, std::move(request), setup_);
    }

    void confirmRemoval() {
        if (busy_ || stopped_ || !snapshot_ || !snapshot_->credentialPresent) return;
        busy_ = true;
        applyState();
        confirmation_ = ContentDialog{};
        confirmation_.XamlRoot(root_.XamlRoot());
        confirmation_.Title(box_value(L"Remove your saved password copy?"));
        confirmation_.Content(box_value(L"iPhone unlock will be unavailable until you save a password again. Your Microsoft Account password will not change."));
        confirmation_.PrimaryButtonText(L"Remove saved password");
        confirmation_.CloseButtonText(L"Cancel");
        confirmation_.DefaultButton(ContentDialogButton::Close);
        work_ = remove(weak_from_this(), confirmation_);
    }

    static Windows::Foundation::IAsyncAction remove(std::weak_ptr<PasswordWindow> weak, ContentDialog dialog) {
        ContentDialogResult choice = ContentDialogResult::None;
        std::wstring failure;
        try { choice = co_await dialog.ShowAsync(); }
        catch (...) { failure = currentException(); }
        if (const auto self = weak.lock(); self && !self->stopped_) {
            try {
                self->confirmation_ = nullptr;
                self->busy_ = false;
                self->applyState();
                if (!failure.empty()) self->notice(failure, InfoBarSeverity::Error);
                else if (choice == ContentDialogResult::Primary) self->begin(Operation::clearCredential, SensitiveBytes{});
            } catch (...) { self->uiError(); }
        }
    }

    static Windows::Foundation::IAsyncAction perform(std::weak_ptr<PasswordWindow> weak,
        Microsoft::UI::Dispatching::DispatcherQueue dispatcher, Operation operation,
        std::optional<StatusPayload> expected, SensitiveBytes request, bool setup) {
        const auto cancellation = co_await get_cancellation_token();
        co_await resume_background();
        if (cancellation()) co_return;
        std::optional<StatusPayload> snapshot;
        std::wstring failure, message;
        bool ready = false;
        try {
            auto status = readStatus();
            if (operation != Operation::status) {
                if (!expected || status.snapshotNonce != expected->snapshotNonce ||
                    (operation == Operation::setCredential && status.credentialPresent) ||
                    ((operation == Operation::updateCredential || operation == Operation::clearCredential) && !status.credentialPresent))
                    throw std::runtime_error("The verified Windows identity or saved password state changed. Choose Retry; no change was submitted.");
                if (cancellation()) co_return;
                Packet response;
                CallDiagnostics diagnostics;
                if (!call(operation, std::move(request), response, 2000, &diagnostics) || response.result != Result::success)
                    throw std::runtime_error("The service did not confirm the password change. Choose Retry to query its current state.");
                message = operation == Operation::clearCredential ? L"The saved password copy has been removed."
                    : L"Your encrypted password copy is saved. Windows has not yet verified that the password is correct.";
                if (diagnostics.stage == CallStage::replyAcknowledgment)
                    message += L" Reply acknowledgment failed (Win32 " + std::to_wstring(diagnostics.win32Error) + L").";
                status = readStatus();
            }
            snapshot = std::move(status);
            if (setup && snapshot->credentialMatches) {
                if (cancellation()) co_return;
                Packet response;
                if (!call(Operation::reloadPhoneEnrollment, SensitiveBytes{}, response) || response.result != Result::success)
                    throw std::runtime_error("The service could not reload phone registration. Setup has not continued. Choose Retry.");
                ready = true;
            }
        } catch (...) { failure = currentException(); snapshot.reset(); }
        if (cancellation()) co_return;
        if (!dispatcher.TryEnqueue([weak, snapshot = std::move(snapshot), failure = std::move(failure), message = std::move(message), ready]() mutable {
            if (const auto self = weak.lock(); self && !self->stopped_) {
                try {
                    self->busy_ = false;
                    self->snapshot_ = std::move(snapshot);
                    self->applyState();
                    if (!failure.empty()) {
                        self->notice(message.empty() ? failure : message + L"\n" + failure, InfoBarSeverity::Error);
                    } else if (ready) {
                        self->result_ = static_cast<int>(SetupResult::credentialReady);
                        self->close();
                    } else {
                        if (!message.empty()) self->notice(message, InfoBarSeverity::Success);
                        if (self->requested_ == Operation::clearCredential && !self->removalOpened_ && self->snapshot_ && self->snapshot_->credentialPresent) {
                            self->removalOpened_ = true;
                            self->confirmRemoval();
                        }
                    }
                } catch (...) { self->uiError(); }
            }
        })) {
            OutputDebugStringW(L"Password window dispatcher rejected an operation result.\n");
        }
    }

    bool setup_, busy_ = false, stopped_ = false, removalOpened_ = false;
    Operation requested_;
    int result_ = static_cast<int>(SetupResult::cancelled);
    std::optional<StatusPayload> snapshot_;
    Window window_{nullptr};
    StackPanel root_{nullptr};
    TextBlock account_{nullptr}, status_{nullptr};
    PasswordBox password_{nullptr};
    Button submit_{nullptr};
    InfoBar notice_{nullptr};
    ContentDialog confirmation_{nullptr};
    Windows::Foundation::IAsyncAction work_{nullptr};
    event_token closedToken_{};
};
}

int unlock_windows::desktop_app::runSavedPassword(HINSTANCE, int, bool setup, saved_credential::Operation operation) {
    bool uiStarted = false;
    try {
        if (!unlock_windows::enrollment::elevatedAdmin())
            throw std::runtime_error("Run the password manager as administrator on the physical console.");
        init_apartment(apartment_type::single_threaded);
        struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
        auto window = std::make_shared<PasswordWindow>(setup, operation);
        com_ptr<DesktopApplication> app;
        uiStarted = true;
        Application::Start([&](const auto&) {
            app = make_self<DesktopApplication>([window] { window->show(); });
        });
        const auto result = window->result();
        app = nullptr;
        window.reset();
        return result;
    } catch (...) {
        const auto message = currentException();
        OutputDebugStringW(message.c_str());
        if (uiStarted) showNativeUiError(L"Could not run password window.", message, L"Could not run password window");
        else showStartupError(message, L"Could not run password window");
        return static_cast<int>(SetupResult::error);
    }
}
