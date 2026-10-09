// Created by Rui MA on 09 Oct 2026

#include "PasswordPage.xaml.h"
#include "PasswordPage.g.cpp"
#include "PageControls.h"
#include "../../DesktopApp.h"
#include "../../../Enrollment/EnrollmentSession.h"
#include <shellapi.h>
#include <utility>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
using namespace unlock_windows::saved_credential;
using namespace Microsoft::UI::Xaml;

void PasswordPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (passwordPanel_) return;
    passwordPanel_ = StackPanel{};
    passwordPanel_.Spacing(16);
    account_ = text(L"Windows account: loading...", 20);
    passwordPanel_.Children().Append(account_);
    passwordPanel_.Children().Append(text(L"Manage the encrypted password copy saved on this PC. This does not change your Microsoft Account password. Administrator approval is required."));
    status_ = text(L"Loading saved password status...");
    passwordPanel_.Children().Append(status_);
    notice_ = InfoBar{};
    notice_.Severity(InfoBarSeverity::Error);
    passwordPanel_.Children().Append(notice_);
    password_ = Button{};
    password_.Content(box_value(L"Save password"));
    password_.Style(Application::Current().Resources().Lookup(box_value(L"AccentButtonStyle")).as<Microsoft::UI::Xaml::Style>());
    password_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && page->summary_) {
            try { page->beginOperation(page->summary_->credentialPresent ? Operation::updateCredential : Operation::setCredential); }
            catch (const hresult_error& error) { page->uiError(error); }
        }
    });
    StackPanel actions;
    actions.Orientation(Orientation::Horizontal);
    actions.Spacing(12);
    actions.Children().Append(password_);
    remove_ = Button{};
    remove_.Content(box_value(L"Remove saved password"));
    remove_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) {
            try { page->beginOperation(Operation::clearCredential); }
            catch (const hresult_error& error) { page->uiError(error); }
        }
    });
    actions.Children().Append(remove_);
    passwordPanel_.Children().Append(actions);
    BodyHost().Content(passwordPanel_);
    applyState();
}

void PasswordPage::Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    reportError_ = std::move(reportError);
}

void PasswordPage::applyState() {
    const bool ready = summary_.has_value() && !loading_ && !managing_ && !stopped_;
    password_.IsEnabled(ready);
    password_.Content(box_value(hstring(summary_ && summary_->credentialPresent ? L"Update password" : L"Save password")));
    remove_.Visibility(summary_ && summary_->credentialPresent ? Visibility::Visible : Visibility::Collapsed);
    remove_.IsEnabled(ready && summary_->credentialPresent);
    if (!summary_) {
        account_.Text(L"Windows account: not yet verified");
        status_.Text(loading_ ? L"Loading saved password status..." : L"Saved password status is unavailable.");
        return;
    }
    const auto& name = summary_->identity.qualifiedUserName;
    const auto separator = name.find_last_of(L'\\');
    account_.Text(L"Windows account: " + name.substr(separator == std::wstring::npos ? 0 : separator + 1));
    status_.Text(!summary_->credentialPresent ? L"No password copy is saved. Save your Microsoft Account password to enable iPhone unlock."
        : summary_->credentialMatches ? L"An encrypted password copy is saved. Update it when your Microsoft Account password changes."
        : L"The saved copy does not match this verified Windows identity. Update it before using iPhone unlock.");
}

void PasswordPage::error(const std::wstring& message) {
    notice_.Message(message);
    notice_.IsOpen(true);
    reportError_(L"Password: " + message);
}

void PasswordPage::Refresh() {
    if (stopped_ || loading_ || managing_) return;
    loading_ = true;
    summary_.reset();
    notice_.IsOpen(false);
    applyState();
    query_ = query(get_weak(), DispatcherQueue(), reportError_);
}

void PasswordPage::uiError(const hresult_error& failure) {
    rethrowNonlocalUiError(failure);
    Stop();
    password_.IsEnabled(false);
    remove_.IsEnabled(false);
    error(L"Password UI: " + std::wstring(failure.message()));
}

void PasswordPage::beginOperation(Operation operation) {
    if (stopped_ || loading_ || managing_ || !summary_ ||
        (operation == Operation::clearCredential && !summary_->credentialPresent)) return;
    managing_ = true;
    notice_.IsOpen(false);
    applyState();
    operation_ = launch(get_weak(), DispatcherQueue(), operation, reportError_);
}

void PasswordPage::Stop() {
    stopped_ = true;
    if (query_) query_.Cancel();
    if (operation_) operation_.Cancel();
}

Windows::Foundation::IAsyncAction PasswordPage::query(weak_ref<PasswordPage> weak,
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
    unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    const auto cancellation = co_await get_cancellation_token();
    co_await resume_background();
    if (cancellation()) co_return;
    std::optional<CredentialSummary> summary;
    std::wstring failure;
    try {
        Packet response;
        CallDiagnostics diagnostics;
        if (!call(Operation::credentialSummary, SensitiveBytes{}, response, 2000, &diagnostics))
            failure = L"Saved password service is unavailable: " + std::wstring(callStageName(diagnostics.stage)) +
                L" (Win32 " + std::to_wstring(diagnostics.win32Error) + L"). Choose Refresh to retry.";
        else if (response.result != Result::success)
            failure = L"The service could not verify this signed-in Windows account. Choose Refresh to retry.";
        else {
            CredentialSummary value;
            if (!decodeCredentialSummary(response.payload.value.data(), response.payload.value.size(), value))
                failure = L"The service returned malformed password status.";
            else summary = std::move(value);
            if (diagnostics.stage == CallStage::replyAcknowledgment)
                reportError(L"Password status reply acknowledgment failed (Win32 " + std::to_wstring(diagnostics.win32Error) + L").");
        }
    } catch (...) { failure = currentException(); }
    if (cancellation()) co_return;
    if (!dispatcher.TryEnqueue([weak, summary = std::move(summary), failure = std::move(failure)]() mutable {
        if (auto page = weak.get(); page && !page->stopped_) {
            try {
                page->loading_ = false;
                page->summary_ = std::move(summary);
                page->applyState();
                if (!failure.empty()) page->error(failure);
            } catch (const hresult_error& error) {
                page->uiError(error);
            }
        }
    })) reportError(L"The Password UI dispatcher rejected a status update.");
}

Windows::Foundation::IAsyncAction PasswordPage::launch(weak_ref<PasswordPage> weak,
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher, Operation operation,
    unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    const auto cancellation = co_await get_cancellation_token();
    co_await resume_background();
    if (cancellation()) co_return;
    std::wstring failure;
    unlock_windows::enrollment::Handle process;
    try {
        init_apartment(apartment_type::multi_threaded);
        struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
        std::wstring executable(32768, L'\0');
        const auto size = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (!size || size >= executable.size()) throw std::runtime_error("Could not locate the password window");
        executable.resize(size);
        const auto arguments = std::wstring(unlock_windows::desktop_app::kSavedPasswordRole) + L" " +
            unlock_windows::desktop_app::passwordOperationArgument(operation);
        SHELLEXECUTEINFOW request{sizeof(request)};
        request.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        request.lpVerb = L"runas";
        request.lpFile = executable.c_str();
        request.lpParameters = arguments.c_str();
        request.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteExW(&request)) {
            const auto code = GetLastError();
            if (code != ERROR_CANCELLED) throw std::runtime_error("Open password window: Win32=" + std::to_string(code));
        } else {
            process.value = request.hProcess;
            if (!process.value) throw std::runtime_error("Password window returned no process handle");
        }
    } catch (...) { failure = currentException(); }
    if (process.value) {
        try {
            co_await resume_on_signal(process.value);
            DWORD result = 0;
            unlock_windows::enrollment::require(GetExitCodeProcess(process.value, &result), "Read password window result");
            if (result == static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::error))
                failure = L"The password window did not complete successfully. Refresh and retry.";
        } catch (...) { failure = currentException(); }
    }
    if (cancellation()) co_return;
    if (!dispatcher.TryEnqueue([weak, failure = std::move(failure)] {
        if (auto page = weak.get(); page && !page->stopped_) {
            try {
                page->managing_ = false;
                page->Refresh();
                if (!failure.empty()) page->error(failure);
            } catch (const hresult_error& error) {
                page->uiError(error);
            }
        }
    })) reportError(L"The Password UI dispatcher rejected a password operation result.");
}
}
