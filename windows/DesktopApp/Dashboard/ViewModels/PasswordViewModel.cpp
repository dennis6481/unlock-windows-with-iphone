// Created by Rui MA on 16 Oct 2026

#include "PasswordViewModel.h"
#include "PasswordViewModel.g.cpp"
#include "../../DesktopErrors.h"
#include "../../DesktopApp.h"
#include "../../../Enrollment/EnrollmentSession.h"
#include <winrt/Windows.Foundation.h>
#include <shellapi.h>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
using namespace unlock_windows::saved_credential;
using namespace Microsoft::UI::Xaml;

PasswordViewModel::PasswordViewModel() {
    dispatcher_ = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
    const auto weak = get_weak();
    using unlock_windows::desktop_app::ViewModelCommand;
    refresh_ = make_self<ViewModelCommand>([weak] { if (auto model = weak.get()) {
        try { model->Refresh(); } catch (const hresult_error& error) {
            if (isNonlocalUiError(error)) throw;
            model->UiError(error);
        }
    } }, [weak] { auto model = weak.get(); return model && !model->stopped_ && !model->loading_ && !model->managing_; });
    password_ = make_self<ViewModelCommand>([weak] { if (auto model = weak.get()) {
        try { model->beginOperation(model->summary_->credentialPresent ? Operation::updateCredential : Operation::setCredential); }
        catch (const hresult_error& error) {
            if (isNonlocalUiError(error)) throw;
            model->UiError(error);
        }
    } }, [weak] { auto model = weak.get(); return model && model->Ready(); });
    remove_ = make_self<ViewModelCommand>([weak] { if (auto model = weak.get()) {
        try { model->beginOperation(Operation::clearCredential); }
        catch (const hresult_error& error) {
            if (isNonlocalUiError(error)) throw;
            model->UiError(error);
        }
    } }, [weak] { auto model = weak.get(); return model && model->CanRemove(); });
}
hstring PasswordViewModel::Account() const {
    if (!summary_) return loading_ ? L"Loading..." : L"Not yet verified";
    const auto& name = summary_->identity.qualifiedUserName;
    const auto separator = name.find_last_of(L'\\');
    return hstring{name.substr(separator == std::wstring::npos ? 0 : separator + 1)};
}
hstring PasswordViewModel::PasswordLabel() const { return summary_ && summary_->credentialPresent ? L"Update saved password" : L"Save password"; }
hstring PasswordViewModel::PasswordAction() const { return summary_ && summary_->credentialPresent ? L"Update" : L"Save"; }
Visibility PasswordViewModel::RemovalVisibility() const { return summary_ && summary_->credentialPresent ? Visibility::Visible : Visibility::Collapsed; }
Visibility PasswordViewModel::RetryVisibility() const { return retry_ ? Visibility::Visible : Visibility::Collapsed; }
Visibility PasswordViewModel::SuccessVisibility() const { return successVisible_ ? Visibility::Visible : Visibility::Collapsed; }
void PasswordViewModel::SuccessOpen(bool value) {
    if (successOpen_ == value) return;
    successOpen_ = value;
    if (value) { successVisible_ = true; Notify({L"SuccessTitle", L"SuccessVisibility"}); }
    Notify({L"SuccessOpen"});
}
void PasswordViewModel::SuccessClosed() { successVisible_ = false; Notify({L"SuccessVisibility"}); }
void PasswordViewModel::Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError) { reportError_ = std::move(reportError); }
void PasswordViewModel::DismissSuccess() { passwordSuccessPending_ = false; SuccessOpen(false); }
void PasswordViewModel::applyState() {
    if (summary_) {
        if (!summary_->credentialPresent) expanded_ = true;
        else if (!summary_->credentialMatches) {
            warning_ = true;
            notice_ = L"The saved copy does not match this verified Windows identity. Update it before using iPhone unlock.";
            noticeOpen_ = true;
        }
    }
    Notify({L"Account", L"PasswordLabel", L"PasswordAction", L"Ready", L"CanRemove", L"Expanded",
        L"Warning", L"Notice", L"NoticeOpen", L"RemovalVisibility", L"RetryVisibility"});
    refresh_->Invalidate(); password_->Invalidate(); remove_->Invalidate();
}
void PasswordViewModel::error(const std::wstring& message) {
    DismissSuccess(); warning_ = false; notice_ = message; noticeOpen_ = true;
    Notify({L"Warning", L"Notice", L"NoticeOpen"});
    reportError_(message);
}
void PasswordViewModel::Refresh() {
    if (stopped_ || loading_ || managing_) return;
    loading_ = true; summary_.reset(); noticeOpen_ = false; retry_ = false;
    applyState();
    query_ = query(get_weak(), dispatcher_, reportError_);
}
void PasswordViewModel::UiError(const hresult_error& failure) {
    Stop(); retry_ = false;
    applyState();
    error(L"Password UI: " + std::wstring(failure.message()));
}
void PasswordViewModel::beginOperation(Operation operation) {
    if (!Ready() || (operation == Operation::clearCredential && !summary_->credentialPresent)) return;
    DismissSuccess(); passwordSuccessPending_ = true; managing_ = true; noticeOpen_ = false; retry_ = false;
    applyState();
    operation_ = launch(get_weak(), dispatcher_, operation, reportError_);
}
void PasswordViewModel::Stop() {
    stopped_ = true; DismissSuccess();
    if (query_) query_.Cancel();
    if (operation_) operation_.Cancel();
    applyState();
}
Windows::Foundation::IAsyncAction PasswordViewModel::query(weak_ref<PasswordViewModel> weak,
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
        if (!call(Operation::credentialSummary, SensitiveBytes{}, response, kPipeTransferLifetimeMs, &diagnostics))
            failure = L"Saved password service is unavailable; stage=" + std::wstring(callStageName(diagnostics.stage)) +
                L"; win32=" + std::to_wstring(diagnostics.win32Error) + L". Choose Retry to check again.";
        else if (response.result != Result::success)
            failure = L"The service could not verify this signed-in Windows account. Choose Retry to check again.";
        else {
            CredentialSummary value;
            if (!decodeCredentialSummary(response.payload.value.data(), response.payload.value.size(), value))
                failure = L"The service returned malformed password status.";
            else summary = std::move(value);
            if (diagnostics.stage == CallStage::replyAcknowledgment)
                reportError(L"Status reply acknowledgment failed; stage=" + std::wstring(callStageName(diagnostics.stage)) +
                    L"; win32=" + std::to_wstring(diagnostics.win32Error));
        }
    } catch (...) { failure = formatException(std::current_exception()); }
    if (cancellation()) co_return;
    if (!dispatcher.TryEnqueue([weak, summary = std::move(summary), failure = std::move(failure)]() mutable {
        if (auto page = weak.get(); page && !page->stopped_) {
            try {
                page->loading_ = false;
                page->summary_ = std::move(summary);
                page->applyState();
                if (!failure.empty()) {
                    page->error(failure);
                    page->retry_ = true; page->Notify({L"RetryVisibility"});
                }
            } catch (const hresult_error& error) {
                if (isNonlocalUiError(error)) throw;
                page->UiError(error);
            }
        }
    })) reportError(L"The Password UI dispatcher rejected a status update.");
}

Windows::Foundation::IAsyncAction PasswordViewModel::launch(weak_ref<PasswordViewModel> weak,
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher, Operation operation,
    unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    const auto cancellation = co_await get_cancellation_token();
    co_await resume_background();
    if (cancellation()) co_return;
    std::wstring failure;
    unlock_windows::enrollment::Handle process;
    bool completed = false;
    try {
        init_apartment(apartment_type::multi_threaded);
        struct Apartment final {
            /// Release the worker's explicit COM apartment before returning its launch result.
            ~Apartment() { uninit_apartment(); }
        } apartment;
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
        request.nShow = operation == Operation::clearCredential ? SW_HIDE : SW_SHOWNORMAL;
        if (!ShellExecuteExW(&request)) {
            const auto code = GetLastError();
            if (code != ERROR_CANCELLED) throw std::runtime_error("Open password window; win32=" + std::to_string(code));
        } else {
            process.value = request.hProcess;
            if (!process.value) throw std::runtime_error("Password window returned no process handle");
        }
    } catch (...) { failure = formatException(std::current_exception()); }
    if (process.value) {
        try {
            co_await resume_on_signal(process.value);
            DWORD result = 0;
            unlock_windows::enrollment::require(GetExitCodeProcess(process.value, &result), "Read password window result");
            if (operation == Operation::clearCredential && result != ERROR_SUCCESS)
                failure = L"The saved password removal did not complete successfully; win32=" + std::to_wstring(result) +
                    L". Check the current state and try again.";
            else if (operation != Operation::clearCredential &&
                result != static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::cancelled) &&
                result != static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::credentialReady))
                failure = L"The password window did not complete successfully; exitCode=" +
                    std::to_wstring(result) + L". Try the password action again.";
            completed = operation == Operation::clearCredential ? result == ERROR_SUCCESS
                : result == static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::credentialReady);
        } catch (...) { failure = formatException(std::current_exception()); }
    }
    if (cancellation()) co_return;
    if (!dispatcher.TryEnqueue([weak, failure = std::move(failure), completed, operation] {
        if (auto page = weak.get(); page && !page->stopped_) {
            try {
                page->managing_ = false;
                page->Refresh();
                if (!failure.empty()) page->error(failure);
                else if (completed && page->passwordSuccessPending_) {
                    page->successTitle_ = hstring(operation == Operation::clearCredential ? L"Saved password removed successfully"
                        : operation == Operation::updateCredential ? L"Saved password updated successfully"
                        : L"Password saved successfully");
                    page->SuccessOpen(true);
                }
                page->passwordSuccessPending_ = false;
            } catch (const hresult_error& error) {
                if (isNonlocalUiError(error)) throw;
                page->UiError(error);
            }
        }
    })) reportError(L"The Password UI dispatcher rejected a password operation result.");
}
}
