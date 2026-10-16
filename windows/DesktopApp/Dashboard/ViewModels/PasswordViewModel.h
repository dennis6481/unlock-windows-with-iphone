// Created by Rui MA on 16 Oct 2026

#pragma once

#include "PasswordViewModel.g.h"
#include "Observable.h"
#include "../Dashboard.h"
#include <winrt/Microsoft.UI.Dispatching.h>

namespace winrt::UnlockDesktop::implementation {
struct PasswordViewModel : PasswordViewModelT<PasswordViewModel>, unlock_windows::desktop_app::Observable<PasswordViewModel> {
    using unlock_windows::desktop_app::Observable<PasswordViewModel>::PropertyChanged;
    /// Initialize the three existing password operations as commands.
    PasswordViewModel();
    /// Return the verified account name or the existing unknown-state text.
    hstring Account() const;
    /// Return the saved-password action label.
    hstring PasswordLabel() const;
    /// Return Save or Update according to the verified summary.
    hstring PasswordAction() const;
    /// Allow changes only after successful verification and while idle.
    bool Ready() const { return summary_.has_value() && !loading_ && !managing_ && !stopped_; }
    /// Allow removal only for a verified existing saved copy.
    bool CanRemove() const { return Ready() && summary_->credentialPresent; }
    /// Return the user's current management expansion state.
    bool Expanded() const { return expanded_; }
    /// Retain user expansion choices between status updates.
    void Expanded(bool value) { if (expanded_ != value) { expanded_ = value; Notify({L"Expanded"}); } }
    /// Select warning severity for an identity mismatch.
    bool Warning() const { return warning_; }
    /// Return whether the existing notice should be open.
    bool NoticeOpen() const { return noticeOpen_; }
    /// Retain manual dismissal until a subsequent query or operation changes the notice.
    void NoticeOpen(bool value) { if (noticeOpen_ != value) { noticeOpen_ = value; Notify({L"NoticeOpen"}); } }
    /// Return the existing query or operation error message.
    hstring Notice() const { return notice_; }
    /// Hide removal when no saved copy is known.
    Microsoft::UI::Xaml::Visibility RemovalVisibility() const;
    /// Offer retry after a failed summary query.
    Microsoft::UI::Xaml::Visibility RetryVisibility() const;
    /// Return whether transient completion feedback is open.
    bool SuccessOpen() const { return successOpen_; }
    /// Accept manual closure without replaying completion feedback.
    void SuccessOpen(bool value);
    /// Collapse feedback after the view completes the existing InfoBar close transition.
    void SuccessClosed();
    /// Return the operation-specific completion heading.
    hstring SuccessTitle() const { return successTitle_; }
    /// Collapse the success bar when dismissed.
    Microsoft::UI::Xaml::Visibility SuccessVisibility() const;
    /// Expose the existing retry operation.
    Microsoft::UI::Xaml::Input::ICommand RefreshCommand() const { return refresh_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Expose the existing Save or Update operation.
    Microsoft::UI::Xaml::Input::ICommand PasswordCommand() const { return password_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Expose removal after the view's existing confirmation Flyout.
    Microsoft::UI::Xaml::Input::ICommand RemoveCommand() const { return remove_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Attach the host's existing error reporter.
    void Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError);
    /// Query the existing non-sensitive service summary.
    void Refresh();
    /// Cancel pending presentation work on desktop shutdown.
    void Stop();
    /// Clear or suppress success feedback on navigation or window hiding.
    void DismissSuccess();
    /// Preserve the page's local UI error handling policy.
    void UiError(const hresult_error& failure);
private:
    /// Publish summary-derived state and command availability.
    void applyState();
    /// Publish an operation failure through the existing error reporter.
    void error(const std::wstring& message);
    /// Start the selected operation with the existing lifecycle gates.
    void beginOperation(unlock_windows::saved_credential::Operation operation);
    /// Preserve the existing service query and reply validation.
    static Windows::Foundation::IAsyncAction query(weak_ref<PasswordViewModel> weak,
        Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
        unlock_windows::desktop_app::Dashboard::ReportError reportError);
    /// Preserve UAC launch, process waiting and operation-specific exit codes.
    static Windows::Foundation::IAsyncAction launch(weak_ref<PasswordViewModel> weak,
        Microsoft::UI::Dispatching::DispatcherQueue dispatcher, unlock_windows::saved_credential::Operation operation,
        unlock_windows::desktop_app::Dashboard::ReportError reportError);
    std::optional<unlock_windows::saved_credential::CredentialSummary> summary_;
    unlock_windows::desktop_app::Dashboard::ReportError reportError_;
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher_{nullptr};
    Windows::Foundation::IAsyncAction query_{nullptr}, operation_{nullptr};
    com_ptr<unlock_windows::desktop_app::ViewModelCommand> refresh_, password_, remove_;
    hstring notice_, successTitle_;
    bool loading_ = false, managing_ = false, stopped_ = false, expanded_ = false;
    bool passwordSuccessPending_ = false, successOpen_ = false, successVisible_ = false;
    bool noticeOpen_ = false, warning_ = false, retry_ = false;
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct PasswordViewModel : PasswordViewModelT<PasswordViewModel, implementation::PasswordViewModel> {};
}
