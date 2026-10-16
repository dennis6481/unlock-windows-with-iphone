// Created by Rui MA on 16 Oct 2026

#pragma once

#include "StatusViewModel.g.h"
#include "Observable.h"
#include "../Dashboard.h"
#include "../UnlockRange.h"
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Windows.Foundation.Collections.h>

namespace winrt::UnlockDesktop::implementation {
struct StatusViewModel : StatusViewModelT<StatusViewModel>, unlock_windows::desktop_app::Observable<StatusViewModel> {
    using unlock_windows::desktop_app::Observable<StatusViewModel>::PropertyChanged;
    /// Create presentation commands and the observable paired-device collection.
    StatusViewModel();
    /// Return the known binding name or the existing unknown/unbound text.
    hstring DeviceName() const;
    /// Return the service-owned last-unlock summary formatted for display.
    hstring LastUnlock() const;
    /// Prefer the local operation error over the periodic snapshot error.
    hstring Error() const;
    /// Show errors while either source reports a failure.
    bool ErrorOpen() const { return !Error().empty(); }
    /// Return the current binding-success feedback state.
    bool SuccessOpen() const { return success_; }
    /// Accept manual or lifecycle dismissal without replaying success.
    void SuccessOpen(bool value);
    /// Collapse feedback after the view completes the existing InfoBar close transition.
    void SuccessClosed();
    /// Collapse dismissed binding-success feedback.
    Microsoft::UI::Xaml::Visibility SuccessVisibility() const;
    /// Show management cards only for a known bound phone.
    Microsoft::UI::Xaml::Visibility BoundVisibility() const;
    /// Show enrollment only for a known unbound phone state.
    Microsoft::UI::Xaml::Visibility BindingVisibility() const;
    /// Show the existing empty-list guidance when enumeration has no choices.
    Microsoft::UI::Xaml::Visibility EmptyVisibility() const;
    /// Show progress only during an initial binding operation.
    Microsoft::UI::Xaml::Visibility ProgressVisibility() const;
    /// Gate enrollment while host or threshold operations are active.
    bool BindingEnabled() const;
    /// Gate device selection while a binding operation is active.
    bool DevicesEnabled() const;
    /// Gate threshold and removal actions using the existing busy state.
    bool ManagementEnabled() const;
    /// Return whether the initial binding progress indicator is active.
    bool BindingBusy() const;
    /// Return the enrollment progress or failure message.
    hstring BindingMessage() const;
    /// Return the existing binding button label.
    hstring BindLabel() const;
    /// Return the existing binding button automation name.
    hstring BindAutomationName() const;
    /// Return the currently paired device choices.
    Windows::Foundation::Collections::IObservableVector<UnlockDesktop::PairedDevice> Devices() const { return devices_; }
    /// Return the selected endpoint projection.
    UnlockDesktop::PairedDevice SelectedDevice() const { return selected_; }
    /// Preserve endpoint selection across enumeration refreshes.
    void SelectedDevice(const UnlockDesktop::PairedDevice& device);
    /// Expose initial binding after selection.
    Microsoft::UI::Xaml::Input::ICommand BindCommand() const { return bind_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Expose binding removal after the view's confirmation.
    Microsoft::UI::Xaml::Input::ICommand RemoveCommand() const { return remove_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Expose threshold submission after the view finishes an input gesture.
    Microsoft::UI::Xaml::Input::ICommand SaveRangeCommand() const { return save_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Expose the existing Windows Bluetooth settings link.
    Microsoft::UI::Xaml::Input::ICommand OpenSettingsCommand() const { return settings_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Attach snapshot refresh and error-reporting callbacks from the host.
    void SetHost(std::function<void(bool)> refresh, unlock_windows::desktop_app::Dashboard::ReportError reportError);
    /// Apply the existing periodic snapshot and report whether the view must reset its gesture.
    bool Update(const unlock_windows::desktop_app::DashboardSnapshot& snapshot);
    /// Refresh an existing enrollment session without creating another polling source.
    void Refresh();
    /// Cancel enrollment and threshold work during desktop shutdown.
    void Stop();
    /// Record navigation visibility without cancelling background enrollment.
    void Visible(bool value) { visible_ = value; }
    /// Return whether any local management operation is active.
    bool Busy() const;
    /// Return whether a threshold operation is active.
    bool Saving() const { return saving_; }
    /// Return whether input can currently finish and submit.
    bool CanFinishRange() const { return visible_ && !stopped_ && !snapshot_.busy && !Busy(); }
    /// Return the positive preview value used by the slider.
    double RangeValue() const { return range_; }
    /// Record a preview without submitting until the view finishes the gesture.
    void PreviewRange(double value) { range_ = value; }
    /// Return whether the preview differs from the current stored threshold.
    bool RangeDirty() const;
    /// Restore the slider preview from the authoritative binding summary.
    void ResetRange();
    /// Surface failure to queue the existing deferred input action.
    void RangeSchedulingFailed();
private:
    struct BindingSession;
    /// Start the existing paired-device watcher and scan when enrollment is needed.
    void EnsureSession();
    /// Submit the selected binding or remove the existing one.
    void StartBinding(bool remove);
    /// Publish the state and command predicates affected by an operation.
    void Publish();
    /// Preserve threshold request encoding, elevation and result readback.
    static fire_and_forget SaveRange(weak_ref<StatusViewModel> weak);
    /// Launch the existing Bluetooth settings URI and report launch failures.
    static fire_and_forget OpenSettings(weak_ref<StatusViewModel> weak);
    unlock_windows::desktop_app::DashboardSnapshot snapshot_;
    std::optional<unlock_windows::saved_credential::BindingSummary> binding_;
    std::shared_ptr<BindingSession> session_;
    Windows::Foundation::Collections::IObservableVector<UnlockDesktop::PairedDevice> devices_{single_threaded_observable_vector<UnlockDesktop::PairedDevice>()};
    UnlockDesktop::PairedDevice selected_{nullptr};
    com_ptr<unlock_windows::desktop_app::ViewModelCommand> bind_, remove_, save_, settings_;
    std::function<void(bool)> refreshSnapshot_;
    unlock_windows::desktop_app::Dashboard::ReportError reportError_;
    std::wstring saveError_;
    handle cancellation_;
    double range_ = -unlock_windows::system_ble::kDefaultThreshold;
    bool saving_ = false, stopped_ = false, visible_ = false, success_ = false, successVisible_ = false;
    bool rendering_ = false, resetSession_ = false;
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct StatusViewModel : StatusViewModelT<StatusViewModel, implementation::StatusViewModel> {};
}
