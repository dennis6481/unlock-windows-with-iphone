// Created by Rui MA on 09 Oct 2026

#pragma once
#include "StatusPage.g.h"
#include "../ViewModels/StatusViewModel.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::UnlockDesktop::implementation {
struct StatusPage : StatusPageT<StatusPage> {
    /// Initialize XAML and retain only view-specific input handling.
    StatusPage();
    /// Expose the cached model to compiled bindings.
    UnlockDesktop::StatusViewModel ViewModel() const { return viewModel_; }
    /// Mark the page visible without starting another enrollment session.
    void OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    /// Discard input previews and transient feedback without cancelling enrollment.
    void OnNavigatedFrom(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    /// Dismiss binding completion feedback on navigation or window hiding.
    void DismissBindingSuccess();
    /// Restore the saved threshold and invalidate queued input completions.
    void ResetThresholdPreview();
    /// Forward the host snapshot and preserve an active input preview.
    void Update(unlock_windows::desktop_app::DesktopSnapshot const& snapshot);
    /// Stop operations and dismiss the view's confirmation Flyout.
    void Stop();
    /// Forward activation refresh to the existing enrollment session.
    void Refresh();
    /// Attach the host callbacks without exposing controls to the model.
    void SetHost(std::function<void(bool)> refresh, unlock_windows::desktop_app::MainWindow::ReportError reportError);
    /// Preserve the existing narrow-card layout.
    void ThresholdCardSizeChanged(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::SizeChangedEventArgs& args);
    /// Preserve the existing narrow removal-card layout.
    void RemovalCardSizeChanged(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::SizeChangedEventArgs& args);
    /// Hide the Flyout before executing the confirmed removal command.
    void ConfirmRemovalClick(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::RoutedEventArgs&);
    /// Follow the official button presenter's theme and visual-state foreground.
    void BindButtonLoaded(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::RoutedEventArgs&);
    /// Collapse the success bar only after its existing close transition finishes.
    void SuccessClosed(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::Controls::InfoBarClosedEventArgs&);
private:
    /// Normalize and submit a completed gesture when the model permits it.
    void FinishThresholdInteraction();
    /// Defer input completion until Slider class handlers have finished.
    void QueueThresholdAction(bool cancel = false);
    UnlockDesktop::StatusViewModel viewModel_{nullptr};
    bool updating_ = false, thresholdPointerActive_ = false, thresholdKeyActive_ = false;
    std::uint64_t thresholdInteraction_ = 0;
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct StatusPage : StatusPageT<StatusPage, implementation::StatusPage> {};
}
