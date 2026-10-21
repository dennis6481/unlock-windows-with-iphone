// Created by Rui MA on 09 Oct 2026

#pragma once
#include "PasswordPage.g.h"
#include "../ViewModels/PasswordViewModel.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::UnlockDesktop::implementation {
struct PasswordPage : PasswordPageT<PasswordPage> {
    /// Initialize the password presentation without taking ownership of its elevated window.
    PasswordPage();
    /// Expose the cached model to compiled bindings.
    UnlockDesktop::PasswordViewModel ViewModel() const { return viewModel_; }
    /// Clear the view's confirmation and transient completion feedback on departure.
    void OnNavigatedFrom(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    /// Attach the existing host diagnostic callback.
    void Bind(unlock_windows::desktop_app::MainWindow::ReportError reportError);
    /// Forward entry and activation refresh to the model.
    void Refresh();
    /// Dismiss view feedback and stop the model during desktop shutdown.
    void Stop();
    /// Hide the existing removal confirmation Flyout.
    void DismissRemoval();
    /// Clear or suppress completion feedback when the page is no longer visible.
    void DismissPasswordSuccess();
    /// Preserve the existing responsive account card layout.
    void AccountCardSizeChanged(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::SizeChangedEventArgs& args);
    /// Apply the existing custom header style to the official Expander toggle.
    void ManagementLoaded(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::RoutedEventArgs&);
    /// Dismiss confirmation when the management group is collapsed.
    void ManagementCollapsed(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::Controls::ExpanderCollapsedEventArgs&);
    /// Hide confirmation before invoking the model's removal command.
    void ConfirmRemovalClick(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::RoutedEventArgs&);
    /// Collapse the success bar only after its existing close transition finishes.
    void SuccessClosed(const Windows::Foundation::IInspectable&, const Microsoft::UI::Xaml::Controls::InfoBarClosedEventArgs&);
private:
    UnlockDesktop::PasswordViewModel viewModel_{nullptr};
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct PasswordPage : PasswordPageT<PasswordPage, implementation::PasswordPage> {};
}
