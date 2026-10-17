// Created by Rui MA on 16 Oct 2026

#pragma once

#include "AboutViewModel.g.h"
#include "Observable.h"
#include "../MainWindow.h"
#include <winrt/Microsoft.UI.Dispatching.h>

namespace winrt::UnlockDesktop::implementation {
struct AboutViewModel : AboutViewModelT<AboutViewModel>, unlock_windows::desktop_app::Observable<AboutViewModel> {
    using unlock_windows::desktop_app::Observable<AboutViewModel>::PropertyChanged;
    /// Initialize the update command without creating a view.
    AboutViewModel();
    /// Return the four-part product version in the existing display format.
    hstring Version() const;
    /// Return the authoritative project link used by the page and release lookup.
    Windows::Foundation::Uri ProjectUri() const;
    /// Return the license link beneath the same project.
    Windows::Foundation::Uri LicenseUri() const;
    /// Return the current update result or progress message.
    hstring UpdateStatus() const { return message_; }
    /// Return the release link only when a newer release exists.
    Windows::Foundation::Uri ReleaseUri() const { return release_; }
    /// Show update feedback after the first explicit check.
    Microsoft::UI::Xaml::Visibility UpdateVisibility() const;
    /// Show the release action when the check found a newer version.
    Microsoft::UI::Xaml::Visibility ReleaseVisibility() const;
    /// Expose the explicit update check operation.
    Microsoft::UI::Xaml::Input::ICommand CheckUpdatesCommand() const { return check_.as<Microsoft::UI::Xaml::Input::ICommand>(); }
    /// Attach the host's existing diagnostic reporter.
    void Bind(unlock_windows::desktop_app::MainWindow::ReportError reportError);
    /// Cancel update work when the desktop shuts down.
    void Stop();
private:
    /// Begin a check and publish its existing progress state.
    void Check();
    /// Preserve the GitHub request, release comparison and cancellation behavior.
    static Windows::Foundation::IAsyncAction checkForUpdates(weak_ref<AboutViewModel> weak,
        Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
        unlock_windows::desktop_app::MainWindow::ReportError reportError);
    hstring message_;
    Windows::Foundation::Uri release_{nullptr};
    bool stopped_ = false, checking_ = false, checked_ = false;
    com_ptr<unlock_windows::desktop_app::ViewModelCommand> check_;
    Windows::Foundation::IAsyncAction updateCheck_{nullptr};
    unlock_windows::desktop_app::MainWindow::ReportError reportError_;
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct AboutViewModel : AboutViewModelT<AboutViewModel, implementation::AboutViewModel> {};
}
