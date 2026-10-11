// Created by Rui MA on 09 Oct 2026

#pragma once

#include "AboutPage.g.h"
#include "../Dashboard.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>
#include <winrt/Microsoft.UI.Dispatching.h>

namespace winrt::UnlockDesktop::implementation {
struct AboutPage : AboutPageT<AboutPage> {
    AboutPage() = default;
    void OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    void Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError);
    void Stop();

private:
    static Windows::Foundation::IAsyncAction checkForUpdates(
        weak_ref<AboutPage> weak, Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
        unlock_windows::desktop_app::Dashboard::ReportError reportError);
    Microsoft::UI::Xaml::Controls::StackPanel aboutPanel_{nullptr};
    Microsoft::UI::Xaml::Controls::Button checkUpdates_{nullptr};
    Microsoft::UI::Xaml::Controls::TextBlock updateStatus_{nullptr};
    Microsoft::UI::Xaml::Controls::HyperlinkButton release_{nullptr};
    Windows::Foundation::IAsyncAction updateCheck_{nullptr};
    unlock_windows::desktop_app::Dashboard::ReportError reportError_;
    bool stopped_ = false;
};
}

namespace winrt::UnlockDesktop::factory_implementation {
struct AboutPage : AboutPageT<AboutPage, implementation::AboutPage> {};
}
