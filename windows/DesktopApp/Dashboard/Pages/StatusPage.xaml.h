// Created by Rui MA on 09 Oct 2026

#pragma once

#include "StatusPage.g.h"
#include "../Dashboard.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::UnlockDesktop::implementation {
struct StatusPage : StatusPageT<StatusPage> {
    StatusPage() = default;
    void OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    void Update(unlock_windows::desktop_app::DashboardSnapshot const& snapshot);

private:
    Microsoft::UI::Xaml::Controls::StackPanel statusPanel_{nullptr};
    Microsoft::UI::Xaml::Controls::TextBlock name_{nullptr}, statusText_{nullptr}, connection_{nullptr};
    Microsoft::UI::Xaml::Controls::Border approvalCard_{nullptr};
    Microsoft::UI::Xaml::Controls::InfoBar error_{nullptr};
};
}

namespace winrt::UnlockDesktop::factory_implementation {
struct StatusPage : StatusPageT<StatusPage, implementation::StatusPage> {};
}
