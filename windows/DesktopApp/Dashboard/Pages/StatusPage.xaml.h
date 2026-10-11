// Created by Rui MA on 09 Oct 2026

#pragma once

#include "StatusPage.g.h"
#include "../Dashboard.h"
#include "../../../Enrollment/BindingView.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::UnlockDesktop::implementation {
struct StatusPage : StatusPageT<StatusPage> {
    StatusPage() = default;
    void OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    void Update(unlock_windows::desktop_app::DashboardSnapshot const& snapshot);
    void Stop();
    void Refresh();
    void Remove();
    bool Busy() const;

private:
    Microsoft::UI::Xaml::Controls::StackPanel statusPanel_{nullptr};
    Microsoft::UI::Xaml::Controls::TextBlock name_{nullptr}, statusText_{nullptr}, connection_{nullptr};
    Microsoft::UI::Xaml::Controls::Border approvalCard_{nullptr};
    Microsoft::UI::Xaml::Controls::InfoBar error_{nullptr};
    Microsoft::UI::Xaml::Controls::Slider threshold_{nullptr};
    Microsoft::UI::Xaml::Controls::TextBlock thresholdText_{nullptr};
    Microsoft::UI::Xaml::Controls::Button save_{nullptr};
    std::optional<unlock_windows::desktop_app::BindingView> bindingView_;
    std::optional<unlock_windows::saved_credential::BindingSummary> binding_;
    bool saving_ = false, dirty_ = false, updating_ = false, stopped_ = false;
    std::wstring saveError_;
    winrt::handle cancellation_;
    void EnsureBindingView();
    static winrt::fire_and_forget save(winrt::weak_ref<StatusPage> weak);
};
}

namespace winrt::UnlockDesktop::factory_implementation {
struct StatusPage : StatusPageT<StatusPage, implementation::StatusPage> {};
}
