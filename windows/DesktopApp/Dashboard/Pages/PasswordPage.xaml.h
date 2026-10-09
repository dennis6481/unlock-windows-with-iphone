// Created by Rui MA on 09 Oct 2026

#pragma once

#include "PasswordPage.g.h"
#include "../Dashboard.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::UnlockDesktop::implementation {
struct PasswordPage : PasswordPageT<PasswordPage> {
    PasswordPage() = default;
    void OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    void Bind(unlock_windows::desktop_app::Dashboard::PasswordAction action);

private:
    Microsoft::UI::Xaml::Controls::StackPanel passwordPanel_{nullptr};
    Microsoft::UI::Xaml::Controls::Button password_{nullptr};
    unlock_windows::desktop_app::Dashboard::PasswordAction managePassword_;
};
}

namespace winrt::UnlockDesktop::factory_implementation {
struct PasswordPage : PasswordPageT<PasswordPage, implementation::PasswordPage> {};
}
