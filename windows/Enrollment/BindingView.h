// Created by Rui MA on 11 Oct 2026

#pragma once

#include <functional>
#include <string>
#include "../SavedCredential/SavedCredentialIpc.h"
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>

namespace unlock_windows::desktop_app {
struct BindingView final {
    winrt::Microsoft::UI::Xaml::Controls::ContentControl content{nullptr};
    std::function<void()> refresh, stop, remove;
    std::function<bool()> busy;
};

BindingView createBindingView(
    std::function<winrt::Microsoft::UI::Xaml::XamlRoot()> dialogRoot,
    std::function<void(std::wstring)> reportError,
    std::function<void(const saved_credential::BindingSummary&)> changed);
}
