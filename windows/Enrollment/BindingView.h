// Created by Rui MA on 11 Oct 2026

#pragma once

#include <functional>
#include <string>
#include <winrt/Microsoft.UI.Xaml.Controls.h>

namespace unlock_windows::desktop_app {
struct BindingView final {
    winrt::Microsoft::UI::Xaml::Controls::ContentControl content{nullptr};
    std::function<void()> refresh, stop, remove;
    std::function<bool()> busy;
};

BindingView createBindingView(std::function<void(std::wstring)> reportError);
}
