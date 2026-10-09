// Created by Rui MA on 09 Oct 2026

#pragma once

#include <Windows.h>
#undef GetCurrentTime
#include <functional>
#include <utility>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Markup.h>
#include <winrt/UnlockDesktop.h>

namespace unlock_windows::desktop_app {
class DesktopApplication : public winrt::Microsoft::UI::Xaml::ApplicationT<DesktopApplication,
    winrt::Microsoft::UI::Xaml::Markup::IXamlMetadataProvider> {
public:
    explicit DesktopApplication(std::function<void()> launched) : launched_(std::move(launched)) {}
    winrt::Microsoft::UI::Xaml::Markup::IXamlType GetXamlType(const winrt::Windows::UI::Xaml::Interop::TypeName& type) {
        return provider_.GetXamlType(type);
    }
    winrt::Microsoft::UI::Xaml::Markup::IXamlType GetXamlType(const winrt::hstring& name) { return provider_.GetXamlType(name); }
    winrt::com_array<winrt::Microsoft::UI::Xaml::Markup::XmlnsDefinition> GetXmlnsDefinitions() {
        return provider_.GetXmlnsDefinitions();
    }
    void OnLaunched(const winrt::Microsoft::UI::Xaml::LaunchActivatedEventArgs&) {
        DispatcherShutdownMode(winrt::Microsoft::UI::Xaml::DispatcherShutdownMode::OnExplicitShutdown);
        Resources().MergedDictionaries().Append(winrt::Microsoft::UI::Xaml::Controls::XamlControlsResources{});
        launched_();
    }
private:
    winrt::UnlockDesktop::XamlMetaDataProvider provider_;
    std::function<void()> launched_;
};
}
