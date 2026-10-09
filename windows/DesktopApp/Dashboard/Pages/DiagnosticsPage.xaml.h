// Created by Rui MA on 09 Oct 2026

#pragma once

#include "DiagnosticsPage.g.h"
#include "../Dashboard.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::UnlockDesktop::implementation {
struct DiagnosticsPage : DiagnosticsPageT<DiagnosticsPage> {
    DiagnosticsPage() = default;
    void OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
    void Update(std::wstring const& diagnostics);

private:
    Microsoft::UI::Xaml::Controls::TextBox diagnostics_{nullptr};
};
}

namespace winrt::UnlockDesktop::factory_implementation {
struct DiagnosticsPage : DiagnosticsPageT<DiagnosticsPage, implementation::DiagnosticsPage> {};
}
