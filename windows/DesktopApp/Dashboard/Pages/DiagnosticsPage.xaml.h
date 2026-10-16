// Created by Rui MA on 09 Oct 2026

#pragma once
#include "DiagnosticsPage.g.h"
#include "../ViewModels/DiagnosticsViewModel.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>

namespace winrt::UnlockDesktop::implementation {
struct DiagnosticsPage : DiagnosticsPageT<DiagnosticsPage> {
    /// Initialize the diagnostic view and observe its presentation model.
    DiagnosticsPage();
    /// Expose the cached diagnostic presentation state.
    UnlockDesktop::DiagnosticsViewModel ViewModel() const { return viewModel_; }
    /// Forward controller text without moving selection or scroll into the model.
    void Update(std::wstring const& diagnostics);
    /// Release the model subscription during desktop shutdown.
    void Stop();
    /// Retain a weak reference to the Dashboard-owned scroll viewer.
    void SetScrollHost(Microsoft::UI::Xaml::Controls::ScrollViewer const& scroll);
private:
    /// Apply model text while preserving the existing selection and viewport.
    void ApplyText();
    UnlockDesktop::DiagnosticsViewModel viewModel_{nullptr};
    weak_ref<Microsoft::UI::Xaml::Controls::ScrollViewer> scrollHost_;
    event_token changed_{};
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct DiagnosticsPage : DiagnosticsPageT<DiagnosticsPage, implementation::DiagnosticsPage> {};
}
