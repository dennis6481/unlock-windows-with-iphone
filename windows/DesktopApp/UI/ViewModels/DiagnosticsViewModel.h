// Created by Rui MA on 16 Oct 2026

#pragma once

#include "DiagnosticsViewModel.g.h"
#include "Observable.h"

namespace winrt::UnlockDesktop::implementation {
struct DiagnosticsViewModel : DiagnosticsViewModelT<DiagnosticsViewModel>, unlock_windows::desktop_app::Observable<DiagnosticsViewModel> {
    using unlock_windows::desktop_app::Observable<DiagnosticsViewModel>::PropertyChanged;
    /// Construct the presentation state for the existing desktop diagnostic history.
    DiagnosticsViewModel() = default;
    /// Return the latest history supplied by the desktop controller.
    hstring Text() const { return text_; }
    /// Notify the view only when the diagnostic text actually changes.
    void Update(const std::wstring& text) {
        if (text_ == text) return;
        text_ = text;
        Notify({L"Text"});
    }
private:
    hstring text_;
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct DiagnosticsViewModel : DiagnosticsViewModelT<DiagnosticsViewModel, implementation::DiagnosticsViewModel> {};
}
