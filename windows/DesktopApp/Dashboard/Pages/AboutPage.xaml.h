// Created by Rui MA on 09 Oct 2026

#pragma once
#include "AboutPage.g.h"
#include "../ViewModels/AboutViewModel.h"

namespace winrt::UnlockDesktop::implementation {
struct AboutPage : AboutPageT<AboutPage> {
    /// Initialize the unchanged presentation and its cached view model.
    AboutPage();
    /// Expose the model to compiled XAML bindings.
    UnlockDesktop::AboutViewModel ViewModel() const { return viewModel_; }
    /// Forward the existing host diagnostic callback.
    void Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError);
    /// Stop update work during desktop shutdown.
    void Stop();
private:
    UnlockDesktop::AboutViewModel viewModel_{nullptr};
};
}
namespace winrt::UnlockDesktop::factory_implementation {
struct AboutPage : AboutPageT<AboutPage, implementation::AboutPage> {};
}
