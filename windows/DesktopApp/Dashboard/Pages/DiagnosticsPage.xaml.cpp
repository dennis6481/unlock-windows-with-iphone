// Created by Rui MA on 09 Oct 2026

#include "DiagnosticsPage.xaml.h"
#include "DiagnosticsPage.g.cpp"
#include "PageControls.h"
#include <winrt/Microsoft.UI.Xaml.Automation.h>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;

void DiagnosticsPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (diagnostics_) return;
    diagnostics_ = TextBox{};
    diagnostics_.IsReadOnly(true);
    diagnostics_.AcceptsReturn(true);
    diagnostics_.TextWrapping(TextWrapping::Wrap);
    diagnostics_.MinHeight(320);
    Automation::AutomationProperties::SetName(diagnostics_, L"Technical details and diagnostic history");

    BodyHost().Content(diagnostics_);
}

void DiagnosticsPage::Update(std::wstring const& diagnostics) {
    diagnostics_.Text(diagnostics);
}
}
