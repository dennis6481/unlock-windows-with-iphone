// Created by Rui MA on 09 Oct 2026

#include "DiagnosticsPage.xaml.h"
#include "DiagnosticsPage.g.cpp"
#include "PageControls.h"
#include <algorithm>
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
    ScrollViewer::SetVerticalScrollBarVisibility(diagnostics_, ScrollBarVisibility::Disabled);
    ScrollViewer::SetHorizontalScrollBarVisibility(diagnostics_, ScrollBarVisibility::Disabled);
    Automation::AutomationProperties::SetName(diagnostics_, L"Technical details and diagnostic history");

    BodyHost().Content(diagnostics_);
}

void DiagnosticsPage::Update(std::wstring const& diagnostics) {
    if (diagnostics == displayedDiagnostics_) return;
    const auto selectionStart = diagnostics_.SelectionStart();
    const auto selectionLength = diagnostics_.SelectionLength();
    const auto scroll = DiagnosticsScroll();
    const auto verticalOffset = scroll.VerticalOffset();
    diagnostics_.Text(diagnostics);
    displayedDiagnostics_ = diagnostics;
    const auto textLength = static_cast<int32_t>(diagnostics_.Text().size());
    const auto start = std::min(selectionStart, textLength);
    diagnostics_.Select(start, std::min(selectionLength, textLength - start));
    scroll.UpdateLayout();
    scroll.ChangeView(nullptr, verticalOffset, nullptr, true);
}
}
