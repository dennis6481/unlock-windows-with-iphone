// Created by Rui MA on 09 Oct 2026

#include "DiagnosticsPage.xaml.h"
#include "DiagnosticsPage.g.cpp"
#include <winrt/Windows.Foundation.h>
#include <algorithm>

namespace winrt::UnlockDesktop::implementation {
DiagnosticsPage::DiagnosticsPage() {
    viewModel_ = make<DiagnosticsViewModel>();
    InitializeComponent();
    changed_ = viewModel_.PropertyChanged([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) page->ApplyText();
    });
}
void DiagnosticsPage::Update(std::wstring const& diagnostics) { get_self<DiagnosticsViewModel>(viewModel_)->Update(diagnostics); }
void DiagnosticsPage::ApplyText() {
    const auto text = DiagnosticsText();
    const auto selectionStart = text.SelectionStart();
    const auto selectionLength = text.SelectionLength();
    const auto scroll = scrollHost_.get();
    const auto verticalOffset = scroll ? scroll.VerticalOffset() : 0.0;
    text.Text(viewModel_.Text());
    const auto textLength = static_cast<int32_t>(text.Text().size());
    const auto start = std::min(selectionStart, textLength);
    text.Select(start, std::min(selectionLength, textLength - start));
    if (scroll) {
        scroll.UpdateLayout();
        scroll.ChangeView(nullptr, verticalOffset, nullptr, true);
    }
}
void DiagnosticsPage::SetScrollHost(Microsoft::UI::Xaml::Controls::ScrollViewer const& scroll) { scrollHost_ = make_weak(scroll); }
void DiagnosticsPage::Stop() {
    if (changed_.value) { viewModel_.PropertyChanged(changed_); changed_ = {}; }
}
}
