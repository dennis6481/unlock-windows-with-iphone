// Created by Rui MA on 09 Oct 2026

#include "AboutPage.xaml.h"
#include "AboutPage.g.cpp"

namespace winrt::UnlockDesktop::implementation {
AboutPage::AboutPage() {
    viewModel_ = make<AboutViewModel>();
    InitializeComponent();
}
void AboutPage::Bind(unlock_windows::desktop_app::MainWindow::ReportError reportError) {
    get_self<AboutViewModel>(viewModel_)->Bind(std::move(reportError));
}
void AboutPage::Stop() { get_self<AboutViewModel>(viewModel_)->Stop(); }
}
