// Created by Rui MA on 09 Oct 2026

#include "PasswordPage.xaml.h"
#include "PasswordPage.g.cpp"
#include "PageControls.h"
#include <vector>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
PasswordPage::PasswordPage() {
    viewModel_ = make<PasswordViewModel>();
    InitializeComponent();
    viewModel_.PropertyChanged([weak = get_weak()](const auto&, const auto& args) {
        if (auto page = weak.get()) {
            try {
                if (args.PropertyName() == L"CanRemove" && !page->viewModel_.CanRemove()) page->DismissRemoval();
                if (args.PropertyName() == L"Warning") page->NoticeBar().Severity(
                    page->viewModel_.Warning() ? InfoBarSeverity::Warning : InfoBarSeverity::Error);
            } catch (const hresult_error& error) {
                if (isNonlocalUiError(error)) throw;
                get_self<PasswordViewModel>(page->viewModel_)->UiError(error);
            }
        }
    });
}
void PasswordPage::Bind(unlock_windows::desktop_app::Dashboard::ReportError reportError) { get_self<PasswordViewModel>(viewModel_)->Bind(std::move(reportError)); }
void PasswordPage::OnNavigatedFrom(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) { DismissRemoval(); DismissPasswordSuccess(); }
void PasswordPage::DismissRemoval() { RemovalFlyout().Hide(); }
void PasswordPage::DismissPasswordSuccess() { get_self<PasswordViewModel>(viewModel_)->DismissSuccess(); }
void PasswordPage::Refresh() { get_self<PasswordViewModel>(viewModel_)->Refresh(); }
void PasswordPage::Stop() { DismissRemoval(); get_self<PasswordViewModel>(viewModel_)->Stop(); }
void PasswordPage::AccountCardSizeChanged(const Windows::Foundation::IInspectable&, const SizeChangedEventArgs& args) {
    resizeCard(AccountLayout(), AccountHeading(), AccountText(), args.NewSize().Width);
}
void PasswordPage::ManagementLoaded(const Windows::Foundation::IInspectable&, const RoutedEventArgs&) {
    try {
        Management().ApplyTemplate();
        std::vector<DependencyObject> elements{Management()};
        while (!elements.empty()) {
            auto element = elements.back(); elements.pop_back();
            if (auto toggle = element.try_as<Primitives::ToggleButton>(); toggle && toggle.Name() == L"ExpanderHeader") {
                toggle.Style(Resources().Lookup(box_value(L"PasswordExpanderHeaderStyle")).as<Microsoft::UI::Xaml::Style>());
                return;
            }
            const auto count = Media::VisualTreeHelper::GetChildrenCount(element);
            for (int index = 0; index < count; ++index) elements.push_back(Media::VisualTreeHelper::GetChild(element, index));
        }
        throw hresult_error(E_UNEXPECTED, L"The password Expander header was not found.");
    } catch (const hresult_error& failure) {
        if (isNonlocalUiError(failure)) throw;
        get_self<PasswordViewModel>(viewModel_)->UiError(failure);
    }
}
void PasswordPage::ManagementCollapsed(const Windows::Foundation::IInspectable&, const ExpanderCollapsedEventArgs&) { DismissRemoval(); }
void PasswordPage::ConfirmRemovalClick(const Windows::Foundation::IInspectable&, const RoutedEventArgs&) { DismissRemoval(); viewModel_.RemoveCommand().Execute(nullptr); }
void PasswordPage::SuccessClosed(const Windows::Foundation::IInspectable&, const InfoBarClosedEventArgs&) { get_self<PasswordViewModel>(viewModel_)->SuccessClosed(); }
}
