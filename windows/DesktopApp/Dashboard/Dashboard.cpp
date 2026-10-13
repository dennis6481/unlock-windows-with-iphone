// Created by Rui MA on 08 Oct 2026

#include "Dashboard.h"
#include "../../Resources/resource.h"
#include "Pages/PageControls.h"

#include <Windows.h>
#undef GetCurrentTime
#include <commctrl.h>
#include <microsoft.ui.xaml.window.h>
#include <winrt/Windows.Foundation.Collections.h>
#include "Pages/StatusPage.xaml.h"
#include "Pages/PasswordPage.xaml.h"
#include "Pages/DiagnosticsPage.xaml.h"
#include <winrt/Windows.UI.Xaml.Interop.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include "Pages/AboutPage.xaml.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Controls.Primitives.h>
#include <winrt/Microsoft.UI.Xaml.Markup.h>
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <winrt/Microsoft.UI.Xaml.Media.Animation.h>
#include <winrt/UnlockDesktop.h>
#include <utility>
#include <array>
#include <map>

namespace unlock_windows::desktop_app {
using namespace winrt;
using namespace winrt::Microsoft::UI;
using namespace winrt::Microsoft::UI::Xaml;
using namespace winrt::Microsoft::UI::Xaml::Controls;
using namespace winrt::Microsoft::UI::Xaml::Markup;

using namespace dashboard_ui;

struct Dashboard::State final {
    struct View;
    std::unique_ptr<View> view;
    DashboardSnapshot snapshot;
    RefreshAction refresh;
    ReportError reportError;
    ReportError passwordReport;
    std::wstring failure;
    bool stopping = false;

    void fail(const hresult_error& error);
};
namespace {
NavigationViewItem navigationItem(DashboardPage page, const wchar_t* label, const wchar_t* glyph) {
    NavigationViewItem item;
    item.Content(box_value(hstring(label)));
    item.Tag(box_value(static_cast<std::int32_t>(page)));
    item.Icon(icon(glyph, 24));
    return item;
}

}

struct Dashboard::State::View final {
    explicit View(State* state) : state_(state) {}
    void refresh() {
        if (exiting_ || state_->stopping) return;
        try {
            if (!window_) buildWindow();
            if (!state_->failure.empty()) return;
            applySnapshot();
        } catch (const hresult_error& error) { state_->fail(error); }
    }

    void show(std::optional<DashboardPage> page) {
        refresh();
        if (exiting_ || state_->stopping || !window_) return;
        try {
            if (page) nav_.SelectedItem(pages_.at(static_cast<std::size_t>(*page)));
            ShowWindow(hwnd_, SW_RESTORE);
            window_.Activate();
            SetForegroundWindow(hwnd_);
            if (passwordPage_ && nav_.SelectedItem() == pages_[1])
                get_self<winrt::UnlockDesktop::implementation::PasswordPage>(passwordPage_)->Refresh();
        } catch (const hresult_error& error) { state_->fail(error); }
    }

private:
    static LRESULT CALLBACK sizing(HWND window, UINT message, WPARAM wparam, LPARAM lparam,
                                   UINT_PTR, DWORD_PTR) {
        if (message == WM_GETMINMAXINFO) {
            const auto dpi = GetDpiForWindow(window);
            auto* bounds = reinterpret_cast<MINMAXINFO*>(lparam);
            bounds->ptMinTrackSize = {MulDiv(800, dpi, 96), MulDiv(520, dpi, 96)};
            return 0;
        }
        return DefSubclassProc(window, message, wparam, lparam);
    }

    template<typename PageType>
    PageType navigateTo() {
        const auto type = xaml_typename<PageType>();
        if (!frame_.Navigate(type, nullptr, Media::Animation::EntranceNavigationTransitionInfo{}))
            throw hresult_error(E_FAIL, L"Failed to navigate to " + type.Name);
        return frame_.Content().as<PageType>();
    }

    void buildWindow() {
        window_ = Window{};
        window_.Title(UNLOCK_PRODUCT_DISPLAY_NAME);
        window_.SystemBackdrop(Media::MicaBackdrop{});
        check_hresult(window_.as<IWindowNative>()->get_WindowHandle(&hwnd_));
        appWindow_ = window_.AppWindow();
        appWindow_.TitleBar().PreferredTheme(Windowing::TitleBarTheme::UseDefaultAppMode);
        const auto dpi = GetDpiForWindow(hwnd_);
        appWindow_.Resize({MulDiv(900, dpi, 96), MulDiv(640, dpi, 96)});
        const auto appIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_UNLOCK_APP));
        if (!appIcon) throw_last_error();
        SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(appIcon));
        SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(appIcon));
        if (!SetWindowSubclass(hwnd_, sizing, 1, 0)) throw_last_error();
        closingToken_ = appWindow_.Closing([this](const auto&, const Windowing::AppWindowClosingEventArgs& args) {
            try {
                args.Cancel(true);
                if (statusPage_)
                    get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->DismissBindingSuccess();
                appWindow_.Hide();
            } catch (const hresult_error& error) { state_->fail(error); }
        });

        nav_ = XamlReader::Load(LR"(<NavigationView
            xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
            xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
            Background="Transparent">
            <NavigationView.Resources>
                <SolidColorBrush x:Key="NavigationViewContentBackground" Color="Transparent"/>
                <Thickness x:Key="NavigationViewContentGridBorderThickness">0</Thickness>
                <CornerRadius x:Key="NavigationViewContentGridCornerRadius">0</CornerRadius>
            </NavigationView.Resources>
        </NavigationView>)").as<NavigationView>();
        nav_.PaneDisplayMode(NavigationViewPaneDisplayMode::Auto);
        nav_.IsPaneToggleButtonVisible(false);
        nav_.OpenPaneLength(210);
        nav_.IsBackButtonVisible(NavigationViewBackButtonVisible::Collapsed);
        nav_.IsSettingsVisible(false);
        nav_.HorizontalContentAlignment(HorizontalAlignment::Stretch);
        nav_.VerticalContentAlignment(VerticalAlignment::Stretch);
        pages_ = {navigationItem(DashboardPage::status, L"Status", L"\xE8EA"),
            navigationItem(DashboardPage::password, L"Password", L"\xE72E"),
            navigationItem(DashboardPage::diagnostics, L"Diagnostics", L"\xE9D9"),
            navigationItem(DashboardPage::about, L"About", L"\xE946")};
        for (std::size_t index = 0; index < 3; ++index) nav_.MenuItems().Append(pages_[index]);
        nav_.FooterMenuItems().Append(pages_[3]);

        scroll_ = ScrollViewer{};
        scroll_.VerticalScrollBarVisibility(ScrollBarVisibility::Auto);
        scroll_.HorizontalScrollBarVisibility(ScrollBarVisibility::Disabled);
        scroll_.HorizontalContentAlignment(HorizontalAlignment::Stretch);
        scroll_.VerticalContentAlignment(VerticalAlignment::Top);
        root_ = Grid{};
        root_.MaxWidth(800);
        root_.HorizontalAlignment(HorizontalAlignment::Stretch);
        root_.Padding({28, 24, 28, 24});
        RowDefinition headerRow;
        headerRow.Height(automatic());
        root_.RowDefinitions().Append(headerRow);
        RowDefinition bodyRow;
        bodyRow.Height(automatic());
        root_.RowDefinitions().Append(bodyRow);

        title_ = text(L"Status", 28);
        title_.VerticalAlignment(VerticalAlignment::Center);
        root_.Children().Append(title_);

        frame_ = Frame{};
        Media::Animation::TransitionCollection transitions;
        transitions.Append(Media::Animation::NavigationThemeTransition{});
        frame_.ContentTransitions(transitions);
        frame_.IsNavigationStackEnabled(false);
        Grid::SetRow(frame_, 1);
        root_.Children().Append(frame_);

        Grid contentLayout;
        contentLayout.Children().Append(root_);
        scroll_.Content(contentLayout);
        nav_.Content(scroll_);
        navigationToken_ = nav_.SelectionChanged([this](const auto&, const NavigationViewSelectionChangedEventArgs& args) {
            try {
                const auto item = args.SelectedItem().try_as<NavigationViewItem>();
                if (!item) return;
                const auto pageId = static_cast<DashboardPage>(unbox_value<std::int32_t>(item.Tag()));
                if (currentPage_) scrollOffsets_[*currentPage_] = scroll_.VerticalOffset();
                currentPage_ = pageId;
                const bool statusPage = pageId == DashboardPage::status;
                const bool diagnosticsPage = pageId == DashboardPage::diagnostics;
                if (statusPage) {
                    statusPage_ = navigateTo<winrt::UnlockDesktop::StatusPage>();
                    get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->SetHost([this](bool resetScroll) {
                        if (resetScroll) {
                            scrollOffsets_[DashboardPage::status] = 0.0;
                            if (currentPage_ == DashboardPage::status) scroll_.ChangeView(nullptr, 0.0, nullptr, true);
                        }
                        state_->refresh();
                    });
                    get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->Update(state_->snapshot);
                } else if (diagnosticsPage) {
                    diagnosticsPage_ = navigateTo<winrt::UnlockDesktop::DiagnosticsPage>();
                    get_self<winrt::UnlockDesktop::implementation::DiagnosticsPage>(diagnosticsPage_)->SetScrollHost(scroll_);
                    get_self<winrt::UnlockDesktop::implementation::DiagnosticsPage>(diagnosticsPage_)->Update(state_->snapshot.diagnostics);
                } else if (pageId == DashboardPage::password) {
                    passwordPage_ = navigateTo<winrt::UnlockDesktop::PasswordPage>();
                    auto* page = get_self<winrt::UnlockDesktop::implementation::PasswordPage>(passwordPage_);
                    page->Bind(state_->passwordReport);
                    page->Refresh();
                } else if (pageId == DashboardPage::about) {
                    aboutPage_ = navigateTo<winrt::UnlockDesktop::AboutPage>();
                    get_self<winrt::UnlockDesktop::implementation::AboutPage>(aboutPage_)->Bind(
                        state_->reportError);
                } else throw hresult_invalid_argument(L"Unknown Dashboard page.");
                title_.Text(unbox_value<hstring>(item.Content()));
                scroll_.UpdateLayout();
                scroll_.ChangeView(nullptr, scrollOffsets_[pageId], nullptr, true);
            } catch (const hresult_error& error) { state_->fail(error); }
        });
        nav_.SelectedItem(pages_[0]);
        if (!state_->failure.empty()) return;
        Grid windowLayout;
        RowDefinition titleBarRow, navigationRow;
        titleBarRow.Height(automatic());
        navigationRow.Height(star());
        windowLayout.RowDefinitions().Append(titleBarRow);
        windowLayout.RowDefinitions().Append(navigationRow);
        TitleBar titleBar;
        titleBar.Title(UNLOCK_PRODUCT_DISPLAY_NAME);
        windowLayout.Children().Append(titleBar);
        Grid::SetRow(nav_, 1);
        windowLayout.Children().Append(nav_);
        window_.Content(windowLayout);
        window_.ExtendsContentIntoTitleBar(true);
        window_.SetTitleBar(titleBar);
        root_.RequestedTheme(ElementTheme::Default);
        activatedToken_ = window_.Activated([this](const auto&, const WindowActivatedEventArgs& args) {
            if (args.WindowActivationState() == WindowActivationState::Deactivated || exiting_) return;
            try {
                if (passwordPage_ && nav_.SelectedItem() == pages_[1])
                    get_self<winrt::UnlockDesktop::implementation::PasswordPage>(passwordPage_)->Refresh();
                if (statusPage_ && nav_.SelectedItem() == pages_[0])
                    get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->Refresh();
            } catch (const hresult_error& error) { state_->fail(error); }
        });
    }

    void applySnapshot() {
        const auto& snapshot = state_->snapshot;
        if (statusPage_) get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->Update(snapshot);
        if (diagnosticsPage_) get_self<winrt::UnlockDesktop::implementation::DiagnosticsPage>(diagnosticsPage_)->Update(snapshot.diagnostics);
    }

public:
    void shutdown() {
        if (exiting_) return;
        exiting_ = true;
        if (appWindow_ && closingToken_.value) appWindow_.Closing(closingToken_);
        if (window_ && activatedToken_.value) window_.Activated(activatedToken_);
        if (nav_ && navigationToken_.value) nav_.SelectionChanged(navigationToken_);
        if (aboutPage_) get_self<winrt::UnlockDesktop::implementation::AboutPage>(aboutPage_)->Stop();
        if (passwordPage_) get_self<winrt::UnlockDesktop::implementation::PasswordPage>(passwordPage_)->Stop();
        if (statusPage_) get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->Stop();
        if (diagnosticsPage_) get_self<winrt::UnlockDesktop::implementation::DiagnosticsPage>(diagnosticsPage_)->Stop();
        if (hwnd_) RemoveWindowSubclass(hwnd_, sizing, 1);
        if (window_) window_.Close();
        window_ = nullptr;
    }

private:
    State* state_;
    Window window_{nullptr};
    Windowing::AppWindow appWindow_{nullptr};
    HWND hwnd_ = nullptr;
    NavigationView nav_{nullptr};
    std::array<NavigationViewItem, 4> pages_{nullptr, nullptr, nullptr, nullptr};
    ScrollViewer scroll_{nullptr};
    std::optional<DashboardPage> currentPage_;
    std::map<DashboardPage, double> scrollOffsets_;
    Grid root_{nullptr};
    Frame frame_{nullptr};
    winrt::UnlockDesktop::StatusPage statusPage_{nullptr};
    winrt::UnlockDesktop::DiagnosticsPage diagnosticsPage_{nullptr};
    winrt::UnlockDesktop::AboutPage aboutPage_{nullptr};
    winrt::UnlockDesktop::PasswordPage passwordPage_{nullptr};
    TextBlock title_{nullptr};
    bool exiting_ = false;
    event_token closingToken_{}, navigationToken_{};
    event_token activatedToken_{};
};

Dashboard::Dashboard(RefreshAction refresh, ReportError reportError, ReportError passwordReport) : state_(std::make_unique<State>()) {
    state_->refresh = std::move(refresh);
    state_->reportError = std::move(reportError);
    state_->passwordReport = std::move(passwordReport);
}

Dashboard::~Dashboard() { stop(); }

void Dashboard::State::fail(const hresult_error& error) {
    rethrowNonlocalUiError(error);
    failure = std::wstring(error.message());
    reportError(L"Dashboard: " + failure);
    if (view) view->shutdown();
}

void Dashboard::show(std::optional<DashboardPage> page) {
    if (state_->stopping) return;
    if (!state_->failure.empty()) {
        state_->reportError(L"Dashboard is unavailable: " + state_->failure);
        return;
    }
    try {
        if (!state_->view) state_->view = std::make_unique<State::View>(state_.get());
        state_->view->show(page);
    } catch (const hresult_error& error) { state_->fail(error); }
}

void Dashboard::update(DashboardSnapshot snapshot) {
    if (state_->stopping || !state_->failure.empty()) return;
    state_->snapshot = std::move(snapshot);
    if (state_->view) state_->view->refresh();
}

void Dashboard::stop() {
    state_->stopping = true;
    if (state_->view) state_->view->shutdown();
    state_->view.reset();
}

}
