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
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include "Pages/AboutPage.xaml.h"
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Controls.Primitives.h>
#include <winrt/Microsoft.UI.Xaml.Markup.h>
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <winrt/UnlockDesktop.h>

#include <mutex>
#include <thread>
#include <utility>

namespace unlock_windows::desktop_app {
using namespace winrt;
using namespace winrt::Microsoft::UI;
using namespace winrt::Microsoft::UI::Xaml;
using namespace winrt::Microsoft::UI::Xaml::Controls;
using namespace winrt::Microsoft::UI::Xaml::Markup;

using namespace dashboard_ui;

struct Dashboard::State final {
    std::mutex mutex;
    std::thread thread;
    Dispatching::DispatcherQueue dispatcher{nullptr};
    DashboardSnapshot snapshot;
    PairingAction action;
    RefreshAction refresh;
    PasswordAction password;
    ReportError reportError;
    std::wstring failure;
    bool stopping = false;
    bool shown = false;
    bool showRequested = false;

    struct App;
    App* app = nullptr;

    void report(std::wstring message) {
        std::lock_guard lock(mutex);
        if (stopping) {
            OutputDebugStringW(message.c_str());
            return;
        }
        failure = message;
        reportError(std::move(message));
    }

    void enqueue(Dispatching::DispatcherQueueHandler handler) {
        Dispatching::DispatcherQueue queue{nullptr};
        {
            std::lock_guard lock(mutex);
            queue = dispatcher;
        }
        try {
            if (queue && !queue.TryEnqueue(handler))
                report(L"The Dashboard UI dispatcher rejected an update.");
        } catch (...) { report(currentException()); }
    }
};

namespace {
NavigationViewItem navigationItem(const wchar_t* label, const wchar_t* glyph) {
    NavigationViewItem item;
    item.Content(box_value(hstring(label)));
    item.Tag(box_value(hstring(label)));
    item.Icon(icon(glyph));
    return item;
}

}

struct Dashboard::State::App : ApplicationT<App, IXamlMetadataProvider> {
    explicit App(std::shared_ptr<State> state) : state_(std::move(state)) {}

    IXamlType GetXamlType(const Windows::UI::Xaml::Interop::TypeName& type) {
        return provider_.GetXamlType(type);
    }
    IXamlType GetXamlType(const hstring& name) { return provider_.GetXamlType(name); }
    com_array<XmlnsDefinition> GetXmlnsDefinitions() { return provider_.GetXmlnsDefinitions(); }

    void OnLaunched(const LaunchActivatedEventArgs&) {
        try {
            state_->app = this;
            Resources().MergedDictionaries().Append(XamlControlsResources{});
            unhandledToken_ = UnhandledException([this](const auto&, const UnhandledExceptionEventArgs& args) {
                args.Handled(true);
                state_->report(L"Dashboard UI: " + std::wstring(args.Message()));
                shutdown();
            });
            buildWindow();
            bool stopping;
            {
                std::lock_guard lock(state_->mutex);
                state_->dispatcher = Dispatching::DispatcherQueue::GetForCurrentThread();
                stopping = state_->stopping;
            }
            if (stopping) { shutdown(); return; }
            refresh();
        } catch (...) {
            state_->report(currentException());
            shutdown();
        }
    }

    void refresh() {
        try {
            DashboardSnapshot snapshot;
            bool show;
            bool stopping;
            {
                std::lock_guard lock(state_->mutex);
                snapshot = state_->snapshot;
                show = std::exchange(state_->showRequested, false);
                stopping = state_->stopping;
            }
            if (stopping) { shutdown(); return; }
            snapshot_ = std::move(snapshot);
            applySnapshot();
            if (show) {
                ShowWindow(hwnd_, SW_RESTORE);
                window_.Activate();
                SetForegroundWindow(hwnd_);
                std::lock_guard lock(state_->mutex);
                state_->shown = true;
            }
        } catch (...) {
            state_->report(currentException());
            shutdown();
        }
    }

private:
    static LRESULT CALLBACK sizing(HWND window, UINT message, WPARAM wparam, LPARAM lparam,
                                   UINT_PTR, DWORD_PTR) {
        if (message == WM_GETMINMAXINFO) {
            const auto dpi = GetDpiForWindow(window);
            auto* bounds = reinterpret_cast<MINMAXINFO*>(lparam);
            bounds->ptMinTrackSize = {MulDiv(720, dpi, 96), MulDiv(520, dpi, 96)};
            return 0;
        }
        return DefSubclassProc(window, message, wparam, lparam);
    }

    template<typename PageType>
    PageType navigateTo() {
        const auto type = xaml_typename<PageType>();
        if (!frame_.Navigate(type))
            throw hresult_error(E_FAIL, L"Failed to navigate to " + type.Name);
        return frame_.Content().as<PageType>();
    }

    void buildWindow() {
        window_ = Window{};
        window_.Title(UNLOCK_PRODUCT_DISPLAY_NAME);
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
            args.Cancel(true);
            appWindow_.Hide();
            std::lock_guard lock(state_->mutex);
            state_->shown = false;
        });

        nav_ = NavigationView{};
        nav_.PaneDisplayMode(NavigationViewPaneDisplayMode::Auto);
        nav_.OpenPaneLength(210);
        nav_.IsBackButtonVisible(NavigationViewBackButtonVisible::Collapsed);
        nav_.IsSettingsVisible(false);
        nav_.HorizontalContentAlignment(HorizontalAlignment::Stretch);
        nav_.VerticalContentAlignment(VerticalAlignment::Stretch);
        auto status = navigationItem(L"Status", L"\xE8EA");
        nav_.MenuItems().Append(status);
        nav_.MenuItems().Append(navigationItem(L"Password", L"\xE72E"));
        nav_.MenuItems().Append(navigationItem(L"Diagnostics", L"\xE9D9"));
        nav_.FooterMenuItems().Append(navigationItem(L"About", L"\xE946"));

        root_ = Grid{};
        root_.Padding({28, 24, 28, 24});
        RowDefinition headerRow;
        headerRow.Height(automatic());
        root_.RowDefinitions().Append(headerRow);
        RowDefinition bodyRow;
        bodyRow.Height(star());
        root_.RowDefinitions().Append(bodyRow);

        Grid header;
        ColumnDefinition titleColumn;
        titleColumn.Width(star());
        header.ColumnDefinitions().Append(titleColumn);
        ColumnDefinition actionColumn;
        actionColumn.Width(automatic());
        header.ColumnDefinitions().Append(actionColumn);
        title_ = text(L"Status", 28);
        title_.VerticalAlignment(VerticalAlignment::Center);
        header.Children().Append(title_);
        StackPanel actions;
        actions.Orientation(Orientation::Horizontal);
        actions.Spacing(12);
        Grid::SetColumn(actions, 1);
        action_ = Button{};
        action_.HorizontalAlignment(HorizontalAlignment::Right);
        Grid::SetColumn(action_, 1);
        actionToken_ = action_.Click([this](const auto&, const auto&) {
            if (!snapshot_.paired.has_value() || snapshot_.busy || actionPending_) return;
            actionPending_ = true;
            action_.IsEnabled(false);
            state_->action(*snapshot_.paired);
        });
        actions.Children().Append(action_);
        refresh_ = Button{};
        refresh_.Content(box_value(L"Refresh"));
        refresh_.HorizontalAlignment(HorizontalAlignment::Right);
        Grid::SetColumn(refresh_, 1);
        refreshToken_ = refresh_.Click([this](const auto&, const auto&) { state_->refresh(); });
        actions.Children().Append(refresh_);
        header.Children().Append(actions);
        root_.Children().Append(header);

        frame_ = Frame{};
        frame_.IsNavigationStackEnabled(false);
        Grid::SetRow(frame_, 1);
        root_.Children().Append(frame_);

        nav_.Content(root_);
        navigationToken_ = nav_.SelectionChanged([this](const auto&, const NavigationViewSelectionChangedEventArgs& args) {
            const auto item = args.SelectedItem().try_as<NavigationViewItem>();
            if (!item) return;
            const auto label = unbox_value<hstring>(item.Tag());
            const bool statusPage = label == L"Status";
            const bool diagnosticsPage = label == L"Diagnostics";
            if (statusPage) {
                statusPage_ = navigateTo<winrt::UnlockDesktop::StatusPage>();
                get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->Update(snapshot_);
            } else if (diagnosticsPage) {
                diagnosticsPage_ = navigateTo<winrt::UnlockDesktop::DiagnosticsPage>();
                get_self<winrt::UnlockDesktop::implementation::DiagnosticsPage>(diagnosticsPage_)->Update(snapshot_.diagnostics);
            } else if (label == L"Password") {
                const auto page = navigateTo<winrt::UnlockDesktop::PasswordPage>();
                get_self<winrt::UnlockDesktop::implementation::PasswordPage>(page)->Bind(state_->password);
            } else if (label == L"About") {
                aboutPage_ = navigateTo<winrt::UnlockDesktop::AboutPage>();
                get_self<winrt::UnlockDesktop::implementation::AboutPage>(aboutPage_)->Bind(
                    [state = state_](std::wstring message) { state->report(std::move(message)); });
            } else throw hresult_invalid_argument(L"Unknown Dashboard page.");
            root_.MaxWidth(diagnosticsPage ? 900 : 560);
            title_.Text(label);
            action_.Visibility(statusPage ? Visibility::Visible : Visibility::Collapsed);
            refresh_.Visibility(statusPage || diagnosticsPage ? Visibility::Visible : Visibility::Collapsed);
        });
        nav_.SelectedItem(status);
        window_.Content(nav_);
        root_.RequestedTheme(ElementTheme::Default);
    }

    void applySnapshot() {
        actionPending_ = false;
        const bool known = snapshot_.paired.has_value();
        const bool paired = snapshot_.paired.value_or(false);
        action_.Content(box_value(hstring(paired ? L"Remove iPhone" : L"Pair iPhone")));
        action_.IsEnabled(known && !snapshot_.busy);
        if (statusPage_) get_self<winrt::UnlockDesktop::implementation::StatusPage>(statusPage_)->Update(snapshot_);
        if (diagnosticsPage_) get_self<winrt::UnlockDesktop::implementation::DiagnosticsPage>(diagnosticsPage_)->Update(snapshot_.diagnostics);
    }

public:
    void shutdown() {
        if (exiting_) return;
        exiting_ = true;
        if (unhandledToken_.value) UnhandledException(unhandledToken_);
        if (appWindow_ && closingToken_.value) appWindow_.Closing(closingToken_);
        if (nav_ && navigationToken_.value) nav_.SelectionChanged(navigationToken_);
        if (action_ && actionToken_.value) action_.Click(actionToken_);
        if (refresh_ && refreshToken_.value) refresh_.Click(refreshToken_);
        if (aboutPage_) get_self<winrt::UnlockDesktop::implementation::AboutPage>(aboutPage_)->Stop();
        if (hwnd_) RemoveWindowSubclass(hwnd_, sizing, 1);
        if (window_) window_.Close();
        window_ = nullptr;
        state_->app = nullptr;
        {
            std::lock_guard lock(state_->mutex);
            state_->dispatcher = nullptr;
            state_->shown = false;
        }
        Exit();
    }

private:
    std::shared_ptr<State> state_;
    winrt::UnlockDesktop::XamlMetaDataProvider provider_;
    Window window_{nullptr};
    Windowing::AppWindow appWindow_{nullptr};
    HWND hwnd_ = nullptr;
    NavigationView nav_{nullptr};
    Grid root_{nullptr};
    Frame frame_{nullptr};
    winrt::UnlockDesktop::StatusPage statusPage_{nullptr};
    winrt::UnlockDesktop::DiagnosticsPage diagnosticsPage_{nullptr};
    winrt::UnlockDesktop::AboutPage aboutPage_{nullptr};
    TextBlock title_{nullptr};
    Button action_{nullptr}, refresh_{nullptr};
    DashboardSnapshot snapshot_;
    bool actionPending_ = false;
    bool exiting_ = false;
    event_token closingToken_{}, navigationToken_{}, actionToken_{}, refreshToken_{}, unhandledToken_{};
};

Dashboard::Dashboard(PairingAction action, RefreshAction refresh, PasswordAction password, ReportError reportError) : state_(std::make_shared<State>()) {
    state_->action = std::move(action);
    state_->refresh = std::move(refresh);
    state_->password = std::move(password);
    state_->reportError = std::move(reportError);
}

Dashboard::~Dashboard() { stop(); }

void Dashboard::show() {
    {
        std::lock_guard lock(state_->mutex);
        if (state_->stopping) return;
        if (!state_->failure.empty()) throw std::runtime_error(to_string(state_->failure));
        state_->showRequested = true;
    }
    if (!state_->thread.joinable()) {
        state_->thread = std::thread([state = state_] {
            try {
                init_apartment(apartment_type::single_threaded);
                struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
                com_ptr<State::App> app;
                Application::Start([&](const auto&) { app = make_self<State::App>(state); });
                {
                    std::lock_guard lock(state->mutex);
                    state->dispatcher = nullptr;
                    state->shown = false;
                }
                app = nullptr;
            } catch (...) { state->report(currentException()); }
            {
                std::lock_guard lock(state->mutex);
                state->dispatcher = nullptr;
                state->shown = false;
                state->showRequested = false;
            }
        });
    } else state_->enqueue([state = state_] { if (state->app) state->app->refresh(); });
}

void Dashboard::update(DashboardSnapshot snapshot) {
    {
        std::lock_guard lock(state_->mutex);
        if (state_->stopping || !state_->failure.empty()) return;
        state_->snapshot = std::move(snapshot);
    }
    state_->enqueue([state = state_] { if (state->app) state->app->refresh(); });
}

bool Dashboard::visible() const {
    std::lock_guard lock(state_->mutex);
    return state_->shown || state_->showRequested;
}

void Dashboard::stop() {
    {
        std::lock_guard lock(state_->mutex);
        state_->stopping = true;
    }
    state_->enqueue([state = state_] { if (state->app) state->app->shutdown(); });
    if (state_->thread.joinable()) state_->thread.join();
}

}
