// Created by Rui MA on 08 Oct 2026

#include "Dashboard.h"
#include "../../Resources/resource.h"

#include <Windows.h>
#undef GetCurrentTime
#include <commctrl.h>
#include <microsoft.ui.xaml.window.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.UI.Xaml.Interop.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Controls.Primitives.h>
#include <winrt/Microsoft.UI.Xaml.Markup.h>
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <winrt/Microsoft.UI.Xaml.XamlTypeInfo.h>

#include <mutex>
#include <thread>
#include <utility>

namespace unlock_windows::desktop_app {
using namespace winrt;
using namespace winrt::Microsoft::UI;
using namespace winrt::Microsoft::UI::Xaml;
using namespace winrt::Microsoft::UI::Xaml::Controls;
using namespace winrt::Microsoft::UI::Xaml::Markup;

namespace { std::wstring currentException(); }

struct Dashboard::State final {
    std::mutex mutex;
    std::thread thread;
    Dispatching::DispatcherQueue dispatcher{nullptr};
    DashboardSnapshot snapshot;
    PairingAction action;
    RefreshAction refresh;
    ReportError reportError;
    std::wstring failure;
    bool stopping = false;
    bool shown = false;
    bool showRequested = false;

    struct App;
    App* app = nullptr;

    void report(std::wstring message) {
        {
            std::lock_guard lock(mutex);
            failure = message;
        }
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
TextBlock text(const wchar_t* value, double size = 14) {
    TextBlock block;
    block.Text(value);
    block.FontSize(size);
    block.TextWrapping(TextWrapping::Wrap);
    return block;
}

FontIcon icon(const wchar_t* glyph, double size = 20) {
    FontIcon result;
    result.FontFamily(Media::FontFamily(L"Segoe Fluent Icons, Segoe MDL2 Assets"));
    result.Glyph(glyph);
    result.FontSize(size);
    return result;
}

NavigationViewItem navigationItem(const wchar_t* label, const wchar_t* glyph) {
    NavigationViewItem item;
    item.Content(box_value(hstring(label)));
    item.Tag(box_value(hstring(label)));
    item.Icon(icon(glyph));
    return item;
}

GridLength star() { return {1, GridUnitType::Star}; }
GridLength automatic() { return {0, GridUnitType::Auto}; }

std::wstring currentException() {
    try { throw; }
    catch (const hresult_error& error) {
        return std::wstring(error.message()) + L" (HRESULT=" +
            std::to_wstring(static_cast<unsigned long>(error.code().value)) + L")";
    }
    catch (const std::exception& error) { return std::wstring(to_hstring(error.what())); }
    catch (...) { return L"Unknown Dashboard error."; }
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
        nav_.PaneDisplayMode(NavigationViewPaneDisplayMode::Left);
        nav_.OpenPaneLength(210);
        nav_.IsBackButtonVisible(NavigationViewBackButtonVisible::Collapsed);
        nav_.IsSettingsVisible(false);
        nav_.PaneTitle(UNLOCK_PRODUCT_DISPLAY_NAME);
        auto status = navigationItem(L"Status", L"\xE8EA");
        nav_.MenuItems().Append(status);
        nav_.MenuItems().Append(navigationItem(L"Diagnostics", L"\xE9D9"));

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

        ScrollViewer scroll;
        scroll.VerticalScrollBarVisibility(ScrollBarVisibility::Auto);
        scroll.HorizontalScrollBarVisibility(ScrollBarVisibility::Disabled);
        scroll.VerticalContentAlignment(VerticalAlignment::Center);
        Grid::SetRow(scroll, 1);
        body_ = StackPanel{};
        body_.MaxWidth(560);
        body_.Spacing(20);
        body_.Margin({0, 32, 0, 0});
        scroll.Content(body_);
        root_.Children().Append(scroll);

        statusPanel_ = StackPanel{};
        statusPanel_.Spacing(12);
        auto phone = icon(L"\xE8EA", 100);
        phone.HorizontalAlignment(HorizontalAlignment::Center);
        Automation::AutomationProperties::SetName(phone, L"iPhone");
        statusPanel_.Children().Append(phone);
        name_ = text(L"iPhone", 24);
        name_.TextAlignment(TextAlignment::Center);
        statusPanel_.Children().Append(name_);
        statusText_ = text(L"");
        statusText_.TextAlignment(TextAlignment::Center);
        statusPanel_.Children().Append(statusText_);
        connection_ = text(L"");
        connection_.TextAlignment(TextAlignment::Center);
        statusPanel_.Children().Append(connection_);

        auto card = XamlReader::Load(LR"(<Border
            xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
            Background="{ThemeResource CardBackgroundFillColorDefaultBrush}"
            BorderBrush="{ThemeResource CardStrokeColorDefaultBrush}"
            BorderThickness="1" CornerRadius="8" Padding="20,18" Margin="0,16,0,0"/>)").as<Border>();
        Grid approval;
        ColumnDefinition labelColumn;
        labelColumn.Width(star());
        approval.ColumnDefinitions().Append(labelColumn);
        ColumnDefinition valueColumn;
        valueColumn.Width(automatic());
        approval.ColumnDefinitions().Append(valueColumn);
        approval.Children().Append(text(L"Last approval"));
        auto value = text(L"N/A");
        Grid::SetColumn(value, 1);
        approval.Children().Append(value);
        card.Child(approval);
        approvalCard_ = card;
        statusPanel_.Children().Append(card);

        error_ = InfoBar{};
        error_.Severity(InfoBarSeverity::Error);
        error_.IsClosable(false);
        statusPanel_.Children().Append(error_);
        diagnostics_ = TextBox{};
        diagnostics_.IsReadOnly(true);
        diagnostics_.AcceptsReturn(true);
        diagnostics_.TextWrapping(TextWrapping::Wrap);
        diagnostics_.MinHeight(320);
        Automation::AutomationProperties::SetName(diagnostics_, L"Technical details and diagnostic history");
        nav_.Content(root_);
        navigationToken_ = nav_.SelectionChanged([this](const auto&, const NavigationViewSelectionChangedEventArgs& args) {
            const auto item = args.SelectedItem().try_as<NavigationViewItem>();
            if (!item) return;
            const auto label = unbox_value<hstring>(item.Tag());
            title_.Text(label);
            const bool statusPage = label == L"Status";
            action_.Visibility(statusPage ? Visibility::Visible : Visibility::Collapsed);
            body_.Children().Clear();
            body_.MaxWidth(statusPage ? 560 : 900);
            if (statusPage) body_.Children().Append(statusPanel_);
            else body_.Children().Append(diagnostics_);
        });
        nav_.SelectedItem(status);
        window_.Content(nav_);
        root_.RequestedTheme(ElementTheme::Default);
    }

    void applySnapshot() {
        actionPending_ = false;
        const bool known = snapshot_.paired.has_value();
        const bool paired = snapshot_.paired.value_or(false);
        name_.Text(!known ? L"Pairing status unavailable" : paired ? L"iPhone" : L"Pair an iPhone");
        statusText_.Text(!known || paired || snapshot_.busy ? snapshot_.status :
            L"Open Unlock PC on your iPhone, then choose Add a Windows PC.");
        connection_.Text(snapshot_.connection);
        action_.Content(box_value(hstring(paired ? L"Remove iPhone" : L"Pair iPhone")));
        action_.IsEnabled(known && !snapshot_.busy);
        approvalCard_.Visibility(known && paired ? Visibility::Visible : Visibility::Collapsed);
        error_.Title(L"Status needs attention");
        error_.Message(snapshot_.error);
        error_.IsOpen(!snapshot_.error.empty());
        diagnostics_.Text(snapshot_.diagnostics);
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
    XamlTypeInfo::XamlControlsXamlMetaDataProvider provider_;
    Window window_{nullptr};
    Windowing::AppWindow appWindow_{nullptr};
    HWND hwnd_ = nullptr;
    NavigationView nav_{nullptr};
    Grid root_{nullptr};
    StackPanel body_{nullptr};
    StackPanel statusPanel_{nullptr};
    TextBlock title_{nullptr}, name_{nullptr}, statusText_{nullptr}, connection_{nullptr};
    Button action_{nullptr}, refresh_{nullptr};
    TextBox diagnostics_{nullptr};
    Border approvalCard_{nullptr};
    InfoBar error_{nullptr};
    DashboardSnapshot snapshot_;
    bool actionPending_ = false;
    bool exiting_ = false;
    event_token closingToken_{}, navigationToken_{}, actionToken_{}, refreshToken_{}, unhandledToken_{};
};

Dashboard::Dashboard(PairingAction action, RefreshAction refresh, ReportError reportError) : state_(std::make_shared<State>()) {
    state_->action = std::move(action);
    state_->refresh = std::move(refresh);
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
