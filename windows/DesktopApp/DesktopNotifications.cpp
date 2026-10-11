// Created by Rui MA on 10 Oct 2026

#include "DesktopNotifications.h"
#include "DesktopApplication.h"
#include "Dashboard/Pages/PageControls.h"
#include "../Resources/resource.h"
#include <microsoft.ui.xaml.window.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <deque>
#include <utility>

namespace unlock_windows::desktop_app {
using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Controls;

void showNativeUiError(const std::wstring& message, const std::wstring& uiError,
    const std::wstring& title) {
    const auto diagnostic = message + L"\nWinUI display failure: " + uiError;
    OutputDebugStringW((title + L": " + diagnostic + L"\n").c_str());
    MessageBoxW(nullptr, diagnostic.c_str(), title.c_str(), MB_OK | MB_ICONERROR);
}

struct DesktopNotifications::State final : std::enable_shared_from_this<State> {
    struct Notice { std::wstring message, title; NoticeSeverity severity; };
    std::deque<Notice> pending;
    std::function<void()> drained;
    Window window{nullptr};
    event_token closedToken{};
    bool advancing = false;
    bool stopped = false;
    bool failed = false;
    std::wstring failure;

    void notifyDrained() {
        const auto completed = drained;
        if (completed) completed();
    }

    void display() {
        if (stopped || window || advancing) return;
        while (!pending.empty()) {
            const auto& notice = pending.front();
            if (failed) {
                showNativeUiError(notice.message, failure, notice.title);
                pending.pop_front();
                continue;
            }
            try {
                window = Window{};
                window.Title(notice.title);
                const auto appWindow = window.AppWindow();
                appWindow.TitleBar().PreferredTheme(Microsoft::UI::Windowing::TitleBarTheme::UseDefaultAppMode);
                HWND hwnd = nullptr;
                check_hresult(window.as<IWindowNative>()->get_WindowHandle(&hwnd));
                const auto dpi = GetDpiForWindow(hwnd);
                appWindow.Resize({MulDiv(560, dpi, 96), MulDiv(360, dpi, 96)});
                const auto appIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_UNLOCK_APP));
                if (!appIcon) throw_last_error();
                SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(appIcon));
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(appIcon));
                StackPanel content;
                content.Spacing(16);
                content.Margin({28, 24, 28, 24});
                content.Children().Append(dashboard_ui::text(notice.title.c_str(), 24));
                InfoBar message;
                message.IsClosable(false);
                message.Severity(dashboard_ui::infoBarSeverity(notice.severity));
                message.Message(notice.message);
                message.IsOpen(true);
                content.Children().Append(message);
                Button close;
                close.Content(box_value(L"OK"));
                close.HorizontalAlignment(HorizontalAlignment::Right);
                close.Style(Application::Current().Resources().Lookup(box_value(L"AccentButtonStyle")).as<Style>());
                const auto weak = weak_from_this();
                close.Click([weak](const auto&, const auto&) {
                    if (const auto self = weak.lock(); self && self->window) {
                        try { self->window.Close(); }
                        catch (...) { self->displayFailure(); }
                    }
                });
                content.Children().Append(close);
                ScrollViewer scroll;
                scroll.HorizontalScrollBarVisibility(ScrollBarVisibility::Disabled);
                scroll.Content(content);
                window.Content(scroll);
                closedToken = window.Closed([weak](const auto&, const auto&) {
                    if (const auto self = weak.lock()) self->closed();
                });
                window.Activate();
                return;
            } catch (...) { displayFailure(); return; }
        }
        notifyDrained();
    }

    void releaseWindow() {
        if (!window) return;
        if (closedToken.value) window.Closed(closedToken);
        closedToken = {};
        auto closing = window;
        window = nullptr;
        closing.Close();
    }

    void displayFailure() {
        failure = dashboard_ui::currentException();
        failed = true;
        try { releaseWindow(); }
        catch (...) { failure += L"\n" + dashboard_ui::currentException(); }
        advancing = false;
        if (pending.empty()) {
            showNativeUiError(L"The desktop notification could not complete.", failure, L"Desktop needs attention");
            throw;
        }
        display();
    }

    void closed() {
        try {
            if (closedToken.value) window.Closed(closedToken);
            closedToken = {};
            window = nullptr;
            pending.pop_front();
            if (stopped) return;
            if (!pending.empty()) {
                advancing = true;
                const auto weak = weak_from_this();
                const auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
                if (!dispatcher || !dispatcher.TryEnqueue([weak] {
                    if (const auto self = weak.lock()) { self->advancing = false; self->display(); }
                })) throw hresult_error(E_FAIL, L"The WinUI dispatcher rejected the next notification.");
                return;
            }
        } catch (...) { displayFailure(); return; }
        notifyDrained();
    }
};

DesktopNotifications::DesktopNotifications(std::function<void()> drained) : state_(std::make_shared<State>()) {
    state_->drained = std::move(drained);
}

DesktopNotifications::~DesktopNotifications() {
    try { stop(); }
    catch (...) { showNativeUiError(L"Could not close the desktop notification.", dashboard_ui::currentException(), L"Desktop needs attention"); }
}

void DesktopNotifications::show(std::wstring message, std::wstring title, NoticeSeverity severity) {
    OutputDebugStringW((title + L": " + message + L"\n").c_str());
    state_->pending.push_back({std::move(message), std::move(title), severity});
    state_->display();
}

bool DesktopNotifications::empty() const { return state_->pending.empty(); }

void DesktopNotifications::stop() {
    state_->stopped = true;
    state_->drained = {};
    state_->releaseWindow();
    state_->pending.clear();
}

void showStartupError(const std::wstring& message, const std::wstring& title) {
    OutputDebugStringW((title + L": " + message + L"\n").c_str());
    try {
        init_apartment(apartment_type::single_threaded);
        struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
        com_ptr<DesktopApplication> app;
        DesktopNotifications notices([] { Application::Current().Exit(); });
        Application::Start([&](const auto&) {
            app = make_self<DesktopApplication>([&] { notices.show(message, title, NoticeSeverity::error); });
        });
        if (!notices.empty()) throw hresult_error(E_FAIL, L"WinUI ended before the error notification was acknowledged.");
        notices.stop();
        app = nullptr;
    } catch (...) { showNativeUiError(message, dashboard_ui::currentException(), title); }
}

}
