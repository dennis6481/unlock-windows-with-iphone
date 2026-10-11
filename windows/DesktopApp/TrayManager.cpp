// Created by Rui MA on 08 Oct 2026

#include "TrayManager.h"
#include "../Resources/DesktopUi.h"

#include <utility>

namespace unlock_windows::desktop_app {
namespace {
constexpr UINT kTray = WM_APP + 2;
}

TrayManager::TrayManager(CommandHandler command, Report report)
    : command_(std::move(command)), report_(std::move(report)) {}

TrayManager::~TrayManager() {
    stop();
    releaseIcon();
}

void TrayManager::loadIcon(HINSTANCE instance) {
    icon_ = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_UNLOCK_APP), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR));
    desktop_ui::require(icon_ != nullptr, "LoadImageW(tray icon)");
}

HICON TrayManager::icon() const { return icon_; }

void TrayManager::bind(HWND window, std::wstring tooltip) {
    window_ = window;
    tooltip_ = std::move(tooltip);
    taskbarCreated_ = RegisterWindowMessageW(L"TaskbarCreated");
    desktop_ui::require(taskbarCreated_ != 0, "RegisterWindowMessageW");
    add();
}

NOTIFYICONDATAW TrayManager::data() const {
    NOTIFYICONDATAW result{};
    result.cbSize = sizeof(result);
    result.hWnd = window_;
    result.uID = 1;
    result.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    result.uCallbackMessage = kTray;
    result.hIcon = icon_;
    wcsncpy_s(result.szTip, tooltip_.c_str(), _TRUNCATE);
    return result;
}

void TrayManager::add() {
    auto notification = data();
    if (!Shell_NotifyIconW(NIM_ADD, &notification)) {
        added_ = false;
        if (!unavailable_) report_(L"Shell_NotifyIconW(NIM_ADD) failed; waiting for the taskbar and retrying.", true);
        unavailable_ = true;
        return;
    }
    added_ = true;
    if (unavailable_) report_(L"Taskbar is ready; tray icon registered.", false);
    unavailable_ = false;
}

void TrayManager::update(std::wstring tooltip) {
    tooltip_ = std::move(tooltip);
    if (!added_) return;
    auto notification = data();
    if (!Shell_NotifyIconW(NIM_MODIFY, &notification)) {
        added_ = false;
        unavailable_ = true;
        report_(L"Shell_NotifyIconW(NIM_MODIFY) failed; tray registration will be retried.", true);
    }
}

void TrayManager::retryRegistration() {
    if (window_ && !added_) add();
}

std::optional<LRESULT> TrayManager::handleMessage(UINT message, WPARAM, LPARAM lparam) {
    if (!window_) return std::nullopt;
    if (taskbarCreated_ && message == taskbarCreated_) {
        added_ = false;
        add();
        return 0;
    }
    if (message != kTray) return std::nullopt;
    if (lparam == WM_RBUTTONUP) menu();
    else if (lparam == WM_LBUTTONUP) command_(TrayCommand::showWindow);
    return 0;
}

void TrayManager::menu() {
    UINT selected = 0;
    {
        const auto popup = CreatePopupMenu();
        desktop_ui::require(popup != nullptr, "CreatePopupMenu");
        struct MenuHandle final {
            HMENU value;
            const Report& report;
            ~MenuHandle() {
                if (!DestroyMenu(value)) report(L"DestroyMenu failed; Win32=" + std::to_wstring(GetLastError()), true);
            }
        } handle{popup, report_};
        const auto append = [popup](TrayCommand command, const wchar_t* label, UINT flags = 0) {
            desktop_ui::require(AppendMenuW(popup, MF_STRING | flags, static_cast<UINT>(command) + 1, label), "AppendMenuW");
        };
        append(TrayCommand::status, L"Status\u2026");
        append(TrayCommand::password, L"Password\u2026");
        append(TrayCommand::about, L"About\u2026");
        desktop_ui::require(AppendMenuW(popup, MF_SEPARATOR, 0, nullptr), "AppendMenuW");
        append(TrayCommand::quit, L"Quit");
        POINT point{};
        desktop_ui::require(GetCursorPos(&point), "GetCursorPos");
        SetForegroundWindow(window_);
        selected = TrackPopupMenu(popup, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
            point.x, point.y, 0, window_, nullptr);
    }
    if (!window_) return;
    desktop_ui::require(PostMessageW(window_, WM_NULL, 0, 0), "PostMessageW(WM_NULL)");
    if (selected) command_(static_cast<TrayCommand>(selected - 1));
}

void TrayManager::stop() {
    if (added_) {
        auto notification = data();
        if (!Shell_NotifyIconW(NIM_DELETE, &notification)) report_(L"Shell_NotifyIconW(NIM_DELETE) failed", true);
    }
    added_ = false;
    window_ = nullptr;
}

void TrayManager::releaseIcon() {
    if (!icon_) return;
    if (!DestroyIcon(icon_)) report_(L"DestroyIcon failed; Win32=" + std::to_wstring(GetLastError()), true);
    icon_ = nullptr;
}

}
