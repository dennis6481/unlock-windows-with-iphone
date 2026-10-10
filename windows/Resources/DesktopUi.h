// Created by Rui MA on 03 Oct 2026

#pragma once

#include <Windows.h>
#include <commctrl.h>
#include <stdexcept>
#include <string>
#include "resource.h"

namespace unlock_windows::desktop_ui {

inline constexpr UINT kApplyDpiAppearance = WM_APP + 130;

inline void require(BOOL value, const char* operation) {
    if (!value) throw std::runtime_error(std::string(operation) + ": Win32=" + std::to_string(GetLastError()));
}

inline void initialize() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
    require(InitCommonControlsEx(&controls), "InitCommonControlsEx(desktop UI)");
}

inline void scheduleDpiAppearance(HWND window, UINT dpi) {
    require(PostMessageW(window, kApplyDpiAppearance, dpi, 0), "PostMessageW(dialog DPI appearance)");
}

inline void centerOnActiveMonitor(HWND window) {
    MONITORINFO monitor{sizeof(monitor)};
    require(GetMonitorInfoW(MonitorFromWindow(GetForegroundWindow(), MONITOR_DEFAULTTOPRIMARY), &monitor),
        "GetMonitorInfoW(dialog placement)");
    RECT bounds{};
    require(GetWindowRect(window, &bounds), "GetWindowRect(dialog placement)");
    require(SetWindowPos(window, nullptr,
        monitor.rcWork.left + ((monitor.rcWork.right - monitor.rcWork.left) - (bounds.right - bounds.left)) / 2,
        monitor.rcWork.top + ((monitor.rcWork.bottom - monitor.rcWork.top) - (bounds.bottom - bounds.top)) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos(dialog placement)");
}

class DialogAppearance final {
public:
    ~DialogAppearance() { if (titleFont_) DeleteObject(titleFont_); }
    DialogAppearance() = default;
    DialogAppearance(const DialogAppearance&) = delete;
    DialogAppearance& operator=(const DialogAppearance&) = delete;

    void apply(HWND window, int titleId, UINT dpi = 0) {
        if (dpi == 0) dpi = GetDpiForWindow(window);
        HFONT font = CreateFontW(-MulDiv(14, static_cast<int>(dpi), 72), 0, 0, 0, FW_NORMAL,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        require(font != nullptr, "CreateFontW(dialog title)");
        SendDlgItemMessageW(window, titleId, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        if (titleFont_) DeleteObject(titleFont_);
        titleFont_ = font;
        const auto instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(window, GWLP_HINSTANCE));
        const auto big = LoadImageW(instance, MAKEINTRESOURCEW(IDI_UNLOCK_APP), IMAGE_ICON,
            GetSystemMetricsForDpi(SM_CXICON, dpi), GetSystemMetricsForDpi(SM_CYICON, dpi), LR_SHARED);
        const auto smallIcon = LoadImageW(instance, MAKEINTRESOURCEW(IDI_UNLOCK_APP), IMAGE_ICON,
            GetSystemMetricsForDpi(SM_CXSMICON, dpi), GetSystemMetricsForDpi(SM_CYSMICON, dpi), LR_SHARED);
        require(big != nullptr && smallIcon != nullptr, "LoadImageW(dialog icons)");
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(big));
        SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
    }
private:
    HFONT titleFont_ = nullptr;
};

inline INT_PTR readOnlyBackground(WPARAM dcValue) {
    const auto dc = reinterpret_cast<HDC>(dcValue);
    SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
    SetBkColor(dc, GetSysColor(COLOR_WINDOW));
    return reinterpret_cast<INT_PTR>(GetSysColorBrush(COLOR_WINDOW));
}

inline void defaultButton(HWND window, int id) {
    const auto old = static_cast<int>(LOWORD(SendMessageW(window, DM_GETDEFID, 0, 0)));
    if (old != 0) SendDlgItemMessageW(window, old, BM_SETSTYLE, BS_PUSHBUTTON, TRUE);
    SendDlgItemMessageW(window, id, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
    SendMessageW(window, DM_SETDEFID, id, 0);
    SetFocus(GetDlgItem(window, id));
}

}
