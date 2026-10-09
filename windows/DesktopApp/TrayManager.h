// Created by Rui MA on 08 Oct 2026

#pragma once

#include <Windows.h>
#include <shellapi.h>
#include <functional>
#include <optional>
#include <string>

namespace unlock_windows::desktop_app {

enum class TrayCommand {
    showWindow,
    status,
    password,
    about,
    continueSetup,
    pairPhone,
    removePhone,
    quit,
};

class TrayManager final {
public:
    using CommandHandler = std::function<void(TrayCommand)>;
    using Report = std::function<void(const std::wstring&, bool error)>;

    TrayManager(CommandHandler command, Report report);
    ~TrayManager();
    TrayManager(const TrayManager&) = delete;
    TrayManager& operator=(const TrayManager&) = delete;

    void loadIcon(HINSTANCE instance);
    HICON icon() const;
    void bind(HWND window, std::wstring tooltip);
    void update(std::wstring tooltip);
    void retryRegistration();
    std::optional<LRESULT> handleMessage(UINT message, WPARAM wparam, LPARAM lparam);
    void stop();
    void releaseIcon();

private:
    NOTIFYICONDATAW data() const;
    void add();
    void menu();

    CommandHandler command_;
    Report report_;
    HWND window_ = nullptr;
    HICON icon_ = nullptr;
    UINT taskbarCreated_ = 0;
    bool added_ = false;
    bool unavailable_ = false;
    std::wstring tooltip_;
};

}
