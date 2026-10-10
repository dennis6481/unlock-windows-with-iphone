// Created by Rui MA on 10 Oct 2026

#pragma once

#include <functional>
#include <memory>
#include <string>

namespace unlock_windows::desktop_app {

enum class NoticeSeverity { information, warning, error };

class DesktopNotifications final {
public:
    explicit DesktopNotifications(std::function<void()> drained);
    ~DesktopNotifications();
    DesktopNotifications(const DesktopNotifications&) = delete;
    DesktopNotifications& operator=(const DesktopNotifications&) = delete;
    void show(std::wstring message, std::wstring title, NoticeSeverity severity);
    bool empty() const;
    void stop();

private:
    struct State;
    std::shared_ptr<State> state_;
};

void showStartupError(const std::wstring& message, const std::wstring& title);
void showNativeUiError(const std::wstring& message, const std::wstring& uiError,
    const std::wstring& title);

}
