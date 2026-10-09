// Created by Rui MA on 08 Oct 2026

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace unlock_windows::desktop_app {

struct DashboardSnapshot final {
    std::optional<bool> paired;
    bool busy = false;
    std::wstring status;
    std::wstring connection;
    std::wstring error;
    std::wstring diagnostics;
};

class Dashboard final {
public:
    using PairingAction = std::function<void(bool remove)>;
    using ReportError = std::function<void(std::wstring)>;
    using RefreshAction = std::function<void()>;
    using PasswordAction = std::function<void()>;

    Dashboard(PairingAction action, RefreshAction refresh, PasswordAction password, ReportError reportError);
    ~Dashboard();
    Dashboard(const Dashboard&) = delete;
    Dashboard& operator=(const Dashboard&) = delete;

    void show();
    void update(DashboardSnapshot snapshot);
    void stop();

private:
    struct State;
    std::unique_ptr<State> state_;
};

}
