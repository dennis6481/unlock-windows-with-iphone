// Created by Rui MA on 08 Oct 2026

#pragma once

#include <functional>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace unlock_windows::desktop_app {

enum class DashboardPage { status, password, diagnostics, about };

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

    Dashboard(PairingAction action, RefreshAction refresh, ReportError reportError, ReportError passwordReport);
    ~Dashboard();
    Dashboard(const Dashboard&) = delete;
    Dashboard& operator=(const Dashboard&) = delete;

    void show(std::optional<DashboardPage> page = std::nullopt);
    void update(DashboardSnapshot snapshot);
    void stop();

private:
    struct State;
    std::unique_ptr<State> state_;
};

}
