// Created by Rui MA on 09 Oct 2026

#pragma once

#include "../DesktopApp/Dashboard/Dashboard.h"
#include "../DesktopApp/TrayManager.h"
#include "../DesktopApp/DesktopNotifications.h"
#include <functional>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

namespace unlock_windows::desktop_app {

inline constexpr wchar_t kComputerIdentityRegistryPath[] = L"Software\\UnlockWindowsWithIPhone\\GattHost";

struct CallbackState;

struct GattNotice final {
    std::wstring message;
    std::wstring title;
    NoticeSeverity severity = NoticeSeverity::information;
};

struct GattUpdate final {
    bool controlReady = false;
    bool stopping = false;
    bool failed = false;
    std::optional<DashboardSnapshot> snapshot;
    std::vector<GattNotice> notices;
};

class GattController final {
public:
    explicit GattController(std::function<bool()> wake);
    void start(HINSTANCE instance);
    bool command(TrayCommand command);
    void requestStop();
    GattUpdate takeUpdate();
    bool ended();
    void join();
    void record(const std::wstring& message);
    std::function<void(std::wstring)> errorReporter(std::wstring title, bool notify = true);

private:
    std::shared_ptr<CallbackState> state_;
    std::thread thread_;
};

}
