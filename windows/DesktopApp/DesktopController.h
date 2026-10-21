// Created by Rui MA on 11 Oct 2026

#pragma once

#include "UI/MainWindow.h"
#include "TrayManager.h"
#include "DesktopNotifications.h"
#include <functional>
#include <memory>
#include <thread>
#include <vector>

namespace unlock_windows::desktop_app {
enum class DiagnosticSource { desktop, tray, mainWindow, password, binding, about, setup, service, serviceIpc, lastUnlock };
struct ControllerState;
struct DesktopNotice final { std::wstring message, title; NoticeSeverity severity; };
struct DesktopUpdate final {
    bool controlReady = false, stopping = false, failed = false;
    std::optional<DesktopSnapshot> snapshot;
    std::vector<DesktopNotice> notices;
};
class DesktopController final {
public:
    explicit DesktopController(std::function<bool()> wake);
    void start();
    bool command(TrayCommand command);
    void requestStop();
    DesktopUpdate takeUpdate();
    bool ended();
    void join();
    void record(DiagnosticSource source, NoticeSeverity severity, const std::wstring& message);
    std::function<void(std::wstring)> errorReporter(DiagnosticSource source, std::wstring title, bool notify = true);
private:
    std::shared_ptr<ControllerState> state_;
    std::thread thread_;
};
}
