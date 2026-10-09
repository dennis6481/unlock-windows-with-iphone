// Created by Rui MA on 05 Oct 2026

#include "DesktopApp.h"
#include "../Enrollment/EnrollmentSession.h"
#include "../Resources/resource.h"
#include <shellapi.h>
#include <cstdio>
#include <iostream>
#include <string>

namespace {
void attachManualConsole() {
    unlock_windows::enrollment::require(AttachConsole(ATTACH_PARENT_PROCESS), "AttachConsole(manual enrollment)");
    FILE* stream = nullptr;
    if (_wfreopen_s(&stream, L"CONIN$", L"r", stdin) != 0 ||
        _wfreopen_s(&stream, L"CONOUT$", L"w", stdout) != 0 ||
        _wfreopen_s(&stream, L"CONOUT$", L"w", stderr) != 0)
        throw std::runtime_error("Could not connect manual enrollment console streams");
    std::cin.clear();
    std::cout.clear();
    std::cerr.clear();
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    using namespace unlock_windows::desktop_app;
    bool manual = false;
    try {
        int argc = 0;
        struct Arguments final {
            wchar_t** value = nullptr;
            ~Arguments() { if (value) LocalFree(value); }
        } arguments;
        arguments.value = CommandLineToArgvW(GetCommandLineW(), &argc);
        unlock_windows::enrollment::require(arguments.value != nullptr, "CommandLineToArgvW");
        const auto launch = parseLaunch(argc, arguments.value);
        manual = launch.role == Role::manualEnrollment;
        if (manual) attachManualConsole();
        switch (launch.role) {
        case Role::tray:
        case Role::setup:
            if (unlock_windows::enrollment::elevatedAdmin())
                throw std::runtime_error("Start Unlock with iPhone as the ordinary console user, without administrator elevation");
            return runTray(instance, launch.role == Role::setup, launch.background);
        case Role::savedPassword:
            return runSavedPassword(instance, show, launch.setup);
        case Role::bluetoothEnrollment:
        case Role::manualEnrollment:
            return runEnrollment(arguments.value, launch);
        }
        throw std::runtime_error("Invalid application role");
    } catch (const std::exception& error) {
        if (manual) std::cerr << "[Unlock with iPhone] " << error.what() << '\n';
        const std::string text(error.what());
        MessageBoxW(nullptr, std::wstring(text.begin(), text.end()).c_str(),
            UNLOCK_PRODUCT_DISPLAY_NAME, MB_OK | MB_ICONERROR);
        return 1;
    }
}
