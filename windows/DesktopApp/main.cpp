// Created by Rui MA on 05 Oct 2026

#include "DesktopApp.h"
#include "DesktopNotifications.h"
#include "../Enrollment/EnrollmentSession.h"
#include "../Enrollment/BindingClient.h"
#include "../Resources/resource.h"
#include <shellapi.h>
#include <cstdio>
#include <iostream>
#include <string>

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    using namespace unlock_windows::desktop_app;

    try {
        int argc = 0;
        struct Arguments final {
            wchar_t** value = nullptr;
            ~Arguments() { if (value) LocalFree(value); }
        } arguments;
        arguments.value = CommandLineToArgvW(GetCommandLineW(), &argc);
        unlock_windows::enrollment::require(arguments.value != nullptr, "CommandLineToArgvW");
        const auto launch = parseLaunch(argc, arguments.value);
        switch (launch.role) {
        case Role::tray:
        case Role::setup:
            if (unlock_windows::enrollment::elevatedAdmin())
                throw std::runtime_error("Start Unlock with iPhone as the ordinary console user, without administrator elevation");
            return runTray(instance, launch.role == Role::setup, launch.background);
        case Role::savedPassword:
            return runSavedPassword(instance, show, launch.setup, launch.passwordOperation);
        case Role::bindingHelper:
            return unlock_windows::enrollment::runBindingHelper(arguments.value[2], arguments.value[3]);
        }
        throw std::runtime_error("Invalid application role");
    } catch (...) {
        showStartupError(winrt::to_message().c_str(), UNLOCK_PRODUCT_DISPLAY_NAME);
        return 1;
    }
}
