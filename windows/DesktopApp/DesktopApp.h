// Created by Rui MA on 05 Oct 2026

#pragma once

#include <Windows.h>
#include "../SavedCredential/SavedCredentialIpc.h"
#include <stdexcept>
#include <string>
#include <string_view>

namespace unlock_windows::desktop_app {
inline constexpr wchar_t kSavedPasswordRole[] = L"--saved-password";
inline constexpr wchar_t kSetupRole[] = L"--setup";
inline constexpr wchar_t kSetupCancelArgument[] = L"--cancel-event";
inline constexpr wchar_t kSetupCancelPrefix[] = L"Global\\UnlockWindowsWithIPhone-Setup-";
inline constexpr wchar_t kBackgroundRole[] = L"--background";
inline constexpr wchar_t kTrayWindowClass[] = L"UnlockWindowsWithIPhoneDesktopHost";
inline constexpr UINT kSetupMessage = WM_APP + 3;
inline constexpr UINT kShowDashboardMessage = WM_APP + 4;
enum class SetupResult : DWORD { cancelled = 0, error = 1, credentialReady = 2 };
enum class Role { tray, setup, savedPassword, bindingHelper };
struct Launch final {
    Role role = Role::tray;
    bool setup = false;
    bool background = false;
    saved_credential::Operation passwordOperation = saved_credential::Operation::status;
    std::wstring setupCancelEvent;
};

inline bool validSetupCancelEvent(std::wstring_view name) {
    const std::wstring_view prefix(kSetupCancelPrefix);
    if (!name.starts_with(prefix) || name.size() != prefix.size() + 38) return false;
    const auto suffix = name.substr(prefix.size());
    if (suffix.front() != L'{' || suffix.back() != L'}') return false;
    try { static_cast<void>(winrt::guid{suffix}); return true; }
    catch (const std::invalid_argument&) { return false; }
}

inline const wchar_t* passwordOperationArgument(saved_credential::Operation operation) {
    using saved_credential::Operation;
    switch (operation) {
    case Operation::setCredential: return L"--save";
    case Operation::updateCredential: return L"--update";
    case Operation::clearCredential: return L"--remove";
    default: throw std::invalid_argument("Invalid password management operation");
    }
}

inline Launch parseLaunch(int argc, wchar_t* const argv[]) {
    if (argc == 1) return {};
    if (argc < 1) throw std::invalid_argument("Missing application arguments");
    const std::wstring_view command(argv[1]);
    if (command == kBackgroundRole && argc == 2) return {Role::tray, false, true};
    if (command == kSetupRole && argc == 2) return {Role::setup};
    if (command == kSavedPasswordRole && argc == 2) return {Role::savedPassword};
    if (command == kSavedPasswordRole && argc == 5 && std::wstring_view(argv[2]) == kSetupRole &&
        std::wstring_view(argv[3]) == kSetupCancelArgument && validSetupCancelEvent(argv[4])) {
        Launch launch{Role::savedPassword, true};
        launch.setupCancelEvent = argv[4];
        return launch;
    }
    if (command == kSavedPasswordRole && argc == 3) {
        for (const auto operation : {saved_credential::Operation::setCredential,
                saved_credential::Operation::updateCredential, saved_credential::Operation::clearCredential}) {
            if (std::wstring_view(argv[2]) == passwordOperationArgument(operation)) {
                Launch launch{Role::savedPassword};
                launch.passwordOperation = operation;
                return launch;
            }
        }
    }
    if (command == L"--binding-helper" && argc == 4) return {Role::bindingHelper};
    throw std::invalid_argument("Unknown or conflicting application arguments");
}

int runTray(HINSTANCE instance, bool setup = false, bool background = false);
int runSavedPassword(HINSTANCE instance, int show, bool setup = false,
    saved_credential::Operation operation = saved_credential::Operation::status,
    const std::wstring& setupCancelEvent = {});
}
