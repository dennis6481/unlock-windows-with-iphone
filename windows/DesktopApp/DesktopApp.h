// Created by Rui MA on 05 Oct 2026

#pragma once

#include <Windows.h>
#include "../SavedCredential/SavedCredentialIpc.h"
#include <stdexcept>
#include <string_view>

namespace unlock_windows::desktop_app {
inline constexpr wchar_t kBluetoothRole[] = L"--bluetooth";
inline constexpr wchar_t kSavedPasswordRole[] = L"--saved-password";
inline constexpr wchar_t kSetupRole[] = L"--setup";
inline constexpr wchar_t kBackgroundRole[] = L"--background";
inline constexpr wchar_t kTrayWindowClass[] = L"UnlockWindowsWithIPhoneGattHost";
inline constexpr UINT kSetupMessage = WM_APP + 3;
inline constexpr UINT kShowDashboardMessage = WM_APP + 4;
enum class SetupResult : DWORD { cancelled = 0, error = 1, credentialReady = 2 };
inline constexpr wchar_t kKeyHexCommand[] = L"--key-hex";
inline constexpr wchar_t kKeyClipboardCommand[] = L"--key-clipboard";
inline constexpr wchar_t kClearCommand[] = L"--clear";
inline constexpr wchar_t kReplaceOption[] = L"--replace";

enum class Role { tray, setup, bluetoothEnrollment, savedPassword, manualEnrollment };
struct Launch final {
    Role role = Role::tray;
    bool clear = false;
    bool clipboard = false;
    bool replace = false;
    bool setup = false;
    bool background = false;
    saved_credential::Operation passwordOperation = saved_credential::Operation::status;
};

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
    if (command == kBackgroundRole && argc == 2) return {Role::tray, false, false, false, false, true};
    if (command == kSetupRole && argc == 2) return {Role::setup};
    if (command == kSavedPasswordRole && argc == 2) return {Role::savedPassword};
    if (command == kSavedPasswordRole && argc == 3 && std::wstring_view(argv[2]) == kSetupRole)
        return {Role::savedPassword, false, false, false, true};
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
    if (command == kBluetoothRole && argc == 9) return {Role::bluetoothEnrollment};
    if (command == kClearCommand && argc == 2) return {Role::manualEnrollment, true};
    const bool clipboard = command == kKeyClipboardCommand;
    if (clipboard || command == kKeyHexCommand) {
        const int expected = clipboard ? 2 : 3;
        if (argc == expected || (argc == expected + 1 && std::wstring_view(argv[expected]) == kReplaceOption))
            return {Role::manualEnrollment, false, clipboard, argc == expected + 1};
    }
    throw std::invalid_argument("Unknown or conflicting arguments. Use --key-hex <key> [--replace], --key-clipboard [--replace], or --clear for manual enrollment");
}

int runTray(HINSTANCE instance, bool setup = false, bool background = false);
int runSavedPassword(HINSTANCE instance, int show, bool setup = false,
    saved_credential::Operation operation = saved_credential::Operation::status);
int runEnrollment(wchar_t* argv[], const Launch& launch);
}
