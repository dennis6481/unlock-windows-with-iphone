// Created by Rui MA on 05 Oct 2026

#pragma once

#include <Windows.h>
#include <stdexcept>
#include <string_view>

namespace unlock_windows::desktop_app {
inline constexpr wchar_t kBluetoothRole[] = L"--bluetooth";
inline constexpr wchar_t kSavedPasswordRole[] = L"--saved-password";
inline constexpr wchar_t kKeyHexCommand[] = L"--key-hex";
inline constexpr wchar_t kKeyClipboardCommand[] = L"--key-clipboard";
inline constexpr wchar_t kClearCommand[] = L"--clear";
inline constexpr wchar_t kReplaceOption[] = L"--replace";

enum class Role { tray, bluetoothEnrollment, savedPassword, manualEnrollment };
struct Launch final {
    Role role = Role::tray;
    bool clear = false;
    bool clipboard = false;
    bool replace = false;
};

inline Launch parseLaunch(int argc, wchar_t* const argv[]) {
    if (argc == 1) return {};
    if (argc < 1) throw std::invalid_argument("Missing application arguments");
    const std::wstring_view command(argv[1]);
    if (command == kSavedPasswordRole && argc == 2) return {Role::savedPassword};
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

int runTray(HINSTANCE instance);
int runSavedPassword(HINSTANCE instance, int show);
int runEnrollment(wchar_t* argv[], const Launch& launch);
}
