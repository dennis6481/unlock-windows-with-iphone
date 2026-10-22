// Created by Liam on 21 Oct 2026
#pragma once

#include <Windows.h>

namespace unlock_windows::saved_credential {
// The machine-wide policy is off unless a DWORD value explicitly equals one.
// Administrators must approve changes. It contains no password or device identifier.
inline constexpr wchar_t kAutomaticUnlockKey[] = L"SOFTWARE\\UnlockWindowsWithIPhone";
// Deliberately separate from the older on-resume setting. The expanded behavior
// must be explicitly opted into again rather than silently widening consent.
inline constexpr wchar_t kAutomaticUnlockValue[] = L"AutomaticUnlockAtLockScreen";

inline constexpr bool automaticUnlockEligible(bool enabled, bool locked,
    bool suspended, bool sessionArmed, bool attemptConsumed) noexcept {
    return enabled && locked && !suspended && sessionArmed && !attemptConsumed;
}

// A real display-off -> display-on transition observed after locking is the
// only event that arms an attempt; locking and power resume alone do not.
inline constexpr bool automaticDisplayWakeRearms(bool previouslyOff, bool sessionArmed) noexcept {
    return previouslyOff && sessionArmed;
}

inline bool automaticUnlockEnabled() noexcept {
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    return RegGetValueW(HKEY_LOCAL_MACHINE, kAutomaticUnlockKey, kAutomaticUnlockValue,
        RRF_RT_REG_DWORD, nullptr, &value, &bytes) == ERROR_SUCCESS &&
        bytes == sizeof(value) && value == 1;
}

inline LONG setAutomaticUnlockEnabled(bool enabled) noexcept {
    HKEY key = nullptr;
    auto code = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kAutomaticUnlockKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
    if (code != ERROR_SUCCESS) return code;
    const DWORD value = enabled ? 1u : 0u;
    code = RegSetValueExW(key, kAutomaticUnlockValue, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
    return code;
}
}
