// Created by Liam on 21 Oct 2026
#pragma once

#include <Windows.h>
#include <atomic>

namespace unlock_windows::saved_credential {
// The machine-wide policy is off unless a DWORD value explicitly equals one.
// Administrators must approve changes. It contains no password or device identifier.
inline constexpr wchar_t kAutomaticUnlockKey[] = L"SOFTWARE\\UnlockWindowsWithIPhone";
// Deliberately separate from the older on-resume setting. The expanded behavior
// must be explicitly opted into again rather than silently widening consent.
inline constexpr wchar_t kAutomaticUnlockValue[] = L"AutomaticUnlockAtLockScreen";

enum class AutomaticUnlockEvent {
    lock, reset, displayOff, displayOn, suspend, backgroundResume, userResume
};

// Service callbacks and IPC share one wake ticket. Lock notifications may arrive
// after display-off or resume; only reset/consumption discards a pending wake.
class AutomaticUnlockState {
public:
    void observe(AutomaticUnlockEvent event) {
        auto current = state_.load();
        unsigned next;
        do {
            next = current;
            switch (event) {
            case AutomaticUnlockEvent::lock:
                next |= locked;
                break;
            case AutomaticUnlockEvent::reset:
                next &= suspended;
                break;
            case AutomaticUnlockEvent::displayOff:
                next = (next | displayOff) & ~wakePending;
                break;
            case AutomaticUnlockEvent::displayOn:
                if ((next & displayOff) && (next & (locked | sleepPending))) {
                    next = (next | wakePending) & ~sleepPending;
                }
                next &= ~displayOff;
                break;
            case AutomaticUnlockEvent::suspend:
                next = (next | suspended | sleepPending) & ~wakePending;
                break;
            case AutomaticUnlockEvent::backgroundResume:
                next &= ~suspended;
                break;
            case AutomaticUnlockEvent::userResume:
                next &= ~suspended;
                if (next & sleepPending) {
                    next = (next | wakePending) & ~(sleepPending | displayOff);
                }
                break;
            }
        } while (!state_.compare_exchange_weak(current, next));
    }

    bool eligible(bool enabled, bool consoleLocked) const {
        return eligibleState(state_.load(), enabled, consoleLocked);
    }

    bool consume(bool automatic, bool enabled, bool consoleLocked) {
        // A delayed display-on/user-resume notification from this cycle must not
        // re-arm a completed manual or automatic attempt.
        auto current = state_.load();
        unsigned next;
        do {
            if (automatic && !eligibleState(current, enabled, consoleLocked)) return false;
            next = current & ~(wakePending | sleepPending | displayOff);
        } while (!state_.compare_exchange_weak(current, next));
        return true;
    }

private:
    static constexpr unsigned locked = 1u, suspended = 2u, displayOff = 4u,
        sleepPending = 8u, wakePending = 16u;
    static bool eligibleState(unsigned state, bool enabled, bool consoleLocked) {
        return enabled && consoleLocked && (state & locked) &&
            !(state & suspended) && (state & wakePending);
    }
    static_assert(std::atomic<unsigned>::is_always_lock_free);
    std::atomic<unsigned> state_{0};
};

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
