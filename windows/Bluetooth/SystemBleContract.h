// Created by Rui MA on 10 Oct 2026

#pragma once

#include <cstdint>
#include <string>
#include <winrt/base.h>

namespace unlock_windows::system_ble {
inline constexpr winrt::guid kAncsService{L"7905F431-B5CE-4E99-A40F-4B1E122D00D0"};
inline constexpr winrt::guid kNotificationSource{L"9FBF120D-6301-42D9-8C58-25E699A21DBD"};
inline constexpr int kMinimumThreshold = -100;
inline constexpr int kMaximumThreshold = -20;
inline constexpr int kDefaultThreshold = -60;
inline constexpr std::uint64_t kEvidenceLifetimeMs = 3'000;
inline constexpr std::uint64_t kOperationLifetimeMs = 15'000;
inline constexpr int kThresholdStep = 1;

inline constexpr bool validThreshold(int value) noexcept {
    return value >= kMinimumThreshold && value <= kMaximumThreshold;
}

inline constexpr bool freshEvidence(std::uint64_t at, std::uint64_t started, std::uint64_t now) noexcept {
    return at != 0 && at >= started && at <= now && now - at <= kEvidenceLifetimeMs;
}

struct BindingRecord final {
    std::wstring accountSid;

    // Legacy storage/IPC layout only; not used for device selection or verification. New bindings leave this empty.
    std::wstring classicId;

    std::wstring bleId;

    // Legacy storage/IPC layout only; not used for device selection or verification. New bindings leave this zero.
    winrt::guid containerId{};

    std::wstring displayName;
    int threshold = kDefaultThreshold;
    bool operator==(const BindingRecord&) const = default;
};

enum class BindingState : std::uint8_t { absent, bound };
}
