// Created by Rui MA on 16 Oct 2026

#pragma once

#include "../../Bluetooth/SystemBleContract.h"

namespace unlock_windows::desktop_app::ui {
inline constexpr int kDistanceStep = 30;
inline constexpr int kNearThreshold = system_ble::kDefaultThreshold + kDistanceStep;
inline constexpr int kFarThreshold = system_ble::kDefaultThreshold - kDistanceStep;

/// Snap an RSSI threshold to the existing Near, Medium or Far presentation value.
inline int nearestDistanceThreshold(double value) {
    if (value >= (kNearThreshold + system_ble::kDefaultThreshold) / 2.0) return kNearThreshold;
    if (value >= (kFarThreshold + system_ble::kDefaultThreshold) / 2.0) return system_ble::kDefaultThreshold;
    return kFarThreshold;
}

/// Return the existing accessible label for a snapped threshold.
inline const wchar_t* distanceLabel(int threshold) {
    return threshold == kNearThreshold ? L"Near" : threshold == kFarThreshold ? L"Far" : L"Medium";
}
}
