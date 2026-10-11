// Created by Rui MA on 11 Oct 2026

#pragma once

#include <Windows.h>
#include <wtsapi32.h>
#include <stdexcept>

namespace unlock_windows {
[[nodiscard]] inline bool consoleLocked(const void* data, DWORD bytes, DWORD session) {
    if (!data || bytes < sizeof(WTSINFOEXW))
        throw std::runtime_error("Physical console lock-state response is malformed");
    const auto& info = *static_cast<const WTSINFOEXW*>(data);
    const auto& level = info.Data.WTSInfoExLevel1;
    if (info.Level != 1 || level.SessionId != session || level.SessionState != WTSActive ||
        (level.SessionFlags != WTS_SESSIONSTATE_LOCK && level.SessionFlags != WTS_SESSIONSTATE_UNLOCK))
        throw std::runtime_error("Physical console state is not an active known lock state");
    return level.SessionFlags == WTS_SESSIONSTATE_LOCK;
}
}
