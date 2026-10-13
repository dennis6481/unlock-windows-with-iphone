// Created by Rui MA on 13 Oct 2026

#include <Windows.h>
#undef GetCurrentTime
#include "PresenceAuthorization.h"
#include <chrono>
#include <thread>

namespace unlock_windows::system_ble {
PresenceEvidence presenceEvidence(const Session& session, const RssiSampler& sampler) {
    return detail::collectPresenceEvidence(session, sampler);
}

void verifyUnlockPresence(Session& session, RssiSampler& sampler, std::uint64_t started,
    std::uint64_t deadline, int threshold, const std::function<void(const std::string&)>& report) {
    detail::verifyUnlockPresence(session, sampler, started, deadline, threshold, report,
        [] { return GetTickCount64(); }, [] { std::this_thread::sleep_for(std::chrono::milliseconds(20)); });
}
}
