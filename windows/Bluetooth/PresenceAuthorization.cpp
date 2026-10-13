// Created by Rui MA on 13 Oct 2026

#include <Windows.h>
#undef GetCurrentTime
#include "PresenceAuthorization.h"
#include <chrono>
#include <thread>

namespace unlock_windows::system_ble {
PresenceEvidence presenceEvidence(const Session& session, const RssiSampler& sampler) {
    const auto communication = session.evidence();
    const auto target = session.target();
    return {communication, sampler.evidence(target), target};
}

void verifyUnlockPresence(Session& session, RssiSampler& sampler, std::uint64_t started,
    std::uint64_t deadline, int threshold, const std::function<void(const std::string&)>& report) {
    const auto log = [&](const std::string& message) { if (report) report(message); };
    log("Verify unlock presence; threshold=" + std::to_string(threshold) + " dBm");
    session.connect();
    sampler.start(session.target(), started);
    session.verifyCommunication();
    bool waiting = false;
    for (;;) {
        session.refresh();
        sampler.updateTarget(session.target());
        const auto proof = presenceEvidence(session, sampler);
        const auto now = GetTickCount64();
        const auto failure = presenceFailure(proof, started, now, deadline, threshold);
        if (failure == Failure::none) {
            if (waiting) log("END waiting for request-fresh RSSI");
            log("Evidence RSSI=" + std::to_string(proof.proximity.rssi) + " dBm; rssiAgeMs=" +
                std::to_string(now - proof.proximity.sampledAt) + "; failure=0");
            return;
        }
        if (failure == Failure::rssiTooLow)
            log("Fresh RSSI=" + std::to_string(proof.proximity.rssi) + " dBm below threshold=" + std::to_string(threshold));
        if (proof.proximity.failure != Failure::none ||
            (failure != Failure::rssiUnavailable && failure != Failure::evidenceExpired))
            throw VerificationError(failure, "Unlock presence evidence rejected");
        if (rssiFailure(proof.proximity, proof.target, started, now, threshold) == Failure::none &&
            communicationFailure(proof.communication, started, now) == Failure::evidenceExpired) {
            log("RSSI available; renew expired protected communication evidence");
            session.verifyCommunication();
            continue;
        }
        if (!waiting) { log("BEGIN waiting for request-fresh RSSI within original deadline"); waiting = true; }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}
}
