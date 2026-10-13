// Created by Rui MA on 11 Oct 2026

#pragma once

#include "RssiSampler.h"

namespace unlock_windows::system_ble {
struct PresenceEvidence final {
    CommunicationEvidence communication;
    RssiEvidence proximity;
    ConnectionTarget target;
};

inline Failure rssiFailure(const RssiEvidence& proof, const ConnectionTarget& target, std::uint64_t started,
    std::uint64_t now, int threshold) noexcept {
    if (!validThreshold(threshold)) return Failure::internalError;
    if (proof.failure != Failure::none) return proof.failure;
    if (proof.started != started || target.endpointId.empty() || !target.address || proof.target != target)
        return Failure::rssiUnavailable;
    if (!freshEvidence(proof.sampledAt, started, now))
        return proof.sampledAt ? Failure::evidenceExpired : Failure::rssiUnavailable;
    return proof.rssi < threshold ? Failure::rssiTooLow : Failure::none;
}

inline Failure presenceFailure(const PresenceEvidence& proof, std::uint64_t started, std::uint64_t now,
    std::uint64_t deadline, int threshold) noexcept {
    if (now >= deadline) return Failure::expired;
    const auto communication = communicationFailure(proof.communication, started, now);
    if (communication != Failure::none && communication != Failure::evidenceExpired) return communication;
    const auto proximity = rssiFailure(proof.proximity, proof.target, started, now, threshold);
    if (proximity != Failure::none) return proximity;
    if (proof.communication.revision != proof.target.revision) return Failure::rssiUnavailable;
    return communication;
}

namespace detail {
template<class SessionType, class SamplerType>
PresenceEvidence collectPresenceEvidence(const SessionType& session, const SamplerType& sampler) {
    const auto target = session.target();
    const auto proximity = sampler.evidence(target);
    return {session.evidence(target), proximity, target};
}

template<class SessionType, class SamplerType, class Clock, class Wait>
void verifyUnlockPresence(SessionType& session, SamplerType& sampler, std::uint64_t started,
    std::uint64_t deadline, int threshold, const std::function<void(const std::string&)>& report,
    Clock clock, Wait wait) {
    const auto log = [&](const std::string& message) { if (report) report(message); };
    log("Verify unlock presence; threshold=" + std::to_string(threshold) + " dBm");
    session.connect();
    sampler.start(session.target(), started);
    session.verifyCommunication();
    bool waiting = false;
    for (;;) {
        session.refresh();
        sampler.updateTarget(session.target());
        const auto proof = collectPresenceEvidence(session, sampler);
        const auto now = clock();
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
        wait();
    }
}
}

PresenceEvidence presenceEvidence(const Session& session, const RssiSampler& sampler);
void verifyUnlockPresence(Session& session, RssiSampler& sampler, std::uint64_t started,
    std::uint64_t deadline, int threshold, const std::function<void(const std::string&)>& report = {});

class PresenceAuthorization final {
public:
    bool consume(bool contextMatches, const PresenceEvidence& proof, std::uint64_t started,
        std::uint64_t now, std::uint64_t deadline, int threshold) noexcept {
        if (consumed_ || !contextMatches || presenceFailure(proof, started, now, deadline, threshold) != Failure::none) return false;
        consumed_ = true;
        return true;
    }
private:
    bool consumed_ = false;
};
}
