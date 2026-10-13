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
    if (proof.communication.revision != proof.target.revision) return Failure::evidenceExpired;
    return communication;
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
