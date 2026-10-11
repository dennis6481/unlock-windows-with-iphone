// Created by Rui MA on 11 Oct 2026

#pragma once

#include "SystemBleSession.h"

namespace unlock_windows::system_ble {
class PresenceAuthorization final {
public:
    bool consume(bool contextMatches, const Evidence& proof, std::uint64_t started,
        std::uint64_t now, std::uint64_t deadline, int threshold) noexcept {
        if (consumed_ || !contextMatches || now >= deadline || !validThreshold(threshold) ||
            proof.failure != Failure::none || !freshEvidence(proof.communicationAt, started, now) ||
            !freshEvidence(proof.rssiAt, started, now) || proof.rssi < threshold) return false;
        consumed_ = true;
        return true;
    }
private:
    bool consumed_ = false;
};
}
