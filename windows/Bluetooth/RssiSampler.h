// Created by Rui MA on 13 Oct 2026

#pragma once

#include "SystemBleSession.h"

namespace unlock_windows::system_ble {
struct RssiEvidence final {
    Failure failure = Failure::none;
    std::uint64_t started = 0, sampledAt = 0;
    int rssi = -127;
    ConnectionTarget target;
};

namespace detail {
// Request-local sample storage. The sampler serializes access with its mutex.
class RssiSamples final {
public:
    RssiSamples(ConnectionTarget target, std::uint64_t started)
        : proof_{Failure::none, started, 0, -127, std::move(target)}, targetSince_(started) {}
    void updateTarget(ConnectionTarget target, std::uint64_t now) {
        if (proof_.target == target) return;
        proof_.target = std::move(target);
        proof_.sampledAt = 0;
        proof_.rssi = -127;
        targetSince_ = now;
    }
    void record(std::uint64_t address, winrt::Windows::Devices::Bluetooth::BluetoothAddressType type,
        std::uint64_t sampledAt, int rssi, std::uint64_t now) noexcept {
        if (!active_ || proof_.failure != Failure::none || !proof_.target.address ||
            address != proof_.target.address || type != proof_.target.addressType ||
            sampledAt < targetSince_ || !freshEvidence(sampledAt, proof_.started, now) ||
            sampledAt < proof_.sampledAt || rssi < -127 || rssi >= 0) return;
        proof_.sampledAt = sampledAt;
        proof_.rssi = rssi;
    }
    void fail() noexcept { if (active_) proof_.failure = Failure::rssiUnavailable; }
    void stop() noexcept {
        active_ = false;
        proof_.failure = Failure::cancelled;
        proof_.sampledAt = 0;
        proof_.rssi = -127;
    }
    RssiEvidence evidence(const ConnectionTarget& current) const {
        auto result = proof_;
        if (result.failure == Failure::none && result.target != current) {
            result.sampledAt = 0;
            result.rssi = -127;
        }
        return result;
    }
private:
    RssiEvidence proof_;
    std::uint64_t targetSince_;
    bool active_ = true;
};
}

class RssiSampler final {
public:
    RssiSampler() = default;
    ~RssiSampler();
    RssiSampler(const RssiSampler&) = delete;
    RssiSampler& operator=(const RssiSampler&) = delete;
    void start(ConnectionTarget target, std::uint64_t started);
    void updateTarget(ConnectionTarget target);
    RssiEvidence evidence(const ConnectionTarget& current) const;
    void stop();
private:
    struct State;
    std::shared_ptr<State> state_;
};
}
