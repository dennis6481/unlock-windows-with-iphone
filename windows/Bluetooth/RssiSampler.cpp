// Created by Rui MA on 13 Oct 2026

#include <Windows.h>
#undef GetCurrentTime
#include "RssiSampler.h"
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <winrt/Windows.Foundation.h>
#include <chrono>
#include <mutex>

namespace unlock_windows::system_ble {
using namespace winrt;
using namespace Windows::Devices::Bluetooth::Advertisement;

struct RssiSampler::State final {
    mutable std::mutex mutex;
    detail::RssiSamples samples;
    BluetoothLEAdvertisementWatcher watcher{nullptr};
    BluetoothLEAdvertisementWatcher::Received_revoker received;
    BluetoothLEAdvertisementWatcher::Stopped_revoker stopped;
    State(ConnectionTarget target, std::uint64_t started) : samples(std::move(target), started) {}
};

void RssiSampler::start(ConnectionTarget target, std::uint64_t started) {
    if (state_) throw VerificationError(Failure::internalError, "RSSI sampler already started");
    state_ = std::make_shared<State>(std::move(target), started);
    const std::weak_ptr<State> weak = state_;
    try {
        state_->watcher = BluetoothLEAdvertisementWatcher();
        state_->received = state_->watcher.Received(auto_revoke, [weak](const auto&, const BluetoothLEAdvertisementReceivedEventArgs& args) {
            if (const auto self = weak.lock()) {
                try {
                    const auto now = GetTickCount64();
                    const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(winrt::clock::now() - args.Timestamp()).count();
                    if (age < 0 || static_cast<std::uint64_t>(age) > kEvidenceLifetimeMs || static_cast<std::uint64_t>(age) > now) return;
                    const auto address = args.BluetoothAddress();
                    const auto type = args.BluetoothAddressType();
                    const auto rssi = args.RawSignalStrengthInDBm();
                    std::lock_guard lock(self->mutex);
                    self->samples.record(address, type, now - static_cast<std::uint64_t>(age), rssi, now);
                } catch (...) {
                    std::lock_guard lock(self->mutex);
                    self->samples.fail();
                }
            }
        });
        state_->stopped = state_->watcher.Stopped(auto_revoke, [weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) {
                std::lock_guard lock(self->mutex);
                self->samples.fail();
            }
        });
        state_->watcher.Start();
    } catch (...) {
        std::lock_guard lock(state_->mutex);
        state_->samples.fail();
        throw VerificationError(Failure::rssiUnavailable, "RSSI advertisement watcher start failed");
    }
}

void RssiSampler::updateTarget(ConnectionTarget target) {
    if (!state_) throw VerificationError(Failure::cancelled, "RSSI sampler is not active");
    std::lock_guard lock(state_->mutex);
    state_->samples.updateTarget(std::move(target), GetTickCount64());
}

RssiEvidence RssiSampler::evidence(const ConnectionTarget& current) const {
    if (!state_) return {Failure::cancelled};
    std::lock_guard lock(state_->mutex);
    return state_->samples.evidence(current);
}

void RssiSampler::stop() {
    if (!state_) return;
    const auto state = std::move(state_);
    { std::lock_guard lock(state->mutex); state->samples.stop(); }
    state->received.revoke();
    state->stopped.revoke();
    if (state->watcher) state->watcher.Stop();
}

RssiSampler::~RssiSampler() {
    try { stop(); }
    catch (...) { OutputDebugStringW(L"RSSI sampler cleanup failed\n"); }
}
}
