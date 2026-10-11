// Created by Rui MA on 11 Oct 2026

#include <Windows.h>
#undef GetCurrentTime
#include "SystemBleSession.h"
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.Streams.h>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>

namespace unlock_windows::system_ble {
using namespace winrt;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::Advertisement;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Foundation;

std::optional<guid> containerId(const DeviceInformation& item) {
    auto properties = item.Properties();
    if (!properties.HasKey(kContainerProperty)) return std::nullopt;
    auto value = properties.Lookup(kContainerProperty).try_as<IPropertyValue>();
    if (!value || value.Type() != PropertyType::Guid) return std::nullopt;
    auto id = value.GetGuid();
    return id == guid{} ? std::nullopt : std::optional<guid>{id};
}

hstring deviceSelector(bool ble) {
    return ble ? BluetoothLEDevice::GetDeviceSelectorFromPairingState(true) : BluetoothDevice::GetDeviceSelectorFromPairingState(true);
}

IAsyncOperation<DeviceInformationCollection> pairedEndpoints(bool ble) {
    return DeviceInformation::FindAllAsync(deviceSelector(ble), single_threaded_vector<hstring>({kContainerProperty}),
        DeviceInformationKind::AssociationEndpoint);
}

DeviceInformation uniqueEndpoint(const DeviceInformationCollection& items, const guid& target) {
    DeviceInformation selected{nullptr};
    for (const auto& item : items) {
        if (containerId(item) != std::optional<guid>{target}) continue;
        if (selected) throw VerificationError(Failure::associationInvalid, "Ambiguous system container");
        selected = item;
    }
    if (!selected) throw VerificationError(Failure::associationInvalid, "Missing paired system endpoint");
    return selected;
}

struct Session::State final : std::enable_shared_from_this<State> {
    BindingRecord binding;
    std::uint64_t started, deadline;
    std::function<bool()> valid;
    std::function<void(const std::string&)> reporter;
    mutable std::mutex mutex;
    Evidence proof;
    const char* failureDetail = "BLE evidence invalidated";
    std::uint64_t revision = 0, address = 0;
    BluetoothAddressType addressType{};
    bool discovering = true, connected = false, closing = false;
    BluetoothLEDevice device{nullptr};
    GattSession session{nullptr};
    GattDeviceService service{nullptr};
    GattCharacteristic source{nullptr};
    bool subscribed = false;
    BluetoothLEAdvertisementWatcher advertisements{nullptr};
    BluetoothLEDevice::ConnectionStatusChanged_revoker connection;
    BluetoothLEDevice::GattServicesChanged_revoker services;
    BluetoothLEAdvertisementWatcher::Received_revoker received;
    BluetoothLEAdvertisementWatcher::Stopped_revoker stopped;
    struct RelationWatch final {
        DeviceWatcher watcher{nullptr};
        DeviceWatcher::Added_revoker added;
        DeviceWatcher::Updated_revoker updated;
        DeviceWatcher::Removed_revoker removed;
        DeviceWatcher::EnumerationCompleted_revoker completed;
        DeviceWatcher::Stopped_revoker stopped;
        std::atomic<bool> ready{false};
        std::atomic<unsigned> addedCount{0};
    } classicWatch, bleWatch;

    State(BindingRecord value, std::uint64_t at, std::function<bool()> predicate,
        std::function<void(const std::string&)> report)
        : binding(std::move(value)), started(at), deadline(at + kOperationLifetimeMs), valid(std::move(predicate)),
          reporter(std::move(report)) {}

    void report(const std::string& message) const {
        if (reporter) reporter(message);
    }

    void invalidate(Failure reason, const char* detail = "BLE evidence invalidated") {
        std::lock_guard lock(mutex);
        if (!closing && proof.failure == Failure::none) { proof.failure = reason; failureDetail = detail; }
    }

    void check(const char* operation = "BLE evidence validation") const {
        if (!valid()) throw VerificationError(Failure::cancelled, "Request invalidated");
        if (GetTickCount64() >= deadline)
            throw VerificationError(Failure::expired, (std::string("BLE deadline exceeded during ") + operation).c_str());
        std::lock_guard lock(mutex);
        if (proof.failure != Failure::none) throw VerificationError(proof.failure, failureDetail);
    }

    template<class Operation> auto await(Operation operation, const char* name) {
        const auto at = GetTickCount64();
        report(std::string("BEGIN ") + name);
        bool cancelled = false;
        while (operation.Status() == AsyncStatus::Started) {
            if (!cancelled) {
                try { check(name); }
                catch (...) {
                    cancelled = true;
                    try { operation.Cancel(); }
                    catch (...) { OutputDebugStringW(L"BLE operation cancellation failed; waiting for the pending operation to end\n"); }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        check(name);
        auto result = operation.GetResults();
        report(std::string("END ") + name + " elapsedMs=" + std::to_string(GetTickCount64() - at));
        return result;
    }

    template<class Result> void gatt(const Result& result) {
        check();
        report("GATT status=" + std::to_string(static_cast<int>(result.Status())) +
            "; ATT=" + (result.ProtocolError() ? std::to_string(result.ProtocolError().Value()) : "none"));
        if (result.Status() != GattCommunicationStatus::Success)
            throw VerificationError(Failure::protectedOperationFailed,
                ("GATT communication failed: status=" + std::to_string(static_cast<int>(result.Status())) +
                 "; ATT=" + (result.ProtocolError() ? std::to_string(result.ProtocolError().Value()) : "none")).c_str());
    }

    void watchRelation(RelationWatch& watch, bool ble) {
        const std::weak_ptr<State> weak = shared_from_this();
        const auto selector = deviceSelector(ble);
        report(std::string("BEGIN ") + (ble ? "BLE" : "Classic") + " paired watcher; AQS=" + winrt::to_string(selector));
        watch.watcher = DeviceInformation::CreateWatcher(selector, single_threaded_vector<hstring>({kContainerProperty,
            L"System.Devices.Aep.IsPaired"}),
            DeviceInformationKind::AssociationEndpoint);
        auto* ready = &watch.ready;
        auto* count = &watch.addedCount;
        watch.added = watch.watcher.Added(auto_revoke, [weak, ready, count](const auto&, const DeviceInformation& item) {
            if (const auto self = weak.lock()) {
                ++*count;
                try {
                    if (*ready && containerId(item) == std::optional<guid>{self->binding.containerId})
                        self->invalidate(Failure::associationInvalid, "DeviceWatcher Added: another endpoint reported the binding ContainerId after enumeration");
                } catch (...) { self->invalidate(Failure::associationInvalid, "DeviceWatcher Added: reading ContainerId failed"); }
            }
        });
        auto changed = [weak](const auto&, const DeviceInformationUpdate& item) {
            if (const auto self = weak.lock()) {
                try {
                    if (item.Id() == self->binding.classicId || item.Id() == self->binding.bleId) {
                        if (item.Properties().HasKey(kContainerProperty)) {
                            auto value = item.Properties().Lookup(kContainerProperty).try_as<IPropertyValue>();
                            if (!value || value.Type() != PropertyType::Guid || value.GetGuid() != self->binding.containerId)
                                self->invalidate(Failure::associationInvalid, "DeviceWatcher Updated: bound endpoint ContainerId changed or invalid");
                        }
                        if (item.Properties().HasKey(L"System.Devices.Aep.IsPaired")) {
                            auto value = item.Properties().Lookup(L"System.Devices.Aep.IsPaired").try_as<IPropertyValue>();
                            if (!value || value.Type() != PropertyType::Boolean || !value.GetBoolean())
                                self->invalidate(Failure::associationInvalid, "DeviceWatcher Updated: bound endpoint no longer paired or IsPaired invalid");
                        }
                    } else if (item.Properties().HasKey(kContainerProperty)) {
                        auto value = item.Properties().Lookup(kContainerProperty).try_as<IPropertyValue>();
                        if (value && value.Type() == PropertyType::Guid && value.GetGuid() == self->binding.containerId)
                            self->invalidate(Failure::associationInvalid, "DeviceWatcher Updated: another endpoint reported the binding ContainerId");
                    }
                } catch (...) { self->invalidate(Failure::associationInvalid, "DeviceWatcher Updated: reading association properties failed"); }
            }
        };
        watch.updated = watch.watcher.Updated(auto_revoke, changed);
        watch.removed = watch.watcher.Removed(auto_revoke, [weak](const auto&, const DeviceInformationUpdate& item) {
            if (const auto self = weak.lock(); self &&
                (item.Id() == self->binding.classicId || item.Id() == self->binding.bleId)) self->invalidate(Failure::associationInvalid, "DeviceWatcher Removed: bound endpoint removed");
        });
        watch.completed = watch.watcher.EnumerationCompleted(auto_revoke, [weak, ready](const auto&, const auto&) {
            if (const auto self = weak.lock()) *ready = true;
        });
        watch.stopped = watch.watcher.Stopped(auto_revoke, [weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) self->invalidate(Failure::associationInvalid, "DeviceWatcher Stopped: system association monitoring stopped");
        });
        watch.watcher.Start();
    }

    void currentAddress() {
        const auto current = device.BluetoothAddress();
        const auto type = device.BluetoothAddressType();
        std::lock_guard lock(mutex);
        if (address != current || addressType != type) {
            address = current;
            addressType = type;
            proof.rssiAt = 0;
            proof.rssi = -127;
        }
    }

    void verify() {
        report("Verify system association; paired-only selectors; threshold=" + std::to_string(binding.threshold) +
            " dBm; ContainerId=" + winrt::to_string(winrt::to_hstring(binding.containerId)));
        report("Requested target; ClassicId=" + winrt::to_string(binding.classicId) + "; BLEId=" + winrt::to_string(binding.bleId));
        watchRelation(classicWatch, false);
        watchRelation(bleWatch, true);
        auto nextReport = GetTickCount64();
        while (!classicWatch.ready || !bleWatch.ready) {
            const auto now = GetTickCount64();
            if (now >= nextReport) {
                report("Watcher Classic status=" + std::to_string(static_cast<int>(classicWatch.watcher.Status())) +
                    " ready=" + std::to_string(classicWatch.ready.load()) + " added=" + std::to_string(classicWatch.addedCount.load()) +
                    "; BLE status=" + std::to_string(static_cast<int>(bleWatch.watcher.Status())) +
                    " ready=" + std::to_string(bleWatch.ready.load()) + " added=" + std::to_string(bleWatch.addedCount.load()));
                nextReport = now + 1000;
            }
            check(!classicWatch.ready ? "Classic DeviceWatcher initial enumeration" : "BLE DeviceWatcher initial enumeration");
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        report("Classic/BLE watcher initial enumeration completed");
        const auto classic = uniqueEndpoint(await(pairedEndpoints(false), "paired Classic endpoint enumeration"), binding.containerId);
        const auto ble = uniqueEndpoint(await(pairedEndpoints(true), "paired BLE endpoint enumeration"), binding.containerId);
        report("Unique paired association; ClassicId=" + winrt::to_string(classic.Id()) + "; BLEId=" + winrt::to_string(ble.Id()));
        if (classic.Id() != binding.classicId || ble.Id() != binding.bleId)
            throw VerificationError(Failure::associationInvalid, "System endpoint IDs changed");
        device = await(BluetoothLEDevice::FromIdAsync(ble.Id()), "BluetoothLEDevice::FromIdAsync");
        if (!device) throw VerificationError(Failure::connectionLost, "BLE endpoint unavailable");
        auto bond = device.DeviceInformation().Pairing();
        report("BLE bond IsPaired=" + std::to_string(bond.IsPaired()) +
            " protectionLevel=" + std::to_string(static_cast<int>(bond.ProtectionLevel())) +
            " secureConnectionsUsedForPairing=" + std::to_string(device.WasSecureConnectionUsedForPairing()));
        if (!bond.IsPaired() || bond.ProtectionLevel() != DevicePairingProtectionLevel::EncryptionAndAuthentication ||
            !device.WasSecureConnectionUsedForPairing())
            throw VerificationError(Failure::bondRejected, "Authenticated Secure Connections bond required");
        session = await(GattSession::FromDeviceIdAsync(device.BluetoothDeviceId()), "GattSession::FromDeviceIdAsync");
        if (!session || !session.CanMaintainConnection())
            throw VerificationError(Failure::connectionLost, "Cannot retain the verified connection");
        session.MaintainConnection(true);
        report("GattSession MaintainConnection=true; sessionStatus=" + std::to_string(static_cast<int>(session.SessionStatus())) +
            "; connectionStatus=" + std::to_string(static_cast<int>(device.ConnectionStatus())));
        connected = device.ConnectionStatus() == BluetoothConnectionStatus::Connected;
        const std::weak_ptr<State> weak = shared_from_this();
        connection = device.ConnectionStatusChanged(auto_revoke, [weak](const BluetoothLEDevice& sender, const auto&) {
            if (const auto self = weak.lock()) {
                try {
                    std::lock_guard lock(self->mutex);
                    if (sender.ConnectionStatus() == BluetoothConnectionStatus::Connected) self->connected = true;
                    else if (self->connected && !self->closing) self->proof.failure = Failure::connectionLost;
                } catch (...) { self->invalidate(Failure::connectionLost); }
            }
        });
        services = device.GattServicesChanged(auto_revoke, [weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) {
                std::lock_guard lock(self->mutex);
                ++self->revision;
                if (!self->discovering && !self->closing) self->proof.failure = Failure::protectedOperationFailed;
            }
        });
        currentAddress();
        advertisements = BluetoothLEAdvertisementWatcher();
        received = advertisements.Received(auto_revoke, [weak](const auto&, const BluetoothLEAdvertisementReceivedEventArgs& args) {
            if (const auto self = weak.lock()) {
                try {
                    const auto at = GetTickCount64();
                    const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(winrt::clock::now() - args.Timestamp()).count();
                    if (age < 0 || static_cast<std::uint64_t>(age) > kEvidenceLifetimeMs || static_cast<std::uint64_t>(age) > at) return;
                    const auto sampledAt = at - static_cast<std::uint64_t>(age);
                    std::lock_guard lock(self->mutex);
                    if (self->closing || self->proof.failure != Failure::none || sampledAt < self->started ||
                        args.BluetoothAddress() != self->address || args.BluetoothAddressType() != self->addressType) return;
                    const auto value = args.RawSignalStrengthInDBm();
                    if (value < -127 || value >= 0) return;
                    if (sampledAt < self->proof.rssiAt) return;
                    self->proof.rssi = value;
                    self->proof.rssiAt = sampledAt;
                } catch (...) { self->invalidate(Failure::rssiUnavailable); }
            }
        });
        stopped = advertisements.Stopped(auto_revoke, [weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) self->invalidate(Failure::rssiUnavailable);
        });
        advertisements.Start();
        for (;;) {
            check("ANCS discovery/rediscovery");
            std::uint64_t initial;
            { std::lock_guard lock(mutex); initial = revision; }
            const auto found = await(device.GetGattServicesForUuidAsync(kAncsService, BluetoothCacheMode::Uncached), "Uncached ANCS service discovery");
            bool changed;
            { std::lock_guard lock(mutex); changed = initial != revision; }
            if (changed) { report("ANCS discovery changed; discard provisional services and rediscover"); for (auto stale : found.Services()) stale.Close(); continue; }
            gatt(found);
            report("ANCS service count=" + std::to_string(found.Services().Size()));
            if (found.Services().Size() != 1) throw VerificationError(Failure::protectedOperationFailed, "ANCS service not unique");
            service = found.Services().GetAt(0);
            const auto sources = await(service.GetCharacteristicsForUuidAsync(kNotificationSource, BluetoothCacheMode::Uncached), "Uncached Notification Source discovery");
            { std::lock_guard lock(mutex); changed = initial != revision; }
            if (changed) { report("ANCS discovery changed; discard provisional characteristics and rediscover"); service.Close(); service = nullptr; continue; }
            gatt(sources);
            report("Notification Source count=" + std::to_string(sources.Characteristics().Size()));
            if (sources.Characteristics().Size() != 1) throw VerificationError(Failure::protectedOperationFailed, "Notification Source not unique");
            source = sources.Characteristics().GetAt(0);
            source.ProtectionLevel(GattProtectionLevel::EncryptionAndAuthenticationRequired);
            const auto descriptors = await(source.GetDescriptorsForUuidAsync(GattDescriptorUuids::ClientCharacteristicConfiguration(), BluetoothCacheMode::Uncached), "Uncached CCCD discovery");
            { std::lock_guard lock(mutex); changed = initial != revision; if (!changed) discovering = false; }
            if (changed) { report("ANCS discovery changed; discard provisional descriptors and rediscover"); source = nullptr; service.Close(); service = nullptr; continue; }
            gatt(descriptors);
            report("CCCD count=" + std::to_string(descriptors.Descriptors().Size()));
            if (descriptors.Descriptors().Size() != 1) throw VerificationError(Failure::protectedOperationFailed, "CCCD not unique");
            auto cccd = descriptors.Descriptors().GetAt(0);
            cccd.ProtectionLevel(GattProtectionLevel::EncryptionAndAuthenticationRequired);
            subscribed = true;
            gatt(await(source.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(GattClientCharacteristicConfigurationDescriptorValue::Notify), "protected CCCD subscription"));
            const auto read = await(cccd.ReadValueAsync(BluetoothCacheMode::Uncached), "protected Uncached CCCD read");
            gatt(read);
            if (!read.Value() || read.Value().Length() != 2) throw VerificationError(Failure::protectedOperationFailed, "Invalid CCCD value");
            auto reader = Windows::Storage::Streams::DataReader::FromBuffer(read.Value());
            reader.ByteOrder(Windows::Storage::Streams::ByteOrder::LittleEndian);
            if (reader.ReadUInt16() != 1) throw VerificationError(Failure::protectedOperationFailed, "CCCD subscription not confirmed");
            { std::lock_guard lock(mutex); proof.communicationAt = GetTickCount64(); }
            gatt(await(source.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(GattClientCharacteristicConfigurationDescriptorValue::None), "CCCD unsubscribe"));
            subscribed = false;
            break;
        }
        currentAddress();
        refresh();
        const auto result = evidence();
        report("Evidence RSSI=" + std::to_string(result.rssi) + " dBm; rssiAgeMs=" +
            (result.rssiAt ? std::to_string(GetTickCount64() - result.rssiAt) : "unavailable") +
            "; failure=" + std::to_string(static_cast<unsigned>(result.failure)));
        if (result.failure != Failure::none) throw VerificationError(result.failure, "BLE evidence rejected");
    }

    Evidence evidence() const {
        std::lock_guard lock(mutex);
        auto result = proof;
        if (closing) { result.failure = Failure::connectionLost; return result; }
        try {
            if (!device || device.ConnectionStatus() != BluetoothConnectionStatus::Connected)
                result.failure = Failure::connectionLost;
            else if (device.BluetoothAddress() != address || device.BluetoothAddressType() != addressType)
                result.failure = Failure::rssiUnavailable;
        } catch (...) { result.failure = Failure::connectionLost; }
        const auto now = GetTickCount64();
        if (result.failure == Failure::none && !freshEvidence(result.communicationAt, started, now))
            result.failure = Failure::evidenceExpired;
        if (result.failure == Failure::none && !freshEvidence(result.rssiAt, started, now))
            result.failure = result.rssiAt ? Failure::evidenceExpired : Failure::rssiUnavailable;
        if (result.failure == Failure::none && result.rssi < binding.threshold) result.failure = Failure::rssiTooLow;
        return result;
    }

    void refresh() {
        check();
        currentAddress();
        if (device.ConnectionStatus() != BluetoothConnectionStatus::Connected)
            throw VerificationError(Failure::connectionLost, "BLE disconnected");
        std::lock_guard lock(mutex);
        connected = true;
    }

    void stopWatch(RelationWatch& watch) {
        watch.added.revoke(); watch.updated.revoke(); watch.removed.revoke(); watch.completed.revoke(); watch.stopped.revoke();
        if (watch.watcher && (watch.watcher.Status() == DeviceWatcherStatus::Started ||
            watch.watcher.Status() == DeviceWatcherStatus::EnumerationCompleted)) watch.watcher.Stop();
        watch.watcher = nullptr;
    }

    void close() {
        { std::lock_guard lock(mutex); closing = true; }
        if (subscribed && source) {
            auto result = source.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(GattClientCharacteristicConfigurationDescriptorValue::None).get();
            if (result.Status() != GattCommunicationStatus::Success) throw VerificationError(Failure::protectedOperationFailed, "CCCD cleanup failed");
            subscribed = false;
        }
        received.revoke(); stopped.revoke();
        if (advertisements) { advertisements.Stop(); advertisements = nullptr; }
        stopWatch(classicWatch); stopWatch(bleWatch);
        connection.revoke(); services.revoke();
        source = nullptr;
        if (service) { service.Close(); service = nullptr; }
        if (session) { session.MaintainConnection(false); session.Close(); session = nullptr; }
        if (device) { device.Close(); device = nullptr; }
    }
};

Session::Session(BindingRecord record, std::uint64_t started, std::function<bool()> valid,
    std::function<void(const std::string&)> report)
    : state_(std::make_shared<State>(std::move(record), started, std::move(valid), std::move(report))) {}
Session::~Session() {
    try { state_->close(); }
    catch (...) { OutputDebugStringW(L"System BLE cleanup failed\n"); }
}
void Session::verify() { state_->verify(); }
void Session::refresh() { state_->refresh(); }
void Session::close() { state_->close(); }
Evidence Session::evidence() const { return state_->evidence(); }
}
