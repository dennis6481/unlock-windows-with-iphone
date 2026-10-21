// Created by Rui MA on 11 Oct 2026

#include <Windows.h>
#undef GetCurrentTime
#include "SystemBleSession.h"
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.Streams.h>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <exception>

namespace unlock_windows::system_ble {
using namespace winrt;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Foundation;

hstring deviceSelector() {
    return BluetoothLEDevice::GetDeviceSelectorFromPairingState(true);
}

IAsyncOperation<DeviceInformationCollection> pairedEndpoints() {
    return DeviceInformation::FindAllAsync(deviceSelector(), single_threaded_vector<hstring>({L"System.Devices.Aep.IsPaired"}),
        DeviceInformationKind::AssociationEndpoint);
}

DeviceInformation findUniqueEndpoint(const DeviceInformationCollection& items, const hstring& target) {
    DeviceInformation selected{nullptr};
    for (const auto& item : items) {
        if (target.empty() || item.Id() != target) continue;
        if (selected) throw VerificationError(Failure::associationInvalid, "Duplicate BLE endpoint ID");
        selected = item;
    }
    return selected;
}

DeviceInformation uniqueEndpoint(const DeviceInformationCollection& items, const hstring& target) {
    auto selected = findUniqueEndpoint(items, target);
    if (!selected) throw VerificationError(Failure::associationInvalid, "Bound BLE endpoint is missing from paired devices");
    return selected;
}

struct Session::State final : std::enable_shared_from_this<State> {
    std::wstring endpointId;
    std::uint64_t started = 0, deadline = 0;
    std::function<bool()> valid;
    std::function<void(const std::string&)> reporter;
    mutable std::mutex reportMutex;
    mutable std::mutex mutex;
    CommunicationEvidence proof;
    Failure transportFailure = Failure::none;
    const char* failureDetail = "BLE evidence invalidated";
    std::uint64_t revision = 0, structureRevision = 0;
    bool requestActive = false, preparing = true, connected = false, closing = false;
    BluetoothLEDevice device{nullptr};
    GattSession session{nullptr};
    GattDeviceService service{nullptr};
    GattCharacteristic source{nullptr};
    GattDescriptor cccd{nullptr};
    bool subscribed = false;
    BluetoothLEDevice::ConnectionStatusChanged_revoker connection;
    BluetoothLEDevice::GattServicesChanged_revoker services;
    GattSession::SessionStatusChanged_revoker sessionStatus;
    struct EndpointWatch final {
        DeviceWatcher watcher{nullptr};
        DeviceWatcher::Added_revoker added;
        DeviceWatcher::Updated_revoker updated;
        DeviceWatcher::Removed_revoker removed;
        DeviceWatcher::EnumerationCompleted_revoker completed;
        DeviceWatcher::Stopped_revoker stopped;
        std::atomic<bool> ready{false};
        std::atomic<unsigned> addedCount{0};
    } bleWatch;

    State(std::wstring value, std::function<void(const std::string&)> report)
        : endpointId(std::move(value)), reporter(std::move(report)) {}

    void beginRequest(std::uint64_t at, std::function<bool()> predicate) {
        std::lock_guard lock(mutex);
        if (requestActive) throw VerificationError(Failure::internalError, "BLE request already active");
        started = at;
        deadline = at + kOperationLifetimeMs;
        valid = std::move(predicate);
        proof = {};
        if (transportFailure == Failure::none) failureDetail = "BLE evidence invalidated";
        requestActive = true;
        preparing = true;
    }

    void report(const std::string& message) const {
        std::lock_guard lock(reportMutex);
        if (reporter) reporter(message);
    }

    void invalidate(Failure reason, const char* detail = "BLE evidence invalidated") {
        std::lock_guard lock(mutex);
        if (!closing) {
            transportFailure = reason;
            failureDetail = detail;
            if (requestActive && proof.failure == Failure::none) proof.failure = reason;
        }
    }

    void checkLocked(const char* operation = "BLE evidence validation") const {
        if (GetTickCount64() >= deadline)
            throw VerificationError(Failure::expired, (std::string("BLE deadline exceeded during ") + operation).c_str());
        if (transportFailure != Failure::none) throw VerificationError(transportFailure, failureDetail);
        if (proof.failure != Failure::none) throw VerificationError(proof.failure, failureDetail);
    }

    void check(const char* operation = "BLE evidence validation") const {
        if (!valid()) throw VerificationError(Failure::cancelled, "Request invalidated");
        std::lock_guard lock(mutex);
        checkLocked(operation);
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

    void watchEndpoint() {
        auto& watch = bleWatch;
        const std::weak_ptr<State> weak = shared_from_this();
        const auto selector = deviceSelector();
        report("BEGIN BLE paired watcher; AQS=" + winrt::to_string(selector));
        watch.watcher = DeviceInformation::CreateWatcher(selector, single_threaded_vector<hstring>({L"System.Devices.Aep.IsPaired"}),
            DeviceInformationKind::AssociationEndpoint);
        auto* ready = &watch.ready;
        auto* count = &watch.addedCount;
        watch.added = watch.watcher.Added(auto_revoke, [weak, count](const auto&, const DeviceInformation&) {
            if (const auto self = weak.lock()) ++*count;
        });
        auto changed = [weak](const auto&, const DeviceInformationUpdate& item) {
            if (const auto self = weak.lock()) {
                try {
                    if (item.Id() == self->endpointId) {
                        if (item.Properties().HasKey(L"System.Devices.Aep.IsPaired")) {
                            auto value = item.Properties().Lookup(L"System.Devices.Aep.IsPaired").try_as<IPropertyValue>();
                            if (!value || value.Type() != PropertyType::Boolean || !value.GetBoolean())
                                self->invalidate(Failure::associationInvalid, "DeviceWatcher Updated: bound BLE endpoint no longer paired or IsPaired invalid");
                        }
                    }
                } catch (...) { self->invalidate(Failure::associationInvalid, "DeviceWatcher Updated: reading BLE pairing state failed"); }
            }
        };
        watch.updated = watch.watcher.Updated(auto_revoke, changed);
        watch.removed = watch.watcher.Removed(auto_revoke, [weak](const auto&, const DeviceInformationUpdate& item) {
            if (const auto self = weak.lock(); self &&
                item.Id() == self->endpointId) self->invalidate(Failure::associationInvalid, "DeviceWatcher Removed: bound BLE endpoint removed");
        });
        watch.completed = watch.watcher.EnumerationCompleted(auto_revoke, [weak, ready](const auto&, const auto&) {
            if (const auto self = weak.lock()) *ready = true;
        });
        watch.stopped = watch.watcher.Stopped(auto_revoke, [weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) self->invalidate(Failure::associationInvalid, "DeviceWatcher Stopped: BLE pairing monitoring stopped");
        });
        watch.watcher.Start();
    }

    void open() {
        report("Verify paired BLE endpoint and protected communication");
        report("Requested target; BLEId=" + winrt::to_string(endpointId));
        if (!bleWatch.watcher) watchEndpoint();
        auto nextReport = GetTickCount64();
        while (!bleWatch.ready) {
            const auto now = GetTickCount64();
            if (now >= nextReport) {
                report("Watcher BLE status=" + std::to_string(static_cast<int>(bleWatch.watcher.Status())) +
                    " ready=" + std::to_string(bleWatch.ready.load()) + " added=" + std::to_string(bleWatch.addedCount.load()));
                nextReport = now + 1000;
            }
            check("BLE DeviceWatcher initial enumeration");
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        report("BLE watcher initial enumeration completed");
        const auto ble = uniqueEndpoint(await(pairedEndpoints(), "paired BLE endpoint enumeration"), hstring(endpointId));
        if (!ble.Pairing().IsPaired())
            throw VerificationError(Failure::associationInvalid, "Bound BLE endpoint is no longer paired");
        report("Paired BLE endpoint matched; BLEId=" + winrt::to_string(ble.Id()));
        if (!device) device = await(BluetoothLEDevice::FromIdAsync(ble.Id()), "BluetoothLEDevice::FromIdAsync");
        if (!device) throw VerificationError(Failure::connectionLost, "BLE endpoint unavailable");
        auto bond = device.DeviceInformation().Pairing();
        report("BLE bond IsPaired=" + std::to_string(bond.IsPaired()) +
            " protectionLevel=" + std::to_string(static_cast<int>(bond.ProtectionLevel())) +
            " secureConnectionsUsedForPairing=" + std::to_string(device.WasSecureConnectionUsedForPairing()));
        if (!bond.IsPaired() || bond.ProtectionLevel() != DevicePairingProtectionLevel::EncryptionAndAuthentication ||
            !device.WasSecureConnectionUsedForPairing()) {
            invalidate(Failure::bondRejected, "Authenticated Secure Connections bond required");
            throw VerificationError(Failure::bondRejected, "Authenticated Secure Connections bond required");
        }
        if (session) return;
        session = await(GattSession::FromDeviceIdAsync(device.BluetoothDeviceId()), "GattSession::FromDeviceIdAsync");
        if (!session || !session.CanMaintainConnection())
            throw VerificationError(Failure::connectionLost, "Cannot retain the verified connection");
        session.MaintainConnection(true);
        report("GattSession MaintainConnection=true; sessionStatus=" + std::to_string(static_cast<int>(session.SessionStatus())) +
            "; connectionStatus=" + std::to_string(static_cast<int>(device.ConnectionStatus())));
        { std::lock_guard lock(mutex); connected = device.ConnectionStatus() == BluetoothConnectionStatus::Connected; }
        const std::weak_ptr<State> weak = shared_from_this();
        connection = device.ConnectionStatusChanged(auto_revoke, [weak](const BluetoothLEDevice& sender, const auto&) {
            if (const auto self = weak.lock()) {
                try {
                    const auto status = sender.ConnectionStatus();
                    {
                        std::lock_guard lock(self->mutex);
                        if (status != BluetoothConnectionStatus::Connected && !self->closing) {
                            ++self->revision;
                            self->proof.communicationAt = 0;
                            if (self->requestActive && self->connected) self->proof.failure = Failure::connectionLost;
                        }
                        self->connected = status == BluetoothConnectionStatus::Connected;
                    }
                    self->report("BLE connectionStatus=" + std::to_string(static_cast<int>(status)));
                } catch (...) { self->invalidate(Failure::connectionLost); }
            }
        });
        services = device.GattServicesChanged(auto_revoke, [weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) {
                try {
                    {
                        std::lock_guard lock(self->mutex);
                        ++self->revision;
                        self->proof.communicationAt = 0;
                        if (self->requestActive && !self->preparing && !self->closing) {
                            self->proof.failure = Failure::protectedOperationFailed;
                            self->failureDetail = "GATT services changed after protected verification became stable";
                        }
                    }
                    self->report("GATT services changed; service structure invalidated");
                } catch (...) { self->invalidate(Failure::protectedOperationFailed, "GATT services changed callback failed"); }
            }
        });
        sessionStatus = session.SessionStatusChanged(auto_revoke, [weak](const auto&, const GattSessionStatusChangedEventArgs& args) {
            if (const auto self = weak.lock()) {
                try {
                    const auto status = args.Status();
                    {
                        std::lock_guard lock(self->mutex);
                        if (status == GattSessionStatus::Closed && !self->closing) {
                            ++self->revision;
                            if (self->requestActive && self->connected) self->proof.failure = Failure::connectionLost;
                        }
                    }
                    self->report("GATT sessionStatus=" + std::to_string(static_cast<int>(status)) +
                        "; error=" + std::to_string(static_cast<int>(args.Error())));
                } catch (...) { self->invalidate(Failure::connectionLost, "GATT session status callback failed"); }
            }
        });
    }

    void discardStructure() {
        cccd = nullptr;
        source = nullptr;
        if (service) { service.Close(); service = nullptr; }
    }

    void discover() {
        bool reusable;
        {
            std::lock_guard lock(mutex);
            reusable = cccd && structureRevision == revision;
        }
        if (reusable) { report("Reuse current connection service structure; live verification still required"); return; }
        discardStructure();
        for (;;) {
            check("ANCS discovery/rediscovery");
            std::uint64_t initial;
            { std::lock_guard lock(mutex); initial = revision; }
            const auto found = await(device.GetGattServicesForUuidAsync(kAncsService, BluetoothCacheMode::Cached), "Cached-mode ANCS structure query (OS may query device)");
            bool changed;
            { std::lock_guard lock(mutex); changed = initial != revision; }
            if (changed) { report("ANCS discovery changed; discard provisional services and rediscover"); for (auto stale : found.Services()) stale.Close(); continue; }
            gatt(found);
            report("ANCS service count=" + std::to_string(found.Services().Size()));
            if (found.Services().Size() != 1) throw VerificationError(Failure::protectedOperationFailed, "ANCS service not unique");
            service = found.Services().GetAt(0);
            const auto opened = await(service.OpenAsync(GattSharingMode::SharedReadAndWrite), "Open ANCS service for shared read/write");
            report("ANCS shared open status=" + std::to_string(static_cast<int>(opened)));
            if (opened != GattOpenStatus::Success && opened != GattOpenStatus::AlreadyOpened)
                throw VerificationError(Failure::protectedOperationFailed,
                    ("ANCS shared open failed: status=" + std::to_string(static_cast<int>(opened))).c_str());
            const auto sources = await(service.GetCharacteristicsForUuidAsync(kNotificationSource, BluetoothCacheMode::Cached), "Cached-mode Notification Source structure query");
            { std::lock_guard lock(mutex); changed = initial != revision; }
            if (changed) { report("ANCS discovery changed; discard provisional characteristics and rediscover"); service.Close(); service = nullptr; continue; }
            gatt(sources);
            report("Notification Source count=" + std::to_string(sources.Characteristics().Size()));
            if (sources.Characteristics().Size() != 1) throw VerificationError(Failure::protectedOperationFailed, "Notification Source not unique");
            source = sources.Characteristics().GetAt(0);
            source.ProtectionLevel(GattProtectionLevel::EncryptionAndAuthenticationRequired);
            const auto descriptors = await(source.GetDescriptorsForUuidAsync(GattDescriptorUuids::ClientCharacteristicConfiguration(), BluetoothCacheMode::Cached), "Cached-mode CCCD structure query");
            { std::lock_guard lock(mutex); changed = initial != revision; }
            if (changed) { report("ANCS discovery changed; discard provisional descriptors and rediscover"); source = nullptr; service.Close(); service = nullptr; continue; }
            gatt(descriptors);
            report("CCCD count=" + std::to_string(descriptors.Descriptors().Size()));
            if (descriptors.Descriptors().Size() != 1) throw VerificationError(Failure::protectedOperationFailed, "CCCD not unique");
            cccd = descriptors.Descriptors().GetAt(0);
            cccd.ProtectionLevel(GattProtectionLevel::EncryptionAndAuthenticationRequired);
            {
                std::lock_guard lock(mutex);
                changed = initial != revision;
                if (!changed) structureRevision = initial;
            }
            if (changed) { report("ANCS structure changed before publication; rediscover"); discardStructure(); continue; }
            break;
        }
    }

    void prepare(std::uint64_t at, std::function<bool()> predicate) {
        { std::lock_guard lock(mutex); started = at; deadline = at + kOperationLifetimeMs; }
        valid = std::move(predicate);
        check("BLE connection preparation");
        if (!session) open();
        bool changed;
        { std::lock_guard lock(mutex); changed = structureRevision != revision; preparing = true; }
        if (changed) discardStructure();
        if (device.ConnectionStatus() == BluetoothConnectionStatus::Connected && (!cccd || changed)) discover();
    }

    void protectedCommunication() {
        check("protected live verification");
        subscribed = true;
        gatt(await(source.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(GattClientCharacteristicConfigurationDescriptorValue::Notify), "protected CCCD subscription"));
        const auto read = await(cccd.ReadValueAsync(BluetoothCacheMode::Uncached), "protected Uncached CCCD read");
        gatt(read);
        if (!read.Value() || read.Value().Length() != 2) throw VerificationError(Failure::protectedOperationFailed, "Invalid CCCD value");
        auto reader = Windows::Storage::Streams::DataReader::FromBuffer(read.Value());
        reader.ByteOrder(Windows::Storage::Streams::ByteOrder::LittleEndian);
        if (reader.ReadUInt16() != 1) throw VerificationError(Failure::protectedOperationFailed, "CCCD subscription not confirmed");
        const auto verifiedAt = GetTickCount64();
        gatt(await(source.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(GattClientCharacteristicConfigurationDescriptorValue::None), "CCCD unsubscribe"));
        subscribed = false;
        check("protected verification publication");
        {
            std::lock_guard lock(mutex);
            if (structureRevision != revision) return;
            proof.communicationAt = verifiedAt;
            proof.revision = revision;
            preparing = false;
        }
        report("Protected verification complete; request evidence stable");
    }

    void verifyCommunication() {
        check("BLE request start");
        if (!session) throw VerificationError(Failure::internalError, "Connect BLE before protected communication verification");
        if (device.ConnectionStatus() != BluetoothConnectionStatus::Connected || session.SessionStatus() != GattSessionStatus::Active) {
            const auto at = GetTickCount64();
            report("BEGIN BLE/GATT connection readiness wait within original deadline");
            while (device.ConnectionStatus() != BluetoothConnectionStatus::Connected || session.SessionStatus() != GattSessionStatus::Active) {
                check("BLE/GATT connection readiness wait");
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            report("END BLE/GATT connection readiness wait elapsedMs=" + std::to_string(GetTickCount64() - at));
        }
        check("connected service structure preparation");
        const auto preparationChanged = [this] {
            check("protected preparation invalidation");
            std::lock_guard lock(mutex);
            return preparing && structureRevision != revision;
        };
        for (;;) {
            check("service structure and protected verification preparation");
            discover();
            try { protectedCommunication(); }
            catch (const VerificationError& error) {
                if (error.reason != Failure::protectedOperationFailed || !preparationChanged()) throw;
                report(std::string("Protected preparation invalidated by GATT services change: ") + error.what());
            } catch (const hresult_error& error) {
                const auto code = error.code();
                if ((code == RO_E_CLOSED || code == E_ABORT || code == HRESULT_FROM_WIN32(ERROR_CANCELLED)) && preparationChanged()) {
                    report("Protected preparation operation invalidated after GATT services change; HRESULT=" +
                        std::to_string(static_cast<std::uint32_t>(code.value)) + ": " + winrt::to_string(error.message()));
                } else {
                    check("protected GATT operation failure");
                    throw VerificationError(Failure::protectedOperationFailed,
                        ("Protected GATT operation failed; HRESULT=" + std::to_string(static_cast<std::uint32_t>(code.value)) +
                            ": " + winrt::to_string(error.message())).c_str());
                }
            }
            bool stable;
            { std::lock_guard lock(mutex); stable = !preparing; }
            if (stable) break;
            report("GATT services changed during protected preparation; rediscover within original deadline");
            unsubscribe();
            discardStructure();
        }
        refresh();
        std::lock_guard lock(mutex);
        const auto result = currentEvidenceLocked();
        if (result.failure != Failure::none)
            throw VerificationError(result.failure, "Protected communication evidence rejected");
    }

    // Caller holds mutex; time freshness belongs to evidence consumers.
    CommunicationEvidence currentEvidenceLocked(const ConnectionTarget* expected = nullptr) const {
        auto result = proof;
        if (!requestActive) { result.failure = Failure::cancelled; return result; }
        if (closing) { result.failure = Failure::connectionLost; return result; }
        try {
            checkLocked();
            if (!device || !session || device.ConnectionStatus() != BluetoothConnectionStatus::Connected ||
                session.SessionStatus() != GattSessionStatus::Active)
                result.failure = Failure::connectionLost;
            else result.failure = detail::communicationStateFailure(result, targetLocked(), expected);
        } catch (const VerificationError& error) { result.failure = error.reason; }
        catch (const hresult_error&) { result.failure = Failure::connectionLost; }
        return result;
    }

    CommunicationEvidence evidence(const ConnectionTarget* expected = nullptr) const {
        std::lock_guard lock(mutex);
        auto result = currentEvidenceLocked(expected);
        result.failure = communicationFailure(result, started, GetTickCount64());
        return result;
    }

    ConnectionTarget targetLocked() const {
        if (!device || closing) throw VerificationError(Failure::connectionLost, "BLE target unavailable");
        try { return {endpointId, device.BluetoothAddress(), device.BluetoothAddressType(), revision}; }
        catch (const hresult_error&) { throw VerificationError(Failure::connectionLost, "Reading current BLE target failed"); }
    }

    ConnectionTarget target() const {
        std::lock_guard lock(mutex);
        return targetLocked();
    }

    void refresh() {
        check();
        if (device.ConnectionStatus() != BluetoothConnectionStatus::Connected)
            throw VerificationError(Failure::connectionLost, "BLE disconnected");
        std::lock_guard lock(mutex);
        connected = true;
    }

    void stopWatch(EndpointWatch& watch) {
        watch.added.revoke(); watch.updated.revoke(); watch.removed.revoke(); watch.completed.revoke(); watch.stopped.revoke();
        if (watch.watcher && (watch.watcher.Status() == DeviceWatcherStatus::Started ||
            watch.watcher.Status() == DeviceWatcherStatus::EnumerationCompleted)) watch.watcher.Stop();
        watch.watcher = nullptr;
    }

    void unsubscribe() {
        if (!subscribed || !source) return;
        try {
            auto result = source.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(GattClientCharacteristicConfigurationDescriptorValue::None).get();
            subscribed = false;
            if (result.Status() != GattCommunicationStatus::Success)
                throw VerificationError(Failure::protectedOperationFailed, "CCCD cleanup failed; connection must close");
        } catch (const hresult_error& error) {
            subscribed = false;
            bool obsolete;
            { std::lock_guard lock(mutex); obsolete = structureRevision != revision; }
            if (!obsolete || (error.code() != RO_E_CLOSED && error.code() != E_ABORT)) throw;
            report("CCCD cleanup: obsolete source already closed after structure invalidation; discard it");
        } catch (...) { subscribed = false; throw; }
    }

    void endRequest() {
        { std::lock_guard lock(mutex); requestActive = false; proof = {}; preparing = true; }
        unsubscribe();
        valid = {};
        bool changed;
        { std::lock_guard lock(mutex); changed = structureRevision != revision; }
        if (changed) discardStructure();
    }

    void close() {
        { std::lock_guard lock(mutex); closing = true; }
        { std::lock_guard lock(reportMutex); reporter = {}; }
        std::exception_ptr cleanupError;
        try { endRequest(); } catch (...) { cleanupError = std::current_exception(); }
        stopWatch(bleWatch);
        connection.revoke(); services.revoke(); sessionStatus.revoke();
        discardStructure();
        if (session) { session.MaintainConnection(false); session.Close(); session = nullptr; }
        if (device) { device.Close(); device = nullptr; }
        if (cleanupError) std::rethrow_exception(cleanupError);
    }

    bool healthy() const {
        std::lock_guard lock(mutex);
        return !closing && transportFailure == Failure::none;
    }
};

Session::Session(std::wstring endpointId, std::function<void(const std::string&)> report)
    : state_(std::make_shared<State>(std::move(endpointId), std::move(report))) {}
Session::~Session() {
    try { state_->close(); }
    catch (...) { OutputDebugStringW(L"System BLE cleanup failed\n"); }
}
void Session::connect() { state_->check("BLE connection start"); state_->open(); }
void Session::verifyCommunication() { state_->verifyCommunication(); }
void Session::prepare(std::uint64_t started, std::function<bool()> valid) { state_->prepare(started, std::move(valid)); }
void Session::beginRequest(std::uint64_t started, std::function<bool()> valid) {
    state_->beginRequest(started, std::move(valid));
}
void Session::endRequest() { state_->endRequest(); }
void Session::refresh() { state_->refresh(); }
void Session::close() { state_->close(); }
bool Session::healthy() const { return state_->healthy(); }
std::uint64_t Session::revision() const { std::lock_guard lock(state_->mutex); return state_->revision; }
CommunicationEvidence Session::evidence() const { return state_->evidence(); }
CommunicationEvidence Session::evidence(const ConnectionTarget& expected) const { return state_->evidence(&expected); }
ConnectionTarget Session::target() const { return state_->target(); }
}
