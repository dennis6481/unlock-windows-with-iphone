// Created by Rui MA on 11 Oct 2026

#pragma once

#include "SystemBleContract.h"
#include "../SavedCredential/SavedCredentialIpc.h"
#include <winrt/Windows.Devices.Bluetooth.h>
#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#include <winrt/Windows.Devices.Enumeration.h>
#include <functional>
#include <memory>
#include <string>

namespace unlock_windows::system_ble {
using Failure = saved_credential::AuthenticationFailure;

winrt::hstring deviceSelector();
winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>
    pairedEndpoints();
winrt::Windows::Devices::Enumeration::DeviceInformation findUniqueEndpoint(
    const winrt::Windows::Devices::Enumeration::DeviceInformationCollection& items, const winrt::hstring& endpointId);
winrt::Windows::Devices::Enumeration::DeviceInformation uniqueEndpoint(
    const winrt::Windows::Devices::Enumeration::DeviceInformationCollection& items, const winrt::hstring& endpointId);

struct VerificationError final : std::runtime_error {
    Failure reason;
    VerificationError(Failure value, const char* message) : std::runtime_error(message), reason(value) {}
};

struct Evidence final {
    Failure failure = Failure::none;
    std::uint64_t communicationAt = 0;
    std::uint64_t rssiAt = 0;
    int rssi = -127;
};

class PreparationState final {
public:
    void reset() noexcept { failed_ = false; }
    void fail(std::uint64_t revision = 0) noexcept { failed_ = true; revision_ = revision; }
    bool failed() const noexcept { return failed_; }
    bool ready(bool healthy, std::uint64_t revision) noexcept {
        if (healthy && revision != revision_) reset();
        return !failed_;
    }
private:
    bool failed_ = false;
    std::uint64_t revision_ = 0;
};

class Session final {
public:
    Session(BindingRecord binding,
        std::function<void(const std::string&)> report = {});
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    void prepare(std::uint64_t started, std::function<bool()> valid);
    void beginRequest(std::uint64_t started, std::function<bool()> valid);
    void endRequest();
    void verify();
    void refresh();
    void close();
    bool healthy() const;
    std::uint64_t revision() const;
    Evidence evidence() const;
private:
    struct State;
    std::shared_ptr<State> state_;
};
}
