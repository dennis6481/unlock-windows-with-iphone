// Created by Rui MA on 11 Oct 2026

#pragma once

#include "SystemBleContract.h"
#include "../SavedCredential/SavedCredentialIpc.h"
#include <winrt/Windows.Devices.Bluetooth.h>
#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#include <winrt/Windows.Devices.Enumeration.h>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace unlock_windows::system_ble {
using Failure = saved_credential::AuthenticationFailure;

std::optional<winrt::guid> containerId(const winrt::Windows::Devices::Enumeration::DeviceInformation& item);
winrt::hstring deviceSelector(bool ble);
winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>
    pairedEndpoints(bool ble);
winrt::Windows::Devices::Enumeration::DeviceInformation uniqueEndpoint(
    const winrt::Windows::Devices::Enumeration::DeviceInformationCollection& items, const winrt::guid& container);

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

class Session final {
public:
    Session(BindingRecord binding, std::uint64_t started, std::function<bool()> valid,
        std::function<void(const std::string&)> report = {});
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    void verify();
    void refresh();
    void close();
    Evidence evidence() const;
private:
    struct State;
    std::shared_ptr<State> state_;
};
}
