// Created by Rui MA on 26 Sep 2026

#include "UnlockServiceIpc.h"

#include <Windows.h>

#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/base.h>

#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace winrt;
using namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace winrt::Windows::Storage::Streams;

constexpr std::wstring_view kServiceUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCDE";
constexpr std::wstring_view kRequestCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD1";
constexpr std::wstring_view kChallengeCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD2";
constexpr std::wstring_view kAssertionCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD3";
constexpr std::wstring_view kResultCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD4";

constexpr std::size_t kMaxTransportFrameSize = 4096;

std::string narrow(const hstring& value) {
    return to_string(value);
}

IBuffer makeBuffer(const std::string& value) {
    DataWriter writer;
    writer.WriteBytes(array_view<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(value.data()),
        reinterpret_cast<const std::uint8_t*>(value.data()) + value.size()
    ));
    return writer.DetachBuffer();
}

std::vector<std::uint8_t> readBuffer(const IBuffer& value) {
    if (!value) {
        return {};
    }

    DataReader reader = DataReader::FromBuffer(value);
    std::vector<std::uint8_t> result(reader.UnconsumedBufferLength());
    if (!result.empty()) {
        reader.ReadBytes(array_view<std::uint8_t>(result));
    }
    return result;
}

std::string bytesAsText(const std::vector<std::uint8_t>& bytes) {
    return std::string(
        reinterpret_cast<const char*>(bytes.data()),
        bytes.size()
    );
}

class GattHost final {
public:
    GattHost() = default;
    GattHost(const GattHost&) = delete;
    GattHost& operator=(const GattHost&) = delete;

    void start() {
        const auto serviceResult = GattServiceProvider::CreateAsync(
            guid(kServiceUuid)
        ).get();
        if (serviceResult.Error() != winrt::Windows::Devices::Bluetooth::BluetoothError::Success) {
            throw hresult_error(E_FAIL, L"GattServiceProvider::CreateAsync failed");
        }
        serviceProvider_ = serviceResult.ServiceProvider();

        requestCharacteristic_ = createCharacteristic(
            kRequestCharacteristicUuid,
            GattCharacteristicProperties::Write
        );
        challengeCharacteristic_ = createCharacteristic(
            kChallengeCharacteristicUuid,
            GattCharacteristicProperties::Notify | GattCharacteristicProperties::Read
        );
        assertionCharacteristic_ = createCharacteristic(
            kAssertionCharacteristicUuid,
            GattCharacteristicProperties::Write
        );
        resultCharacteristic_ = createCharacteristic(
            kResultCharacteristicUuid,
            GattCharacteristicProperties::Notify | GattCharacteristicProperties::Read
        );

        requestWriteToken_ = requestCharacteristic_.WriteRequested(
            [this](GattLocalCharacteristic const&, GattWriteRequestedEventArgs const& args) {
                handleRequestWrite(args);
            }
        );
        assertionWriteToken_ = assertionCharacteristic_.WriteRequested(
            [this](GattLocalCharacteristic const&, GattWriteRequestedEventArgs const& args) {
                handleAssertionWrite(args);
            }
        );
        challengeSubscriptionToken_ = challengeCharacteristic_.SubscribedClientsChanged(
            [this](GattLocalCharacteristic const& characteristic, winrt::Windows::Foundation::IInspectable const&) {
                std::cout << "[GattHost] challenge subscribers: "
                          << characteristic.SubscribedClients().Size() << "\n";
            }
        );

        advertisementStatusToken_ = serviceProvider_.AdvertisementStatusChanged(
            [this](
                GattServiceProvider const&,
                GattServiceProviderAdvertisementStatusChangedEventArgs const& args
            ) {
                std::cout << "[GattHost] advertisement status="
                          << static_cast<int>(args.Status())
                          << " error=" << static_cast<int>(args.Error()) << "\n";
            }
        );

        GattServiceProviderAdvertisingParameters advertisingParameters;
        advertisingParameters.IsDiscoverable(true);
        advertisingParameters.IsConnectable(true);
        serviceProvider_.StartAdvertising(advertisingParameters);
        std::cout << "[GattHost] advertising service " << to_string(kServiceUuid) << "\n"
                  << "[GattHost] request=" << to_string(kRequestCharacteristicUuid) << "\n"
                  << "[GattHost] challenge=" << to_string(kChallengeCharacteristicUuid) << "\n"
                  << "[GattHost] assertion=" << to_string(kAssertionCharacteristicUuid) << "\n"
                  << "[GattHost] result=" << to_string(kResultCharacteristicUuid) << "\n"
                  << "[GattHost] transport-only foreground prototype; authentication is not implemented\n";
    }

    void stop() noexcept {
        try {
            if (serviceProvider_) {
                serviceProvider_.AdvertisementStatusChanged(advertisementStatusToken_);
            }
            if (serviceProvider_) {
                serviceProvider_.StopAdvertising();
            }
            if (requestCharacteristic_) {
                requestCharacteristic_.WriteRequested(requestWriteToken_);
            }
            if (assertionCharacteristic_) {
                assertionCharacteristic_.WriteRequested(assertionWriteToken_);
            }
            if (challengeCharacteristic_) {
                challengeCharacteristic_.SubscribedClientsChanged(challengeSubscriptionToken_);
            }
        } catch (...) {
            // Shutdown is best effort; the process is already leaving the apartment.
        }
    }

private:
    GattLocalCharacteristic createCharacteristic(
        const std::wstring_view uuid,
        const GattCharacteristicProperties properties
    ) const {
        GattLocalCharacteristicParameters parameters;
        parameters.CharacteristicProperties(properties);
        parameters.ReadProtectionLevel(GattProtectionLevel::Plain);
        parameters.WriteProtectionLevel(GattProtectionLevel::Plain);

        const auto result = serviceProvider_.Service().CreateCharacteristicAsync(
            guid(uuid),
            parameters
        ).get();
        if (result.Error() != winrt::Windows::Devices::Bluetooth::BluetoothError::Success) {
            throw hresult_error(E_FAIL, L"GattLocalService::CreateCharacteristicAsync failed");
        }
        return result.Characteristic();
    }

    static fire_and_forget finishRequest(
        GattWriteRequestedEventArgs args,
        std::function<void(GattWriteRequest const&)> handler
    ) {
        auto deferral = args.GetDeferral();
        try {
            auto request = co_await args.GetRequestAsync();
            if (request) {
                if (request.Option() == GattWriteOption::WriteWithResponse) {
                    request.Respond();
                }
                handler(request);
            }
        } catch (const hresult_error& error) {
            std::cerr << "[GattHost] GATT write handler failed: "
                      << narrow(error.message()) << "\n";
        } catch (const std::exception& error) {
            std::cerr << "[GattHost] GATT write handler failed: "
                      << error.what() << "\n";
        }
        deferral.Complete();
    }

    void handleRequestWrite(const GattWriteRequestedEventArgs& args) {
        finishRequest(args, [this](const GattWriteRequest& request) {
            const auto bytes = readBuffer(request.Value());
            if (bytes.size() != 1 || bytes.front() != 0x01) {
                std::cerr << "[GattHost] rejected request frame: expected one byte 0x01, got "
                          << bytes.size() << " byte(s)\n";
                return;
            }

            std::cout << "[GattHost] request frame received; asking UnlockService for challenge\n";
            const auto response = unlock_windows::service::ipc::call(
                unlock_windows::service::ipc::Operation::issueChallenge,
                {}
            );
            if (response.status != unlock_windows::service::ipc::Status::success) {
                throw std::runtime_error(
                    "UnlockService challenge request failed: " + response.payload
                );
            }

            std::cout << "[GattHost] request accepted; challenge issued by UnlockService\n";
            std::cout << "[GattHost] challenge notification length=" << response.payload.size() << "\n";
            logNotificationResults(
                challengeCharacteristic_.NotifyValueAsync(makeBuffer(response.payload)).get(),
                "challenge"
            );
        });
    }

    void handleAssertionWrite(const GattWriteRequestedEventArgs& args) {
        finishRequest(args, [this](const GattWriteRequest& request) {
            const auto bytes = readBuffer(request.Value());
            if (bytes.empty() || bytes.size() > kMaxTransportFrameSize) {
                std::cerr << "[GattHost] rejected assertion frame length=" << bytes.size() << "\n";
                return;
            }

            std::cout << "[GattHost] assertion frame received, length=" << bytes.size() << "\n";
            const auto response = unlock_windows::service::ipc::call(
                unlock_windows::service::ipc::Operation::verifyAssertion,
                bytesAsText(bytes)
            );
            if (response.status != unlock_windows::service::ipc::Status::success) {
                std::cerr << "[GattHost] UnlockService verification failed: "
                          << response.payload << "\n";
            } else {
                std::cout << "[GattHost] UnlockService verification result received\n";
            }

            const std::string result = response.status == unlock_windows::service::ipc::Status::success
                ? response.payload
                : "{\"authenticated\":false,\"status\":\"service_unavailable\"}";
            logNotificationResults(
                resultCharacteristic_.NotifyValueAsync(makeBuffer(result)).get(),
                "result"
            );
        });
    }

    static void logNotificationResults(
        const winrt::Windows::Foundation::Collections::IVectorView<GattClientNotificationResult>& results,
        const char* name
    ) {
        for (const auto& result : results) {
            if (result.Status() != GattCommunicationStatus::Success) {
                std::cerr << "[GattHost] " << name << " notification status="
                          << static_cast<int>(result.Status()) << "\n";
            }
        }
    }

    GattServiceProvider serviceProvider_{nullptr};
    GattLocalCharacteristic requestCharacteristic_{nullptr};
    GattLocalCharacteristic challengeCharacteristic_{nullptr};
    GattLocalCharacteristic assertionCharacteristic_{nullptr};
    GattLocalCharacteristic resultCharacteristic_{nullptr};
    event_token requestWriteToken_{};
    event_token assertionWriteToken_{};
    event_token challengeSubscriptionToken_{};
    event_token advertisementStatusToken_{};
};

} // namespace

int main() {
    try {
        init_apartment(apartment_type::multi_threaded);

        GattHost host;
        host.start();
        std::cout << "[GattHost] press Enter to stop advertising\n";
        std::string line;
        std::getline(std::cin, line);
        host.stop();
        uninit_apartment();
        return 0;
    } catch (const hresult_error& error) {
        std::cerr << "[GattHost] startup failed: " << narrow(error.message())
                  << " (0x" << std::hex << static_cast<std::uint32_t>(error.code().value)
                  << std::dec << ")\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "[GattHost] startup failed: " << error.what() << "\n";
        return 1;
    }
}
