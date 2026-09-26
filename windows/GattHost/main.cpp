// Created by Rui MA on 26 Sep 2026

#include <Windows.h>
#include <objbase.h>
#include <bcrypt.h>

#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/base.h>

#include <array>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
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

constexpr std::string_view kAudience = "windows-unlock";
constexpr std::size_t kMaxTransportFrameSize = 4096;

std::string narrow(const hstring& value) {
    return to_string(value);
}

std::string guidToString(const GUID& value) {
    wchar_t buffer[40]{};
    if (StringFromGUID2(value, buffer, static_cast<int>(std::size(buffer))) == 0) {
        throw std::runtime_error("StringFromGUID2 failed");
    }

    std::wstring result(buffer);
    if (!result.empty() && result.front() == L'{') {
        result.erase(result.begin());
    }
    if (!result.empty() && result.back() == L'}') {
        result.pop_back();
    }

    return to_string(result);
}

void fillRandom(std::uint8_t* output, const ULONG size) {
    const auto status = BCryptGenRandom(
        nullptr,
        output,
        size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status < 0) {
        throw winrt::hresult_error(HRESULT_FROM_NT(status));
    }
}

std::string base64Encode(const std::uint8_t* bytes, const std::size_t size) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(((size + 2) / 3) * 4);
    for (std::size_t index = 0; index < size; index += 3) {
        const auto remaining = size - index;
        const auto first = bytes[index];
        const auto second = remaining > 1 ? bytes[index + 1] : 0;
        const auto third = remaining > 2 ? bytes[index + 2] : 0;

        result.push_back(alphabet[first >> 2]);
        result.push_back(alphabet[((first & 0x03) << 4) | (second >> 4)]);
        result.push_back(remaining > 1 ? alphabet[((second & 0x0f) << 2) | (third >> 6)] : '=');
        result.push_back(remaining > 2 ? alphabet[third & 0x3f] : '=');
    }
    return result;
}

struct ChallengeFrame final {
    std::string requestId;
    std::array<std::uint8_t, 32> nonce{};
    std::int64_t issuedAtMilliseconds = 0;

    [[nodiscard]] std::string toJson() const {
        const auto nonceBase64 = base64Encode(nonce.data(), nonce.size());
        std::ostringstream output;
        output << "{\"audience\":\"" << kAudience
               << "\",\"issuedAtMilliseconds\":" << issuedAtMilliseconds
               << ",\"nonce\":\"" << nonceBase64
               << "\",\"requestID\":\"" << requestId
               << "\",\"version\":1}";
        return output.str();
    }
};

ChallengeFrame makeChallenge() {
    GUID requestId{};
    const auto guidStatus = CoCreateGuid(&requestId);
    if (FAILED(guidStatus)) {
        throw winrt::hresult_error(guidStatus);
    }

    ChallengeFrame result;
    result.requestId = guidToString(requestId);
    fillRandom(result.nonce.data(), static_cast<ULONG>(result.nonce.size()));

    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = now.dwLowDateTime;
    ticks.HighPart = now.dwHighDateTime;
    constexpr std::uint64_t kUnixEpochOffset100Nanoseconds = 116444736000000000ULL;
    const auto unixTicks = ticks.QuadPart - kUnixEpochOffset100Nanoseconds;
    result.issuedAtMilliseconds = static_cast<std::int64_t>(unixTicks / 10000ULL);
    return result;
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

        serviceProvider_.StartAdvertising();
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
                handler(request);
                if (request.Option() == GattWriteOption::WriteWithResponse) {
                    request.Respond();
                }
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

            const auto challenge = makeChallenge();
            const auto json = challenge.toJson();
            std::cout << "[GattHost] request accepted; requestID=" << challenge.requestId << "\n";
            std::cout << "[GattHost] challenge notification length=" << json.size() << "\n";
            logNotificationResults(
                challengeCharacteristic_.NotifyValueAsync(makeBuffer(json)).get(),
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

            const auto text = bytesAsText(bytes);
            std::cout << "[GattHost] assertion frame received, length=" << bytes.size() << "\n";
            std::cout << "[GattHost] assertion JSON is intentionally not trusted by GattHost\n";

            const std::string result =
                "{\"authenticated\":false,\"status\":\"transport-received\"}";
            logNotificationResults(
                resultCharacteristic_.NotifyValueAsync(makeBuffer(result)).get(),
                "result"
            );
            (void)text;
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
