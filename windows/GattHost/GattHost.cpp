// Created by Rui MA on 26 Sep 2026

#include "../Resources/resource.h"
#include "SavedCredentialIpc.h"
#include "AdvertisingLifecycle.h"
#include "TransportReadiness.h"
#include "../DesktopApp/DesktopApp.h"
#include "GattController.h"
#include "EnrollmentStore.h"
#include "../Enrollment/EnrollmentSession.h"
#include "../Enrollment/EnrollmentChannel.h"
#include "../Resources/DesktopUi.h"
#include "../DesktopApp/Dashboard/Dashboard.h"

#include <Windows.h>
#include <WtsApi32.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <objbase.h>

#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#include <winrt/Windows.Devices.Bluetooth.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/base.h>

#include <cstdint>
#include <exception>
#include <functional>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <array>
#include <filesystem>
#include <thread>
#include <iomanip>
#include <algorithm>

namespace {

using namespace winrt;
using namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace winrt::Windows::Storage::Streams;

constexpr std::wstring_view kServiceUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCDE";
constexpr std::wstring_view kRequestCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD1";
constexpr std::wstring_view kChallengeCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD2";
constexpr std::wstring_view kAssertionCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD3";
constexpr std::wstring_view kResultCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD4";
constexpr std::wstring_view kComputerIdCharacteristicUuid = L"F1E2D3C4-B5A6-4789-8012-3456789ABCD5";

constexpr std::size_t kMaxTransportFrameSize = 4096;
constexpr std::uint8_t kRejectRequest = 0x03;
constexpr std::uint8_t kEnrollmentRequest = 0x02;

constexpr UINT kDispatch = WM_APP + 1;
constexpr wchar_t kControlWindowClass[] = L"UnlockWindowsWithIPhoneGattControl";
class GattControl;
}
namespace unlock_windows::desktop_app {

struct CallbackState final {
    std::mutex mutex;
    std::condition_variable drained;
    HWND window = nullptr;
    bool accepting = true;
    unsigned activeWrites = 0;
    std::deque<std::function<void()>> pending;
    std::wstring diagnostics;
    std::wstring transportError;

    bool post(std::function<void()> action) {
        std::lock_guard lock(mutex);
        if (!accepting) return false;
        pending.push_back(std::move(action));
        if (window && !PostMessageW(window, kDispatch, 0, 0)) {
            transportError = L"PostMessageW failed: Win32=" + std::to_wstring(GetLastError());
            OutputDebugStringW(transportError.c_str());
        }
        return true;
    }

    GattControl* control = nullptr;
    bool stopRequested = false;
    bool controlReady = false;
    bool failed = false;
    std::optional<DashboardSnapshot> snapshot;
    std::vector<GattNotice> notices;
    std::function<bool()> wake;

    void notify() {
        try {
            if (!wake()) record(L"Desktop dispatcher: background notification rejected; the STA timer will observe it.", false);
        } catch (const winrt::hresult_error& error) {
            record(L"Desktop dispatcher: " + std::wstring(error.message()), false);
        }
    }

    bool stopping() {
        std::lock_guard lock(mutex);
        return stopRequested;
    }

    void stop() {
        {
            std::lock_guard lock(mutex);
            stopRequested = true;
            accepting = false;
            pending.clear();
        }
        notify();
    }

    void notice(std::wstring message, std::wstring title, UINT flags, bool requireRunning = false) {
        {
            std::lock_guard lock(mutex);
            if (requireRunning && stopRequested) return;
            notices.push_back({std::move(message), std::move(title), flags});
        }
        notify();
    }
    void record(const std::wstring& message, bool error) {
        SYSTEMTIME utc{};
        GetSystemTime(&utc);
        std::wostringstream prefix;
        prefix << std::setfill(L'0') << std::setw(4) << utc.wYear << L'-'
            << std::setw(2) << utc.wMonth << L'-' << std::setw(2) << utc.wDay << L'T'
            << std::setw(2) << utc.wHour << L':' << std::setw(2) << utc.wMinute << L':'
            << std::setw(2) << utc.wSecond << L'.' << std::setw(3) << utc.wMilliseconds
            << L"Z tickMs=" << GetTickCount64() << L' ';
        const auto line = prefix.str() + message;
        OutputDebugStringW((line + L"\n").c_str());
        std::lock_guard lock(mutex);
        diagnostics += line + L"\r\n";
        if (diagnostics.size() > 16000) diagnostics.erase(0, diagnostics.find(L"\n", 8000) + 1);
        if (error) transportError = message;
    }
};

}
namespace {
using CallbackState = unlock_windows::desktop_app::CallbackState;
class LogLine final : public std::ostringstream {
public:
    LogLine(std::shared_ptr<CallbackState> state, bool error) : state_(std::move(state)), error_(error) {}
    ~LogLine() { state_->record(std::wstring(to_hstring(str())), error_); }
private:
    std::shared_ptr<CallbackState> state_;
    bool error_;
};

std::wstring exceptionText() {
    try { throw; }
    catch (const hresult_error& error) {
        return std::wstring(error.message()) + L" (HRESULT=" +
            std::to_wstring(static_cast<std::uint32_t>(error.code().value)) + L")";
    } catch (const std::exception& error) { return std::wstring(to_hstring(error.what())); }
    catch (...) { return L"Unknown exception"; }
}

void requireWin32(BOOL result, const wchar_t* operation) {
    if (!result) throw hresult_error(HRESULT_FROM_WIN32(GetLastError()), operation);
}

std::string loadComputerId() {
    HKEY key = nullptr;
    const auto opened = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\UnlockWindowsWithIPhone\\GattHost",
        0, nullptr, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &key, nullptr);
    if (opened != ERROR_SUCCESS) throw hresult_error(HRESULT_FROM_WIN32(opened), L"Open persistent computer ID");
    struct RegistryKey final {
        HKEY value;
        ~RegistryKey() { RegCloseKey(value); }
    } registry{key};
    GUID id{};
    DWORD size = sizeof(id);
    const auto read = RegGetValueW(key, nullptr, L"ComputerId", RRF_RT_REG_BINARY, nullptr, &id, &size);
    if (read == ERROR_FILE_NOT_FOUND) {
        check_hresult(CoCreateGuid(&id));
        const auto written = RegSetValueExW(key, L"ComputerId", 0, REG_BINARY,
            reinterpret_cast<const BYTE*>(&id), sizeof(id));
        if (written != ERROR_SUCCESS) throw hresult_error(HRESULT_FROM_WIN32(written), L"Save persistent computer ID");
        const auto flushed = RegFlushKey(key);
        if (flushed != ERROR_SUCCESS) throw hresult_error(HRESULT_FROM_WIN32(flushed), L"Flush persistent computer ID");
    } else {
        if (read != ERROR_SUCCESS) throw hresult_error(HRESULT_FROM_WIN32(read), L"Read persistent computer ID");
        if (size != sizeof(id) || IsEqualGUID(id, GUID{}))
            throw hresult_error(E_FAIL, L"Stored computer ID is invalid; refusing to replace the registered identity");
    }
    wchar_t text[39]{};
    if (StringFromGUID2(id, text, 39) != 39) throw hresult_error(E_FAIL, L"Format persistent computer ID");
    return to_string(hstring(text + 1, 36));
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
    explicit GattHost(std::shared_ptr<CallbackState> state) : state_(std::move(state)) {}
    GattHost(const GattHost&) = delete;
    GattHost& operator=(const GattHost&) = delete;

    std::function<void(const std::vector<std::uint8_t>&, const GattSession&, ULONGLONG)> enrollmentRequest;
    bool pairingActive = false;

    std::wstring connectionSummary() const {
        if (!initialized_) return L"iPhone connection: unavailable.";
        for (const auto& client : challengeCharacteristic_.SubscribedClients())
            if (subscriber(client.Session())) return readiness_.ready(GetTickCount64()) || authenticationSession_
                ? L"iPhone connection: unlock channel ready." : L"iPhone connection: waiting for channel confirmation.";
        if (challengeCharacteristic_.SubscribedClients().Size() || resultCharacteristic_.SubscribedClients().Size())
            return L"iPhone connection: preparing unlock channel.";
        return L"iPhone connection: waiting for your iPhone.";
    }

    GattSubscribedClient subscriber(const GattSession& session) const {
        if (!session || session.SessionStatus() != GattSessionStatus::Active) return nullptr;
        for (const auto& client : resultCharacteristic_.SubscribedClients())
            if (client.Session().DeviceId().Id() == session.DeviceId().Id()) return client;
        return nullptr;
    }

    void enrollmentResult(const GattSession& session, const char* status, bool savedReloadFailed = false) {
        const auto client = subscriber(session);
        if (!client) {
            state_->record(L"Enrollment result unavailable: initiating client is no longer subscribed", true);
            return;
        }
        const std::string json = std::string("{\"authenticated\":false,\"status\":\"") + status + "\"" +
            (savedReloadFailed ? ",\"detail\":\"saved_reload_failed\"" : "") + "}";
        const auto result = resultCharacteristic_.NotifyValueAsync(makeBuffer(json), client).get();
        if (result.Status() != GattCommunicationStatus::Success)
            state_->record(L"Enrollment notification status=" + std::to_wstring(static_cast<int>(result.Status())), true);
    }

    void initialize(std::function<void()> statusChanged) {
        const auto computerId = loadComputerId();
        const auto serviceResult = GattServiceProvider::CreateAsync(
            guid(kServiceUuid)
        ).get();
        if (serviceResult.Error() != winrt::Windows::Devices::Bluetooth::BluetoothError::Success) {
            throw hresult_error(E_FAIL, hstring(L"GattServiceProvider::CreateAsync BluetoothError=" +
                std::to_wstring(static_cast<int>(serviceResult.Error()))));
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
        GattLocalCharacteristicParameters identityParameters;
        identityParameters.CharacteristicProperties(GattCharacteristicProperties::Read);
        identityParameters.ReadProtectionLevel(GattProtectionLevel::Plain);
        identityParameters.StaticValue(makeBuffer(computerId));
        const auto identityResult = serviceProvider_.Service().CreateCharacteristicAsync(
            guid(kComputerIdCharacteristicUuid), identityParameters).get();
        if (identityResult.Error() != winrt::Windows::Devices::Bluetooth::BluetoothError::Success)
            throw hresult_error(E_FAIL, hstring(L"Computer ID characteristic BluetoothError=" +
                std::to_wstring(static_cast<int>(identityResult.Error()))));
        computerIdCharacteristic_ = identityResult.Characteristic();

        requestWriteToken_ = requestCharacteristic_.WriteRequested(
            [state = state_, this](GattLocalCharacteristic const&, GattWriteRequestedEventArgs const& args) {
                finishRequest(state, args, [this](const std::vector<std::uint8_t>& bytes, const GattSession& session, ULONGLONG receivedAt) {
                    handleRequestWrite(bytes, session, receivedAt);
                });
            }
        );
        assertionWriteToken_ = assertionCharacteristic_.WriteRequested(
            [state = state_, this](GattLocalCharacteristic const&, GattWriteRequestedEventArgs const& args) {
                finishRequest(state, args, [this](const std::vector<std::uint8_t>& bytes, const GattSession& session, ULONGLONG) {
                    if (!pairingActive && isAuthenticationSession(session)) handleAssertionWrite(bytes);
                    else state_->record(L"Authentication assertion rejected during pairing", false);
                });
            }
        );
        const auto subscriptionsChanged =
            [this, state = state_](GattLocalCharacteristic const& characteristic, winrt::Windows::Foundation::IInspectable const&) {
                try {
                    std::vector<std::wstring> peers;
                    for (const auto& client : characteristic.SubscribedClients())
                        peers.emplace_back(client.Session().DeviceId().Id());
                    state->post([this, state, peers = std::move(peers)] {
                        LogLine(state, false) << "[GattHost] notification subscribers=" << peers.size()
                            << " generation=" << transportGeneration_;
                        if (!watchedSession_) return;
                        const std::wstring peer(watchedSession_.DeviceId().Id());
                        if (std::find(peers.begin(), peers.end(), peer) != peers.end()) return;
                        try { if (authenticationSession_ && GetTickCount64() < authenticationDeadline_) reportFailure(4); }
                        catch (...) { state->record(L"Subscription loss report: " + exceptionText(), true); }
                        invalidateTransport(L"selected notification subscription lost");
                    });
                } catch (...) { state->record(exceptionText(), true); }
            };
        challengeSubscriptionToken_ = challengeCharacteristic_.SubscribedClientsChanged(subscriptionsChanged);
        resultSubscriptionToken_ = resultCharacteristic_.SubscribedClientsChanged(subscriptionsChanged);

        advertisementStatusToken_ = serviceProvider_.AdvertisementStatusChanged(
            [this, state = state_, statusChanged](
                GattServiceProvider const&,
                GattServiceProviderAdvertisementStatusChangedEventArgs const& args
            ) {
                try {
                    const auto status = args.Status();
                    const auto error = args.Error();
                    state->post([this, state, statusChanged, status, error] {
                        LogLine(state, false) << "[GattHost] advertisement event status=" << static_cast<int>(status)
                            << " error=" << static_cast<int>(error) << " generation=" << transportGeneration_;
                        if (error != winrt::Windows::Devices::Bluetooth::BluetoothError::Success)
                            state->record(L"Advertisement BluetoothError=" + std::to_wstring(static_cast<int>(error)), true);
                        statusChanged();
                    });
                } catch (...) { state->record(L"Advertisement callback: " + exceptionText(), true); }
            }
        );

        initialized_ = true;
    }

    bool initialized() const { return initialized_; }
    GattServiceProviderAdvertisementStatus status() const { return serviceProvider_.AdvertisementStatus(); }

    void advertise(bool enabled) {
        using Action = unlock_windows::gatt::AdvertisingLifecycle::Action;
        const auto now = GetTickCount64();
        if (advertising_.desired() != enabled || transportPairing_ != pairingActive) {
            invalidateTransport(L"publication target or pairing changed");
            transportPairing_ = pairingActive;
        }
        advertising_.desire(enabled);
        const auto action = advertising_.advance(now, static_cast<int>(status()));
        if (action != Action::none) {
            invalidateTransport(action == Action::start ? L"publication starting" : L"publication stopping");
            LogLine(state_, false) << "[GattHost] publication command=" << (action == Action::start ? "start" : "stop")
                << " generation=" << transportGeneration_ << " retry=" << advertising_.retries();
            bool accepted = false;
            try {
                if (action == Action::stop) serviceProvider_.StopAdvertising();
                else {
                    GattServiceProviderAdvertisingParameters parameters;
                    parameters.IsDiscoverable(true);
                    parameters.IsConnectable(true);
                    serviceProvider_.StartAdvertising(parameters);
                }
                advertising_.commandSucceeded(action);
                accepted = true;
            } catch (...) {
                advertising_.commandFailed(now, action);
                state_->record(L"Publication command: " + exceptionText(), true);
            }
            if (accepted) LogLine(state_, false) << "[GattHost] publication command accepted="
                << (action == Action::start ? "start" : "stop") << " generation=" << transportGeneration_
                << " rawStatus=" << static_cast<int>(status());
        }
        if (advertising_.failures() != loggedAdvertisingFailures_) {
            loggedAdvertisingFailures_ = advertising_.failures();
            invalidateTransport(L"publication failed");
            state_->record(advertisingError(), true);
        }
    }

    void retryAdvertising() { advertising_.refresh(); }

    bool advertisingReady() const {
        return advertising_.desired() && advertising_.started() &&
            status() == GattServiceProviderAdvertisementStatus::Started;
    }

    bool advertisingExhausted() const { return advertising_.exhausted(); }
    bool advertisingStopped() const { return advertising_.stopped(); }

    std::wstring advertisingError() const {
        using Failure = unlock_windows::gatt::AdvertisingLifecycle::Failure;
        const wchar_t* text = L"Bluetooth publication failed";
        switch (advertising_.failure()) {
        case Failure::startTimeout: text = L"Bluetooth publication did not start within 5 seconds"; break;
        case Failure::startException: text = L"Bluetooth publication start failed; see the original error in history"; break;
        case Failure::aborted: text = L"Bluetooth publication was interrupted"; break;
        case Failure::incomplete: text = L"Bluetooth publication is missing advertisement data"; break;
        case Failure::stopException: text = L"Bluetooth publication stop failed; see the original error in history"; break;
        case Failure::none: return {};
        }
        return std::wstring(text) + L"; status=" + std::to_wstring(static_cast<int>(status())) +
            L"; retries=" + std::to_wstring(advertising_.retries()) +
            (advertising_.exhausted() ? L"; open Status and choose Refresh" : L"; automatic recovery pending");
    }

    void invalidateTransport(const wchar_t* reason) {
        ++transportGeneration_;
        if (watchedSession_ && sessionStatusToken_.value) {
            watchedSession_.SessionStatusChanged(sessionStatusToken_);
            sessionStatusToken_ = {};
        }
        watchedSession_ = nullptr;
        readiness_.clear();
        preparationSession_ = nullptr;
        authenticationSession_ = nullptr;
        authenticationRequestId_.clear();
        authenticationDeadline_ = 0;
        LogLine(state_, false) << "[GattHost] transport invalidated generation=" << transportGeneration_
            << " reason=" << to_string(hstring(reason));
    }

    void shutdown() {
        {
            std::lock_guard lock(state_->mutex);
            state_->accepting = false;
        }
        auto cleanup = [this](auto action) {
            try { action(); } catch (...) { state_->record(L"Shutdown: " + exceptionText(), true); }
        };
        if (serviceProvider_) {
            cleanup([this] {
                invalidateTransport(L"exit");
                advertising_.desire(false);
                if (!advertising_.stopped() && status() != GattServiceProviderAdvertisementStatus::Created &&
                    status() != GattServiceProviderAdvertisementStatus::Stopped) serviceProvider_.StopAdvertising();
            });
            if (advertisementStatusToken_.value) cleanup([this] { serviceProvider_.AdvertisementStatusChanged(advertisementStatusToken_); });
        }
        if (requestCharacteristic_ && requestWriteToken_.value)
            cleanup([this] { requestCharacteristic_.WriteRequested(requestWriteToken_); });
        if (assertionCharacteristic_ && assertionWriteToken_.value)
            cleanup([this] { assertionCharacteristic_.WriteRequested(assertionWriteToken_); });
        if (challengeCharacteristic_ && challengeSubscriptionToken_.value)
            cleanup([this] { challengeCharacteristic_.SubscribedClientsChanged(challengeSubscriptionToken_); });
        if (resultCharacteristic_ && resultSubscriptionToken_.value)
            cleanup([this] { resultCharacteristic_.SubscribedClientsChanged(resultSubscriptionToken_); });
        std::unique_lock lock(state_->mutex);
        state_->drained.wait(lock, [this] { return state_->activeWrites == 0; });
        state_->pending.clear();
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
            throw hresult_error(E_FAIL, hstring(L"GattLocalService::CreateCharacteristicAsync BluetoothError=" +
                std::to_wstring(static_cast<int>(result.Error()))));
        }
        return result.Characteristic();
    }

    static fire_and_forget finishRequest(
        std::shared_ptr<CallbackState> state,
        GattWriteRequestedEventArgs args,
        std::function<void(const std::vector<std::uint8_t>&, const GattSession&, ULONGLONG)> handler
    ) {
        const ULONGLONG receivedAt = GetTickCount64();
        {
            std::lock_guard lock(state->mutex);
            if (!state->accepting) co_return;
            ++state->activeWrites;
        }
        struct WriteLease final {
            std::shared_ptr<CallbackState> state;
            ~WriteLease() {
                std::lock_guard lock(state->mutex);
                --state->activeWrites;
                state->drained.notify_all();
            }
        } lease{state};
        winrt::Windows::Foundation::Deferral deferral{nullptr};
        try {
            deferral = args.GetDeferral();
            auto request = co_await args.GetRequestAsync();
            if (request) {
                auto bytes = readBuffer(request.Value());
                const auto session = args.Session();
                if (request.Option() == GattWriteOption::WriteWithResponse) {
                    request.Respond();
                }
                state->post([state, bytes = std::move(bytes), session, receivedAt, handler = std::move(handler)] {
                    try { handler(bytes, session, receivedAt); }
                    catch (...) { state->record(L"GATT write handler: " + exceptionText(), true); }
                });
            }
        } catch (...) { state->record(L"GATT write request: " + exceptionText(), true); }
        if (deferral) {
            try { deferral.Complete(); }
            catch (...) { state->record(L"GATT deferral: " + exceptionText(), true); }
        }
    }

    void handleRequestWrite(const std::vector<std::uint8_t>& bytes, const GattSession& session, ULONGLONG receivedAt) {
        if (!bytes.empty() && bytes.front() == unlock_windows::gatt::TransportReadiness::readyRequest) {
            using namespace unlock_windows::saved_credential;
            AuthenticationStatus current;
            if (preparationSession_ && (!subscriber(preparationSession_) || !challengeSubscriber(preparationSession_)))
                invalidateTransport(L"preparation connection no longer active");
            const bool subscribed = session && subscriber(session) && challengeSubscriber(session);
            if (pairingActive || !advertisingReady() || !subscribed || !peekAuthentication(current) ||
                current.stage != AuthenticationStage::waitingPhone || current.requestId != readiness_.request() ||
                !readiness_.acknowledge(bytes, std::wstring(session.DeviceId().Id()), transportGeneration_, GetTickCount64(), receivedAt)) {
                state_->record(L"Ready acknowledgment rejected: stale request, frame, connection or publication", true);
                return;
            }
            LogLine(state_, false) << "[GattHost] ready acknowledged requestID=" << current.requestId
                << " generation=" << transportGeneration_ << " receivedTickMs=" << receivedAt;
            return;
        }
        if (!bytes.empty() && bytes.front() == kEnrollmentRequest) {
            enrollmentRequest(bytes, session, receivedAt);
            return;
        }
        if (bytes.size() == 38 && bytes.front() == kRejectRequest && isAuthenticationSession(session) &&
            std::string(bytes.begin() + 1, bytes.begin() + 37) == authenticationRequestId_ &&
            (bytes.back() == 1 || bytes.back() == 2 || bytes.back() == 3 || bytes.back() == 4 || bytes.back() == 6)) {
            reportFailure(bytes.back());
            return;
        }
        LogLine(state_, true) << "[GattHost] rejected request frame, got " << bytes.size() << " byte(s)\n";
    }

    bool isAuthenticationSession(const GattSession& session) const {
        return authenticationSession_ && session && GetTickCount64() < authenticationDeadline_ &&
            authenticationSession_.DeviceId().Id() == session.DeviceId().Id();
    }

    void reportFailure(std::uint8_t reason) {
        using namespace unlock_windows::saved_credential;
        const auto session = authenticationSession_;
        const auto requestId = authenticationRequestId_;
        authenticationSession_ = nullptr;
        authenticationRequestId_.clear();
        SensitiveBytes request;
        request.value.assign(requestId.begin(), requestId.end());
        request.value.push_back(reason);
        Packet response;
        CallDiagnostics diagnostics;
        if (!callPhone(Operation::reportPhoneFailure, std::move(request), response, 250, &diagnostics) ||
            response.result != Result::success) {
            LogLine(state_, true) << "[GattHost] failure report failed, stage="
                << to_string(callStageName(diagnostics.stage)) << " win32=" << diagnostics.win32Error;
        }
        if (session) {
            const auto client = subscriber(session);
            if (client) {
                const char* status = reason == 1 ? "rssi_too_low" : reason == 2 ? "automatic_disabled" :
                    reason == 3 ? "rssi_unavailable" : reason == 6 ? "signing_failed" : "transport_failed";
                const std::string json = std::string("{\"authenticated\":false,\"status\":\"") + status +
                    "\",\"requestID\":\"" + requestId + "\"}";
                const auto notification = resultCharacteristic_.NotifyValueAsync(makeBuffer(json), client).get();
                if (notification.Status() != GattCommunicationStatus::Success)
                    state_->record(L"Phone rejection result delivery failed", true);
            }
        }
    }

public:
    void pollAuthentication() {
        using namespace unlock_windows::saved_credential;
        if (pairingActive || !advertisingReady()) return;
        if (authenticationSession_ && GetTickCount64() < authenticationDeadline_ &&
            (!subscriber(authenticationSession_) || !challengeSubscriber(authenticationSession_))) {
            reportFailure(4);
            invalidateTransport(L"authentication subscription lost");
        }
        if (preparationSession_ && (!subscriber(preparationSession_) || !challengeSubscriber(preparationSession_)))
            invalidateTransport(L"preparation subscription lost");
        AuthenticationStatus current;
        if (!peekAuthentication(current)) return;
        if (current.stage != AuthenticationStage::waitingPhone) {
            if (current.stage == AuthenticationStage::awaitingAssertion) return;
            const auto session = authenticationSession_ ? authenticationSession_ : preparationSession_;
            const auto request = authenticationSession_ ? authenticationRequestId_ : readiness_.request();
            if (session && current.stage == AuthenticationStage::failed && current.requestId == request) {
                const auto client = subscriber(session);
                if (client) {
                    const char* code = current.failure == AuthenticationFailure::expired ? "challenge_expired" :
                        current.failure == AuthenticationFailure::sessionChanged ? "session_changed" : "phone_rejected";
                    const std::string json = std::string("{\"authenticated\":false,\"status\":\"") + code +
                        "\",\"requestID\":\"" + request + "\"}";
                    const auto sent = resultCharacteristic_.NotifyValueAsync(makeBuffer(json), client).get();
                    if (sent.Status() != GattCommunicationStatus::Success)
                        state_->record(L"Authentication failure result delivery failed", true);
                }
                state_->record(authenticationStatusText(current), true);
            }
            if (session || watchedSession_ || !readiness_.request().empty()) invalidateTransport(L"request ended");
            return;
        }
        GattSubscribedClient target{nullptr};
        for (const auto& client : challengeCharacteristic_.SubscribedClients()) {
            if (!subscriber(client.Session())) continue;
            if (target) {
                if (preparationSession_) invalidateTransport(L"multiple subscribed connections");
                return;
            }
            target = client;
        }
        if (!target) {
            if (preparationSession_) invalidateTransport(L"preparation subscription lost");
            return;
        }
        if (preparationSession_ && preparationSession_.DeviceId().Id() != target.Session().DeviceId().Id())
            invalidateTransport(L"preparation connection changed");
        const auto now = GetTickCount64();
        if (!readiness_.prepare(current.requestId, std::wstring(target.Session().DeviceId().Id()),
            transportGeneration_, current.deadline, now)) return;
        preparationSession_ = target.Session();
        watchConnection(preparationSession_);
        if (!readiness_.ready(now)) {
            if (!readiness_.probeDue(now)) return;
            const std::string json = "{\"authenticated\":false,\"status\":\"transport_ready_required\",\"requestID\":\"" +
                current.requestId + "\"}";
            bool sent = false;
            try {
                const auto client = subscriber(target.Session());
                const auto result = resultCharacteristic_.NotifyValueAsync(makeBuffer(json), client).get();
                sent = result.Status() == GattCommunicationStatus::Success;
                LogLine(state_, !sent) << "[GattHost] ready probe requestID=" << current.requestId
                    << " generation=" << transportGeneration_ << " status=" << static_cast<int>(result.Status());
            } catch (...) { state_->record(L"Ready probe delivery: " + exceptionText(), true); }
            readiness_.probeAttempted(now, sent);
            return;
        }
        Packet response;
        CallDiagnostics diagnostics;
        if (!callPhone(Operation::takePhoneChallenge, SensitiveBytes{}, response, 250, &diagnostics)) {
            const auto error = diagnostics.win32Error;
            if (error != lastAuthenticationIpcError_) {
                LogLine(state_, true) << "[GattHost] challenge polling failed, stage="
                    << to_string(callStageName(diagnostics.stage)) << " win32=" << error;
            }
            lastAuthenticationIpcError_ = error;
            return;
        }
        lastAuthenticationIpcError_ = NO_ERROR;
        if (response.result != Result::success) {
            LogLine(state_, true) << "[GattHost] challenge polling rejected, service result="
                << static_cast<unsigned>(response.result);
            return;
        }
        PhoneChallengePayload challenge;
        if (!decodePhoneChallenge(response.payload.value.data(), response.payload.value.size(), challenge)) {
            throw std::runtime_error("Invalid structured phone challenge frame");
        }
        if (challenge.json.empty()) return;
        if (challenge.status.requestId != readiness_.request() || challenge.status.deadline != current.deadline ||
            challenge.status.stage != AuthenticationStage::awaitingAssertion) {
            invalidateTransport(L"challenge no longer matches readiness");
            throw std::runtime_error("Challenge changed after readiness confirmation");
        }
        authenticationRequestId_ = challenge.status.requestId;
        authenticationDeadline_ = challenge.status.deadline;
        if (GetTickCount64() >= authenticationDeadline_) return;
        authenticationSession_ = target.Session();
        readiness_.clear();
        preparationSession_ = nullptr;
        try {
            const auto now = GetTickCount64();
            LogLine(state_, false) << "[GattHost] challenge delivery attempt requestID=" << authenticationRequestId_
                << " generation=" << transportGeneration_ << " subscriptions=2 remainingMs="
                << (now < authenticationDeadline_ ? authenticationDeadline_ - now : 0);
            const auto result = challengeCharacteristic_.NotifyValueAsync(makeBuffer(challenge.json), target).get();
            LogLine(state_, result.Status() != GattCommunicationStatus::Success)
                << "[GattHost] challenge delivery completed requestID=" << authenticationRequestId_
                << " generation=" << transportGeneration_ << " status=" << static_cast<int>(result.Status());
            if (result.Status() != GattCommunicationStatus::Success) {
                LogLine(state_, true) << "[GattHost] challenge delivery status=" << static_cast<int>(result.Status());
                reportFailure(5);
            }
        } catch (...) {
            state_->record(L"Challenge delivery: " + exceptionText(), true);
            reportFailure(5);
        }
    }

private:
    void watchConnection(const GattSession& session) {
        if (watchedSession_) return;
        const auto generation = transportGeneration_;
        sessionStatusToken_ = session.SessionStatusChanged([this, state = state_, generation](const GattSession&,
            const GattSessionStatusChangedEventArgs& args) {
            try {
                const auto status = args.Status();
                state->post([this, state, generation, status] {
                    LogLine(state, false) << "[GattHost] connection status=" << static_cast<int>(status)
                        << " generation=" << generation;
                    if (generation != transportGeneration_ || status == GattSessionStatus::Active) return;
                    try { if (authenticationSession_ && GetTickCount64() < authenticationDeadline_) reportFailure(4); }
                    catch (...) { state->record(L"Disconnection report: " + exceptionText(), true); }
                    invalidateTransport(L"selected connection disconnected");
                });
            } catch (...) { state->record(L"Connection status callback: " + exceptionText(), true); }
        });
        watchedSession_ = session;
    }

    bool challengeSubscriber(const GattSession& session) const {
        if (!session || session.SessionStatus() != GattSessionStatus::Active) return false;
        for (const auto& client : challengeCharacteristic_.SubscribedClients())
            if (client.Session().DeviceId().Id() == session.DeviceId().Id()) return true;
        return false;
    }

    bool peekAuthentication(unlock_windows::saved_credential::AuthenticationStatus& current) {
        using namespace unlock_windows::saved_credential;
        Packet response;
        CallDiagnostics diagnostics;
        if (!callPhone(Operation::peekPhoneAuthentication, SensitiveBytes{}, response, 250, &diagnostics)) {
            if (diagnostics.win32Error != lastAuthenticationIpcError_)
                LogLine(state_, true) << "[GattHost] status peek failed stage=" << to_string(callStageName(diagnostics.stage))
                    << " win32=" << diagnostics.win32Error;
            lastAuthenticationIpcError_ = diagnostics.win32Error;
            return false;
        }
        lastAuthenticationIpcError_ = NO_ERROR;
        if (response.result != Result::success) {
            LogLine(state_, true) << "[GattHost] status peek rejected result=" << static_cast<unsigned>(response.result);
            return false;
        }
        if (!decodeAuthenticationStatus(response.payload.value.data(), response.payload.value.size(), current))
            throw std::runtime_error("Invalid phone authentication status frame");
        return true;
    }

    void handleAssertionWrite(const std::vector<std::uint8_t>& bytes) {
        if (bytes.empty() || bytes.size() > kMaxTransportFrameSize) {
            LogLine(state_, true) << "[GattHost] rejected assertion frame length=" << bytes.size() << "\n";
            return;
        }

        LogLine(state_, false) << "[GattHost] assertion frame received, length=" << bytes.size() << "\n";
        unlock_windows::saved_credential::SensitiveBytes assertion;
        assertion.value = bytes;
        unlock_windows::saved_credential::Packet response;
        unlock_windows::saved_credential::CallDiagnostics diagnostics;
        const bool received = unlock_windows::saved_credential::callPhone(
            unlock_windows::saved_credential::Operation::submitPhoneAssertion,
            std::move(assertion), response, 2000, &diagnostics);
        if (!received || response.result != unlock_windows::saved_credential::Result::success ||
            response.payload.value.empty()) {
            LogLine(state_, true) << "[GattHost] signed assertion was not accepted by saved-credential service\n";
            if (!received) {
                LogLine(state_, true) << "[GattHost] IPC stage="
                    << to_string(unlock_windows::saved_credential::callStageName(diagnostics.stage))
                    << " check=" << to_string(diagnostics.serverCheck)
                    << " win32=" << diagnostics.win32Error << "\n";
            }
        } else {
            LogLine(state_, false) << "[GattHost] signed assertion result received from service\n";
        }

        const char* failure = !received ? "service_unavailable" :
            response.result == unlock_windows::saved_credential::Result::rejected ? "not_ready" : "service_error";
        std::string result = received && response.result == unlock_windows::saved_credential::Result::success &&
            !response.payload.value.empty()
            ? bytesAsText(response.payload.value)
            : std::string("{\"authenticated\":false,\"status\":\"") + failure + "\"}";
        if (result.find("request_mismatch") != std::string::npos) {
            state_->record(L"Ignoring assertion for a different request", true);
            return;
        }
        if (!result.empty() && result.back() == '}') {
            result.pop_back();
            result += ",\"requestID\":\"" + authenticationRequestId_ + "\"}";
        }
        const auto session = authenticationSession_;
        authenticationSession_ = nullptr;
        authenticationRequestId_.clear();
        if (session) {
            const auto client = subscriber(session);
            if (client) {
                const auto notification = resultCharacteristic_.NotifyValueAsync(makeBuffer(result), client).get();
                if (notification.Status() != GattCommunicationStatus::Success)
                    LogLine(state_, true) << "[GattHost] result delivery status=" << static_cast<int>(notification.Status());
            } else state_->record(L"Authentication result subscriber disconnected", true);
        }
        invalidateTransport(L"assertion result delivered or failed");
    }

    std::shared_ptr<CallbackState> state_;
    GattSession authenticationSession_{nullptr};
    GattSession watchedSession_{nullptr};
    event_token sessionStatusToken_{};
    std::string authenticationRequestId_;
    ULONGLONG authenticationDeadline_ = 0;
    DWORD lastAuthenticationIpcError_ = NO_ERROR;
    bool initialized_ = false;
    unlock_windows::gatt::AdvertisingLifecycle advertising_;
    unlock_windows::gatt::TransportReadiness readiness_;
    std::uint64_t loggedAdvertisingFailures_ = 0;
    std::uint64_t transportGeneration_ = 0;
    bool transportPairing_ = false;
    GattSession preparationSession_{nullptr};
    GattServiceProvider serviceProvider_{nullptr};
    GattLocalCharacteristic requestCharacteristic_{nullptr};
    GattLocalCharacteristic challengeCharacteristic_{nullptr};
    GattLocalCharacteristic assertionCharacteristic_{nullptr};
    GattLocalCharacteristic resultCharacteristic_{nullptr};
    GattLocalCharacteristic computerIdCharacteristic_{nullptr};
    event_token requestWriteToken_{};
    event_token assertionWriteToken_{};
    event_token challengeSubscriptionToken_{};
    event_token resultSubscriptionToken_{};
    event_token advertisementStatusToken_{};
};

class GattControl final {
public:
    explicit GattControl(std::shared_ptr<CallbackState> state) : state_(std::move(state)), host_(state_) {
        host_.enrollmentRequest = [this](const auto& bytes, const auto& session, ULONGLONG receivedAt) {
            receiveEnrollment(bytes, session, receivedAt);
        };
    }
    ~GattControl() { close(); }

    void run(HINSTANCE instance) {
        if (state_->stopping()) return;
        requireWin32(ProcessIdToSessionId(GetCurrentProcessId(), &session_), L"ProcessIdToSessionId");
        WNDCLASSW windowClass{};
        windowClass.hInstance = instance;
        windowClass.lpszClassName = kControlWindowClass;
        windowClass.lpfnWndProc = windowProcedure;
        requireWin32(RegisterClassW(&windowClass), L"RegisterClassW(GATT control)");
        window_ = CreateWindowExW(0, windowClass.lpszClassName, UNLOCK_PRODUCT_DISPLAY_NAME,
            0, 0, 0, 0, 0, nullptr, nullptr, instance, this);
        if (!window_) requireWin32(FALSE, L"CreateWindowExW(GATT control)");
        {
            std::lock_guard lock(state_->mutex);
            state_->window = window_;
            state_->control = this;
        }
        requireWin32(WTSRegisterSessionNotification(window_, NOTIFY_FOR_ALL_SESSIONS),
            L"WTSRegisterSessionNotification");
        sessionRegistered_ = true;
        if (!SetTimer(window_, 1, 1000, nullptr)) requireWin32(FALSE, L"SetTimer");
        {
            std::lock_guard lock(state_->mutex);
            state_->controlReady = true;
        }
        state_->notify();
        if (state_->stopping()) { close(); return; }
        try { host_.initialize([this] { reconcile(false); }); }
        catch (...) {
            initializationError_ = exceptionText();
            state_->record(L"GATT initialization: " + initializationError_, true);
        }
        initializing_ = false;
        if (state_->stopping()) { close(); return; }
        reconcile(true);
        publishDashboard();
        requireWin32(PostMessageW(window_, kDispatch, 0, 0), L"Dispatch pending GATT requests");
        MSG message{};
        BOOL result;
        while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (result == -1) requireWin32(FALSE, L"GetMessageW");
    }

    void execute(unlock_windows::desktop_app::TrayCommand command) {
        using unlock_windows::desktop_app::TrayCommand;
        if (state_->stopping()) return;
        try {
            if (!host_.initialized() && command != TrayCommand::status)
                throw std::runtime_error("GATT initialization failed; the requested operation cannot start. Restart the EXE.");
            switch (command) {
            case TrayCommand::status: reconcile(true); break;
            case TrayCommand::continueSetup: continueSetup(); break;
            case TrayCommand::pairPhone: startPairing(); break;
            case TrayCommand::removePhone: startPairing(true); break;
            }
        } catch (...) {
            const auto error = exceptionText();
            state_->record(L"Desktop request: " + error, true);
            state_->notice(error, L"Requested operation could not start", MB_OK | MB_ICONERROR);
        }
    }
private:
    struct Pairing final {
        unlock_windows::enrollment::Console target;
        ULONGLONG deadline = 0;
        bool remove = false;
        bool helperReady = false;
        DWORD helperPid = 0;
        std::wstring channelName;
        std::unique_ptr<unlock_windows::enrollment::EnrollmentChannel> channel;
        std::wstring eventName;
        unlock_windows::enrollment::Handle cancel;
        GattSession session{nullptr};
        event_token sessionToken{};
    };

    void startPairing(bool remove = false) {
        try {
            if (pairing_ || launchOutstanding_) throw std::runtime_error("Previous pairing is still active; cancel or wait for its window to close");
            if (!host_.initialized()) throw std::runtime_error("GATT initialization failed; restart the EXE");
            const auto target = unlock_windows::enrollment::queryConsole();
            if (target.locked || target.session != session_ || suspended_ || endingSession_ ||
                target.sid != unlock_windows::phone_approval::EnrollmentStore::currentUserSid() ||
                unlock_windows::enrollment::elevatedAdmin())
                throw std::runtime_error("Pairing requires the unlocked physical console user running without elevation");
            std::wstring executable(32768, L'\0');
            const DWORD size = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
            if (!size || size >= executable.size()) throw std::runtime_error("GetModuleFileNameW failed");
            executable.resize(size);
            const std::filesystem::path helper(executable);
            const DWORD attributes = GetFileAttributesW(helper.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
                throw std::runtime_error("The main application executable is unavailable");
            auto job = std::make_shared<Pairing>();
            job->target = target;
            job->deadline = GetTickCount64() + unlock_windows::enrollment::kPairingLifetime;
            job->remove = remove;
            std::array<std::uint8_t, 16> random{};
            if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
                throw std::runtime_error("Pairing event random generation failed");
            job->eventName = unlock_windows::enrollment::kCancelPrefix;
            constexpr wchar_t hex[] = L"0123456789abcdef";
            for (auto byte : random) { job->eventName += hex[byte >> 4]; job->eventName += hex[byte & 15]; }
            const std::wstring acl = L"D:P(A;;GA;;;SY)(A;;0x00100000;;;BA)(A;;GA;;;" + target.sid + L")";
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            requireWin32(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1,
                &descriptor, nullptr), L"Pairing cancellation event ACL");
            SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
            job->cancel.value = CreateEventW(&security, TRUE, FALSE, job->eventName.c_str());
            const DWORD error = GetLastError();
            LocalFree(descriptor);
            if (!job->cancel.value) { SetLastError(error); requireWin32(FALSE, L"CreateEventW(pairing cancellation)"); }
            if (error == ERROR_ALREADY_EXISTS) throw std::runtime_error("Pairing cancellation event already exists");
            if (!remove) {
                job->channelName = std::wstring(unlock_windows::enrollment::kChannelPrefix) +
                    job->eventName.substr(std::wstring_view(unlock_windows::enrollment::kCancelPrefix).size());
                job->channel = std::make_unique<unlock_windows::enrollment::EnrollmentChannel>(job->channelName, target.sid);
            }
            helperPath_ = helper.wstring();
            pairing_ = job;
            host_.pairingActive = true;
            pairingOutcome_ = L"";
            state_->record(L"Pairing opened by local user; fixed 120-second lifetime", false);
            reconcile(true);
            if (pairing_ == job) launchHelper(job, std::wstring(unlock_windows::desktop_app::kBluetoothRole) + L" " + (remove ? std::wstring(L"clear remove ") :
                job->channelName + L" pair ") + lifetimeArguments(job));
        } catch (...) {
            const auto error = exceptionText();
            state_->record(L"Pairing start: " + error, true);
            finishPairing("enrollment_error");
            state_->notice(error.c_str(), L"Could not start iPhone pairing", MB_OK | MB_ICONERROR);
        }
    }

    void finishPairing(const char* result, bool savedReloadFailed = false) {
        if (!pairing_) return;
        auto job = pairing_;
        requireWin32(SetEvent(job->cancel.value), L"SetEvent(pairing cancellation)");
        if (job->session && job->sessionToken.value) {
            job->session.SessionStatusChanged(job->sessionToken);
            job->sessionToken = {};
        }
        pairing_.reset();
        host_.pairingActive = false;
        pairingOutcome_ = std::wstring(to_hstring(result));
        if (savedReloadFailed) pairingOutcome_ += job->remove ? L": registration removed, service reload failed" : L": registration saved, service reload failed";
        state_->record(L"Pairing finished: " + pairingOutcome_, savedReloadFailed || std::string_view(result) == "enrollment_error");
        const bool guided = std::exchange(setupPairing_, false);
        if (job->session) {
            try { host_.enrollmentResult(job->session, result, savedReloadFailed); }
            catch (...) { state_->record(L"Pairing result notification: " + exceptionText(), true); }
        }
        if (guided && !job->remove && !savedReloadFailed &&
            (std::string_view(result) == "enrollment_saved" || std::string_view(result) == "enrollment_already_registered"))
            state_->notice(L"Setup is configured. Lock this PC to test iPhone unlock. Windows has not yet verified the saved password.",
                L"Setup configured", MB_OK | MB_ICONINFORMATION);
    }

    void checkPairing() {
        if (!pairing_) return;
        if (GetTickCount64() >= pairing_->deadline) { finishPairing("enrollment_expired"); return; }
        const auto target = unlock_windows::enrollment::queryConsole();
        if (target.locked || target.session != pairing_->target.session || target.sid != pairing_->target.sid ||
            suspended_ || endingSession_) { finishPairing("enrollment_cancelled"); return; }
        if (pairing_->session && (pairing_->session.SessionStatus() != GattSessionStatus::Active ||
            !host_.subscriber(pairing_->session))) finishPairing("enrollment_cancelled");
        if (pairing_ && pairing_->channel) {
            try {
                if (!pairing_->helperReady && pairing_->channel->ready(pairing_->helperPid)) {
                    pairing_->helperReady = true;
                    state_->record(L"Pairing role ready; desktop pairing advertising enabled", false);
                }
                pairing_->channel->checkWrite();
            } catch (...) {
                state_->record(L"Pairing channel: " + exceptionText(), true);
                finishPairing("enrollment_error");
                throw;
            }
        }
    }

    std::wstring lifetimeArguments(const std::shared_ptr<Pairing>& job) {
        return std::to_wstring(job->target.session) + L" " + job->target.sid + L" " + std::to_wstring(job->deadline) +
            L" " + job->eventName + L" " + std::to_wstring(GetCurrentProcessId());
    }

    void launchHelper(const std::shared_ptr<Pairing>& job, const std::wstring& arguments) {
        launchOutstanding_ = true;
        try {
            std::thread([state = state_, this, job, path = helperPath_, arguments] {
                DWORD code = static_cast<DWORD>(unlock_windows::enrollment::ExitCode::error);
                std::wstring error;
                try {
                    init_apartment(apartment_type::multi_threaded);
                    struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
                    const DWORD cancelled = WaitForSingleObject(job->cancel.value, 0);
                    if (cancelled == WAIT_FAILED) requireWin32(FALSE, L"WaitForSingleObject(pairing cancellation)");
                    if (cancelled == WAIT_OBJECT_0)
                        code = static_cast<DWORD>(unlock_windows::enrollment::ExitCode::cancelled);
                    else {
                        SHELLEXECUTEINFOW launch{};
                        launch.cbSize = sizeof(launch);
                        launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
                        launch.lpVerb = L"runas";
                        launch.lpFile = path.c_str();
                        launch.lpParameters = arguments.c_str();
                        launch.nShow = SW_SHOWNORMAL;
                        if (!ShellExecuteExW(&launch)) {
                            const DWORD win32 = GetLastError();
                            if (win32 == ERROR_CANCELLED) code = static_cast<DWORD>(unlock_windows::enrollment::ExitCode::cancelled);
                            else throw hresult_error(HRESULT_FROM_WIN32(win32), L"ShellExecuteExW(pairing role)");
                        } else {
                            unlock_windows::enrollment::Handle process;
                            process.value = launch.hProcess;
                            if (!process.value) throw std::runtime_error("Pairing role returned no process handle");
                        const DWORD helperPid = GetProcessId(process.value);
                        requireWin32(helperPid != 0, L"GetProcessId(pairing role)");
                        state->post([this, job, helperPid] {
                            if (pairing_ == job) job->helperPid = helperPid;
                        });
                            if (WaitForSingleObject(process.value, INFINITE) == WAIT_FAILED) requireWin32(FALSE, L"WaitForSingleObject(pairing role)");
                            requireWin32(GetExitCodeProcess(process.value, &code), L"GetExitCodeProcess(pairing role)");
                        }
                    }
                } catch (...) { error = exceptionText(); }
                state->post([this, state, job, code, error] {
                    launchOutstanding_ = false;
                    if (!error.empty()) state->record(L"Enrollment role launch: " + error, true);
                    if (pairing_ != job) {
                        if (code == static_cast<DWORD>(unlock_windows::enrollment::ExitCode::savedReloadFailed)) {
                            pairingOutcome_ = job->remove ? L"Registration removed, service reload failed; operation window closed afterward" :
                                L"Registration saved, service reload failed; pairing window closed afterward";
                            state->record(pairingOutcome_, true);
                            try { if (job->session) host_.enrollmentResult(job->session, "enrollment_error", true); }
                            catch (...) { state->record(L"Late enrollment failure notification: " + exceptionText(), true); }
                            return;
                        }
                        if (code == static_cast<DWORD>(unlock_windows::enrollment::ExitCode::saved) ||
                            code == static_cast<DWORD>(unlock_windows::enrollment::ExitCode::alreadyRegistered))
                            state->record(L"Enrollment role committed before cancellation was observed; verify current enrollment", true);
                        return;
                    }
                    using unlock_windows::enrollment::ExitCode;
                    const auto outcome = static_cast<ExitCode>(code);
                    const char* status = outcome == ExitCode::saved ? (job->remove ? "enrollment_removed" : "enrollment_saved") :
                        outcome == ExitCode::alreadyRegistered ? "enrollment_already_registered" :
                        outcome == ExitCode::cancelled || outcome == ExitCode::invalidated ? "enrollment_cancelled" :
                        outcome == ExitCode::expired ? "enrollment_expired" :
                        outcome == ExitCode::rejected ? "enrollment_rejected" :
                        outcome == ExitCode::busy ? "enrollment_busy" : "enrollment_error";
                    finishPairing(status, outcome == ExitCode::savedReloadFailed);
                });
            }).detach();
        } catch (...) { launchOutstanding_ = false; throw; }
        reconcile(false);
    }

    void receiveEnrollment(const std::vector<std::uint8_t>& bytes, const GattSession& session, ULONGLONG receivedAt) {
        reconcile(false);
        if (!session || session.SessionStatus() != GattSessionStatus::Active) return;
        if (!pairing_ || pairing_->remove || !pairing_->helperReady || receivedAt < pairing_->deadline - unlock_windows::enrollment::kPairingLifetime) {
            host_.enrollmentResult(session, "enrollment_rejected"); return;
        }
        if (pairing_->session) { host_.enrollmentResult(session, "enrollment_busy"); return; }
        try {
            if (bytes.size() != 66) throw std::invalid_argument("Enrollment request must be 0x02 followed by a 65-byte public key");
            const std::vector<std::uint8_t> key(bytes.begin() + 1, bytes.end());
            unlock_windows::phone_approval::EnrollmentStore::validatePublicKey(key);
            if (!host_.subscriber(session)) throw std::runtime_error("Initiating phone must subscribe to enrollment results");
            auto job = pairing_;
            job->session = session;
            job->sessionToken = session.SessionStatusChanged([state = state_, this, job](const GattSession&,
                const GattSessionStatusChangedEventArgs& args) {
                try {
                    const auto status = args.Status();
                    state->post([this, job, status] {
                        if (pairing_ == job && status != GattSessionStatus::Active) finishPairing("enrollment_cancelled");
                    });
                } catch (...) { state->record(L"Pairing session callback: " + exceptionText(), true); }
            });
            checkPairing();
            if (pairing_ != job) return;
            job->channel->sendKey(key);
        } catch (...) {
            state_->record(L"Enrollment candidate: " + exceptionText(), true);
            if (!pairing_ || !pairing_->session) {
                try { host_.enrollmentResult(session, "enrollment_rejected"); }
                catch (...) { state_->record(L"Enrollment rejection notification: " + exceptionText(), true); }
            }
            finishPairing("enrollment_rejected");
        }
    }

    bool queryLocked() {
        const DWORD console = WTSGetActiveConsoleSessionId();
        if (console == 0xffffffff) throw hresult_error(E_FAIL, L"No physical console session can be confirmed");
        if (console != session_) {
            condition_ = L"Phone unlock is unavailable outside this PC's active local session.";
            return false;
        }
        LPWSTR raw = nullptr;
        DWORD bytes = 0;
        requireWin32(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_,
            WTSSessionInfoEx, &raw, &bytes), L"WTSQuerySessionInformationW(WTSSessionInfoEx)");
        struct WtsMemory final {
            LPWSTR value;
            ~WtsMemory() { if (value) WTSFreeMemory(value); }
        } memory{raw};
        if (!raw || bytes < sizeof(WTSINFOEXW)) throw hresult_error(E_FAIL, L"Malformed WTSSessionInfoEx response");
        const auto& info = *reinterpret_cast<const WTSINFOEXW*>(raw);
        const auto& level = info.Data.WTSInfoExLevel1;
        if (info.Level != 1 || level.SessionId != session_ || level.SessionState != WTSActive ||
            (level.SessionFlags != WTS_SESSIONSTATE_LOCK && level.SessionFlags != WTS_SESSIONSTATE_UNLOCK))
            throw hresult_error(E_FAIL, L"Console session is not active with a known lock state");
        if (WTSGetActiveConsoleSessionId() != session_)
            throw hresult_error(E_FAIL, L"Physical console changed during lock-state query");
        const bool locked = level.SessionFlags == WTS_SESSIONSTATE_LOCK;
        condition_ = locked ? L"This PC is locked." : L"This PC is unlocked. Bluetooth discovery is paused.";
        return locked;
    }

    void reconcile(bool recheck) {
        if (closing_ || state_->stopping()) return;
        bool locked = false;
        bool lifecycleConfirmed = false;
        std::wstring currentError;
        try {
            locked = queryLocked();
            checkPairing();
            if (suspended_ || endingSession_) {
                locked = false;
                condition_ = L"Bluetooth discovery paused while this PC sleeps or signs out.";
            }
        } catch (...) {
            currentError = exceptionText();
            locked = false;
            finishPairing("enrollment_cancelled");
            condition_ = L"Bluetooth discovery paused: Windows session could not be verified.";
        }
        try {
            if (host_.initialized()) {
                const bool advertising = locked || (pairing_ && !pairing_->remove && pairing_->helperReady);
                if (pairing_) condition_ = pairing_->remove ? L"Waiting for confirmation to remove paired iPhone." :
                    !pairing_->helperReady ? L"Pairing: waiting for Windows permission." :
                    pairing_->session ? L"Pairing: compare the fingerprints." : L"Pairing: waiting for your iPhone.";
                if (recheck && (host_.advertisingExhausted() || (advertising &&
                    host_.status() != GattServiceProviderAdvertisementStatus::Started &&
                    host_.status() != GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData)))
                    host_.retryAdvertising();
                host_.advertise(advertising);
                if (locked && host_.advertisingReady()) host_.pollAuthentication();
                const auto status = host_.status();
                if (host_.advertisingExhausted()) {
                    if (!currentError.empty()) currentError += L"; ";
                    currentError += host_.advertisingError();
                }
                lifecycleConfirmed = currentError.empty() && (advertising
                    ? host_.advertisingReady()
                    : status == GattServiceProviderAdvertisementStatus::Stopped ||
                        status == GattServiceProviderAdvertisementStatus::Created ||
                        status == GattServiceProviderAdvertisementStatus::Aborted || host_.advertisingStopped());
                if (advertising) {
                    if (host_.advertisingReady()) {
                        if (!pairing_) condition_ = L"This PC is locked and discoverable by your iPhone.";
                    }
                    else if (host_.advertisingExhausted()) condition_ = L"Bluetooth discovery needs attention.";
                    else condition_ += L" Starting or recovering Bluetooth discovery...";
                } else if (!host_.advertisingStopped() && (status == GattServiceProviderAdvertisementStatus::Started ||
                    status == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData))
                    condition_ += L" Bluetooth discovery is stopping.";
            } else currentError += L" GATT initialization failed; restart the EXE: " + initializationError_;
        } catch (...) {
            if (!currentError.empty()) currentError += L"; ";
            currentError += exceptionText();
        }
        if (!currentError.empty() && currentError != lastError_) state_->record(currentError, false);
        if (lifecycleConfirmed) lastError_.clear();
        else if (!currentError.empty()) lastError_ = currentError;
    }

    std::wstring technicalDetails() {
        std::wstring details = L"Process session: " + std::to_wstring(session_) +
            L"\r\nConsole session: " + std::to_wstring(WTSGetActiveConsoleSessionId()) +
            L"\r\nCurrent lifecycle error: " + (lastError_.empty() ? L"none" : lastError_) +
            L"\r\nLast registration result: " + (pairingOutcome_.empty() ? L"none" : pairingOutcome_);
        if (host_.initialized()) details += L"\r\nWinRT publication status (raw): " +
            std::to_wstring(static_cast<int>(host_.status())) + L"\r\nApplication publication state: " +
            (host_.advertisingStopped() ? L"no active publication request" :
                host_.advertisingReady() ? L"started" : L"pending or failed; see history");
        std::lock_guard lock(state_->mutex);
        return details + L"\r\nLast communication error (history): " + state_->transportError +
            L"\r\n\r\nDiagnostic history:\r\n" + state_->diagnostics;
    }

    bool busy() const { return initializing_ || pairing_ || launchOutstanding_ || setupPasswordPending_; }

    void publishDashboard() {
        if (closing_ || state_->stopping()) return;
        unlock_windows::desktop_app::DashboardSnapshot snapshot;
        snapshot.busy = busy();
        snapshot.status = condition_;
        snapshot.diagnostics = technicalDetails();
        snapshot.error = lastError_.empty() ? initializationError_ : lastError_;
        try { snapshot.connection = host_.connectionSummary(); }
        catch (...) { snapshot.error += L"\n" + exceptionText(); }
        try { snapshot.paired = unlock_windows::phone_approval::EnrollmentStore{}.load().has_value(); }
        catch (...) {
            snapshot.error += L"\nCould not read the paired iPhone: " + exceptionText();
        }
        {
            std::lock_guard lock(state_->mutex);
            state_->snapshot = std::move(snapshot);
        }
        state_->notify();
    }

    void finishSetup(const unlock_windows::enrollment::Console& target) {
        const auto current = unlock_windows::enrollment::queryConsole();
        if (current.locked || current.session != target.session || current.sid != target.sid || closing_)
            throw std::runtime_error("The setup console account changed. Start setup again from the target user's unlocked console.");
        const auto registration = unlock_windows::phone_approval::EnrollmentStore{}.load();
        if (registration && registration->accountSid != target.sid)
            throw std::runtime_error("The paired iPhone belongs to a different Windows account.");
        if (registration) {
            state_->notice(L"A password copy and iPhone registration are present. Lock this PC to test iPhone unlock. Windows has not yet verified the saved password.",
                L"Setup configured", MB_OK | MB_ICONINFORMATION);
            return;
        }
        setupPairing_ = true;
        startPairing();
        if (!pairing_) setupPairing_ = false;
    }

    void continueSetup() {
        if (busy()) return;
        const auto target = unlock_windows::enrollment::queryConsole();
        if (target.locked || target.session != session_ ||
            target.sid != unlock_windows::phone_approval::EnrollmentStore::currentUserSid() ||
            unlock_windows::enrollment::elevatedAdmin())
            throw std::runtime_error("Continue setup as the ordinary unlocked physical console user.");
        std::wstring executable(32768, L'\0');
        const DWORD size = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (!size || size >= executable.size()) throw std::runtime_error("Could not locate the saved password manager");
        executable.resize(size);
        const auto arguments = std::wstring(unlock_windows::desktop_app::kSavedPasswordRole) + L" " +
            unlock_windows::desktop_app::kSetupRole;
        setupPasswordPending_ = true;
        try {
            SHELLEXECUTEINFOW launch{sizeof(launch)};
            launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
            launch.lpVerb = L"runas"; launch.lpFile = executable.c_str(); launch.lpParameters = arguments.c_str();
            launch.nShow = SW_SHOWNORMAL;
            if (!ShellExecuteExW(&launch)) {
                const auto error = GetLastError();
                if (error == ERROR_CANCELLED) { setupPasswordPending_ = false; return; }
                SetLastError(error); requireWin32(FALSE, L"Open saved password setup");
            }
            auto process = std::make_shared<unlock_windows::enrollment::Handle>();
            process->value = launch.hProcess;
            if (!process->value) throw std::runtime_error("Saved password setup returned no process handle");
            std::thread([state = state_, this, process, target] {
                DWORD code = static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::error);
                std::wstring error;
                try {
                    requireWin32(WaitForSingleObject(process->value, INFINITE) == WAIT_OBJECT_0, L"Wait for password setup");
                    requireWin32(GetExitCodeProcess(process->value, &code), L"Read password setup result");
                } catch (...) { error = exceptionText(); }
                state->post([this, code, error, target] {
                    setupPasswordPending_ = false;
                    try {
                        if (!error.empty()) throw std::runtime_error(winrt::to_string(error));
                        if (code == static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::credentialReady)) finishSetup(target);
                        else if (code != static_cast<DWORD>(unlock_windows::desktop_app::SetupResult::cancelled))
                            throw std::runtime_error("Password setup did not complete. Start setup again to retry.");
                    } catch (...) {
                        const auto message = exceptionText();
                        state_->record(L"Setup: " + message, true);
                        state_->notice(message, L"Setup needs attention", MB_OK | MB_ICONERROR);
                    }
                });
            }).detach();
        } catch (...) { setupPasswordPending_ = false; throw; }
    }

    void dispatch() {
        if (state_->stopping()) { close(); return; }
        std::deque<std::function<void()>> pending;
        { std::lock_guard lock(state_->mutex); pending.swap(state_->pending); }
        for (auto& action : pending) {
            if (closing_ || state_->stopping()) break;
            action();
        }
        if (state_->stopping()) close();
        else if (!closing_) {
            reconcile(false);
            publishDashboard();
        }
    }

    void close() {
        if (closing_) return;
        closing_ = true;
        state_->stop();
        try { finishPairing("enrollment_cancelled"); }
        catch (...) { state_->record(L"Pairing shutdown: " + exceptionText(), true); }
        host_.shutdown();
        if (window_) {
            if (sessionRegistered_ && !WTSUnRegisterSessionNotification(window_))
                state_->record(L"WTSUnRegisterSessionNotification Win32=" + std::to_wstring(GetLastError()), true);
            KillTimer(window_, 1);
            DestroyWindow(window_);
            window_ = nullptr;
        }
        std::lock_guard lock(state_->mutex);
        state_->window = nullptr;
        state_->control = nullptr;
    }

    static LRESULT CALLBACK windowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* self = reinterpret_cast<GattControl*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<GattControl*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(window, message, wparam, lparam);
        try {
            switch (message) {
            case kDispatch: self->dispatch(); return 0;
            case WM_TIMER: self->dispatch(); return 0;
            case WM_WTSSESSION_CHANGE:
                if (self->pairing_ && ((static_cast<DWORD>(lparam) == self->session_ &&
                    (wparam == WTS_SESSION_LOCK || wparam == WTS_SESSION_LOGOFF || wparam == WTS_CONSOLE_DISCONNECT || wparam == WTS_REMOTE_CONNECT)) ||
                    WTSGetActiveConsoleSessionId() != self->session_)) self->finishPairing("enrollment_cancelled");
                if (wparam == WTS_SESSION_LOGOFF && static_cast<DWORD>(lparam) == self->session_) self->close();
                else self->reconcile(false);
                self->publishDashboard();
                return 0;
            case WM_POWERBROADCAST:
                if (wparam == PBT_APMSUSPEND) self->suspended_ = true;
                if (wparam == PBT_APMRESUMEAUTOMATIC || wparam == PBT_APMRESUMESUSPEND) self->suspended_ = false;
                self->reconcile(false);
                self->publishDashboard();
                return TRUE;
            case WM_QUERYENDSESSION:
                self->endingSession_ = true;
                self->reconcile(false);
                self->publishDashboard();
                return TRUE;
            case WM_ENDSESSION:
                if (wparam) self->close();
                else { self->endingSession_ = false; self->reconcile(false); }
                self->publishDashboard();
                return 0;
            case WM_CLOSE: self->close(); return 0;
            case WM_DESTROY: PostQuitMessage(0); return 0;
            case WM_NCDESTROY:
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
                break;
            }
        } catch (...) {
            self->lastError_ = exceptionText();
            self->state_->record(self->lastError_, true);
            {
                std::lock_guard lock(self->state_->mutex);
                self->state_->failed = true;
            }
            self->close();
            self->state_->notice(self->lastError_, L"Phone connectivity stopped", MB_OK | MB_ICONERROR);
            return message == WM_QUERYENDSESSION ? TRUE : 0;
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }

    std::shared_ptr<CallbackState> state_;
    GattHost host_;
    HWND window_ = nullptr;
    bool initializing_ = true;
    DWORD session_ = 0;
    bool sessionRegistered_ = false;
    bool closing_ = false;
    bool suspended_ = false;
    bool endingSession_ = false;
    std::wstring condition_ = L"Bluetooth discovery is stopped.";
    std::wstring lastError_;
    std::wstring initializationError_;
    std::shared_ptr<Pairing> pairing_;
    bool launchOutstanding_ = false;
    bool setupPasswordPending_ = false;
    bool setupPairing_ = false;
    std::wstring helperPath_;
    std::wstring pairingOutcome_;
};

} // namespace

namespace unlock_windows::desktop_app {

GattController::GattController(std::function<bool()> wake) : state_(std::make_shared<CallbackState>()) {
    state_->wake = std::move(wake);
}

void GattController::start(HINSTANCE instance) {
    thread_ = std::thread([state = state_, instance] {
        try {
            winrt::init_apartment(winrt::apartment_type::multi_threaded);
            struct Apartment final { ~Apartment() { winrt::uninit_apartment(); } } apartment;
            GattControl control(state);
            control.run(instance);
        } catch (...) {
            const auto error = exceptionText();
            state->record(L"GATT controller: " + error, true);
            {
                std::lock_guard lock(state->mutex);
                state->failed = true;
            }
            state->notice(error, L"Phone connectivity stopped", MB_OK | MB_ICONERROR);
        }
        state->stop();
    });
}

bool GattController::command(TrayCommand command) {
    return state_->post([state = state_, command] { state->control->execute(command); });
}

void GattController::requestStop() { state_->stop(); }

GattUpdate GattController::takeUpdate() {
    std::lock_guard lock(state_->mutex);
    GattUpdate update;
    update.controlReady = state_->controlReady;
    update.stopping = state_->stopRequested;
    update.failed = state_->failed;
    update.snapshot = std::move(state_->snapshot);
    state_->snapshot.reset();
    update.notices.swap(state_->notices);
    return update;
}

bool GattController::ended() {
    if (!thread_.joinable()) return true;
    const DWORD result = WaitForSingleObject(thread_.native_handle(), 0);
    if (result == WAIT_FAILED) requireWin32(FALSE, L"Observe GATT control thread");
    return result == WAIT_OBJECT_0;
}

void GattController::join() {
    if (thread_.joinable()) {
        if (!ended()) throw std::logic_error("GATT control thread is still running");
        thread_.join();
    }
}

void GattController::record(const std::wstring& message) { state_->record(message, false); }

std::function<void(std::wstring)> GattController::errorReporter(std::wstring title, bool notify) {
    return [state = state_, title = std::move(title), notify](std::wstring message) {
        state->record(message, false);
        if (notify) state->notice(std::move(message), title, MB_OK | MB_ICONERROR, true);
    };
}

}
