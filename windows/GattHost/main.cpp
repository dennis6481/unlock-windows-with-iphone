// Created by Rui MA on 26 Sep 2026

#include "SavedCredentialIpc.h"
#include "EnrollmentStore.h"
#include "../PairingTool/EnrollmentSession.h"
#include "../PairingTool/EnrollmentChannel.h"

#include <Windows.h>
#include <WtsApi32.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <objidl.h>
#include <gdiplus.h>
#include <shlwapi.h>

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
constexpr std::uint8_t kAuthenticateRequest = 0x01;
constexpr std::uint8_t kEnrollmentRequest = 0x02;

constexpr UINT kDispatch = WM_APP + 1;
constexpr UINT kTray = WM_APP + 2;

struct CallbackState final {
    std::mutex mutex;
    std::condition_variable drained;
    HWND window = nullptr;
    bool accepting = true;
    unsigned activeWrites = 0;
    std::deque<std::function<void()>> pending;
    std::wstring diagnostics;
    std::wstring transportError;

    void post(std::function<void()> action) {
        std::lock_guard lock(mutex);
        if (!accepting) return;
        pending.push_back(std::move(action));
        if (!PostMessageW(window, kDispatch, 0, 0)) {
            transportError = L"PostMessageW failed: Win32=" + std::to_wstring(GetLastError());
            OutputDebugStringW(transportError.c_str());
        }
    }

    void record(const std::wstring& message, bool error) {
        OutputDebugStringW((message + L"\n").c_str());
        std::lock_guard lock(mutex);
        diagnostics += message + L"\r\n";
        if (diagnostics.size() > 16000) diagnostics.erase(0, diagnostics.find(L"\n", 8000) + 1);
        if (error) transportError = message;
    }
};

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

        requestWriteToken_ = requestCharacteristic_.WriteRequested(
            [state = state_, this](GattLocalCharacteristic const&, GattWriteRequestedEventArgs const& args) {
                finishRequest(state, args, [this](const std::vector<std::uint8_t>& bytes, const GattSession& session, ULONGLONG receivedAt) {
                    handleRequestWrite(bytes, session, receivedAt);
                });
            }
        );
        assertionWriteToken_ = assertionCharacteristic_.WriteRequested(
            [state = state_, this](GattLocalCharacteristic const&, GattWriteRequestedEventArgs const& args) {
                finishRequest(state, args, [this](const std::vector<std::uint8_t>& bytes, const GattSession&, ULONGLONG) {
                    if (!pairingActive) handleAssertionWrite(bytes);
                    else state_->record(L"Authentication assertion rejected during pairing", false);
                });
            }
        );
        challengeSubscriptionToken_ = challengeCharacteristic_.SubscribedClientsChanged(
            [state = state_](GattLocalCharacteristic const& characteristic, winrt::Windows::Foundation::IInspectable const&) {
                try {
                    const auto count = characteristic.SubscribedClients().Size();
                    state->post([state, count] { LogLine(state, false) << "[GattHost] challenge subscribers: " << count; });
                } catch (...) { state->record(exceptionText(), true); }
            }
        );

        advertisementStatusToken_ = serviceProvider_.AdvertisementStatusChanged(
            [state = state_, statusChanged](
                GattServiceProvider const&,
                GattServiceProviderAdvertisementStatusChangedEventArgs const& args
            ) {
                try {
                    const auto status = args.Status();
                    const auto error = args.Error();
                    state->post([state, statusChanged, status, error] {
                        LogLine(state, false) << "[GattHost] advertisement event status=" << static_cast<int>(status)
                            << " error=" << static_cast<int>(error);
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
        if (enabled == advertisingRequested_ && (enabled ||
            (status() != GattServiceProviderAdvertisementStatus::Started &&
             status() != GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData))) return;
        if (enabled) {
            GattServiceProviderAdvertisingParameters parameters;
            parameters.IsDiscoverable(true);
            parameters.IsConnectable(true);
            advertisingRequested_ = true;
            serviceProvider_.StartAdvertising(parameters);
        } else {
            serviceProvider_.StopAdvertising();
        }
        advertisingRequested_ = enabled;
    }

    void retryAdvertising() { advertisingRequested_ = false; }

    void shutdown() {
        {
            std::lock_guard lock(state_->mutex);
            state_->accepting = false;
        }
        auto cleanup = [this](auto action) {
            try { action(); } catch (...) { state_->record(L"Shutdown: " + exceptionText(), true); }
        };
        if (serviceProvider_) {
            cleanup([this] { serviceProvider_.StopAdvertising(); });
            if (advertisementStatusToken_.value) cleanup([this] { serviceProvider_.AdvertisementStatusChanged(advertisementStatusToken_); });
        }
        if (requestCharacteristic_ && requestWriteToken_.value)
            cleanup([this] { requestCharacteristic_.WriteRequested(requestWriteToken_); });
        if (assertionCharacteristic_ && assertionWriteToken_.value)
            cleanup([this] { assertionCharacteristic_.WriteRequested(assertionWriteToken_); });
        if (challengeCharacteristic_ && challengeSubscriptionToken_.value)
            cleanup([this] { challengeCharacteristic_.SubscribedClientsChanged(challengeSubscriptionToken_); });
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
        if (!bytes.empty() && bytes.front() == kEnrollmentRequest) {
            enrollmentRequest(bytes, session, receivedAt);
            return;
        }
        if (bytes.size() == 1 && bytes.front() == kAuthenticateRequest) {
            if (!pairingActive) handleAuthenticationRequest();
            else state_->record(L"Authentication request rejected during pairing", false);
            return;
        }

        LogLine(state_, true) << "[GattHost] rejected request frame, got "
                  << bytes.size() << " byte(s)\n";
    }

    void handleAuthenticationRequest() {
        LogLine(state_, false) << "[GattHost] request frame received; asking saved-credential service for challenge\n";
        unlock_windows::saved_credential::Packet response;
        unlock_windows::saved_credential::CallDiagnostics diagnostics;
        const bool received = unlock_windows::saved_credential::callPhone(
                unlock_windows::saved_credential::Operation::issuePhoneChallenge,
                unlock_windows::saved_credential::SensitiveBytes{}, response, 2000, &diagnostics);
        if (!received || response.result != unlock_windows::saved_credential::Result::success ||
            response.payload.value.empty()) {
            const char* status = !received ? "service_unavailable" :
                response.result == unlock_windows::saved_credential::Result::rejected ? "not_ready" : "service_error";
            LogLine(state_, true) << "[GattHost] phone challenge failed: " << status << "\n";
            if (!received) {
                LogLine(state_, true) << "[GattHost] IPC stage="
                    << to_string(unlock_windows::saved_credential::callStageName(diagnostics.stage))
                    << " check=" << to_string(diagnostics.serverCheck)
                    << " win32=" << diagnostics.win32Error << "\n";
            }
            logNotificationResults(resultCharacteristic_.NotifyValueAsync(
                makeBuffer(std::string("{\"authenticated\":false,\"status\":\"") + status + "\"}")).get(), "result");
            return;
        }

        LogLine(state_, false) << "[GattHost] request accepted; service issued challenge\n";
        LogLine(state_, false) << "[GattHost] challenge notification length=" << response.payload.value.size() << "\n";
        logNotificationResults(
            challengeCharacteristic_.NotifyValueAsync(makeBuffer(bytesAsText(response.payload.value))).get(),
            "challenge"
        );
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
        const std::string result = received && response.result == unlock_windows::saved_credential::Result::success &&
            !response.payload.value.empty()
            ? bytesAsText(response.payload.value)
            : std::string("{\"authenticated\":false,\"status\":\"") + failure + "\"}";
        logNotificationResults(
            resultCharacteristic_.NotifyValueAsync(makeBuffer(result)).get(),
            "result"
        );
    }

    void logNotificationResults(
        const winrt::Windows::Foundation::Collections::IVectorView<GattClientNotificationResult>& results,
        const char* name
    ) {
        for (const auto& result : results) {
            if (result.Status() != GattCommunicationStatus::Success) {
                LogLine(state_, true) << "[GattHost] " << name << " notification status="
                          << static_cast<int>(result.Status()) << "\n";
            }
        }
    }

    std::shared_ptr<CallbackState> state_;
    bool initialized_ = false;
    bool advertisingRequested_ = false;
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

class TrayHost final {
public:
    TrayHost() : state_(std::make_shared<CallbackState>()), host_(state_) {
        host_.enrollmentRequest = [this](const auto& bytes, const auto& session, ULONGLONG receivedAt) {
            receiveEnrollment(bytes, session, receivedAt);
        };
    }
    ~TrayHost() { close(); }

    int run(HINSTANCE instance) {
        requireWin32(ProcessIdToSessionId(GetCurrentProcessId(), &session_), L"ProcessIdToSessionId");
        singleton_ = CreateMutexW(nullptr, FALSE, L"Local\\UnlockWindowsWithIPhone-GattHost");
        if (!singleton_) requireWin32(FALSE, L"CreateMutexW");
        if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
        loadTrayIcon(instance);

        WNDCLASSW windowClass{};
        windowClass.hInstance = instance;
        windowClass.lpszClassName = L"UnlockWindowsWithIPhoneGattHost";
        windowClass.lpfnWndProc = windowProcedure;
        requireWin32(RegisterClassW(&windowClass), L"RegisterClassW");
        window_ = CreateWindowExW(0, windowClass.lpszClassName, L"Unlock Windows with iPhone",
            0, 0, 0, 0, 0, nullptr, nullptr, instance, this);
        if (!window_) requireWin32(FALSE, L"CreateWindowExW");
        state_->window = window_;
        taskbarCreated_ = RegisterWindowMessageW(L"TaskbarCreated");
        if (!taskbarCreated_) requireWin32(FALSE, L"RegisterWindowMessageW");
        addTray();
        if (!SetTimer(window_, 1, 1000, nullptr)) requireWin32(FALSE, L"SetTimer");
        try {
            host_.initialize([this] { reconcile(false); });
        } catch (...) {
            initializationError_ = exceptionText();
            state_->record(L"GATT initialization: " + initializationError_, true);
        }
        reconcile(true);
        MSG message{};
        BOOL result;
        while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (result == -1) requireWin32(FALSE, L"GetMessageW");
        return 0;
    }

private:
    void loadTrayIcon(HINSTANCE instance) {
        const auto resource = FindResourceW(instance, MAKEINTRESOURCEW(101), MAKEINTRESOURCEW(10));
        requireWin32(resource != nullptr, L"FindResourceW(tray PNG)");
        const auto loaded = LoadResource(instance, resource);
        requireWin32(loaded != nullptr, L"LoadResource(tray PNG)");
        const auto bytes = static_cast<const BYTE*>(LockResource(loaded));
        if (!bytes) throw std::runtime_error("LockResource(tray PNG) failed");
        winrt::com_ptr<IStream> stream;
        stream.attach(SHCreateMemStream(bytes, SizeofResource(instance, resource)));
        if (!stream) throw std::runtime_error("SHCreateMemStream(tray PNG) failed");
        Gdiplus::GdiplusStartupInput input;
        ULONG_PTR token = 0;
        if (Gdiplus::GdiplusStartup(&token, &input, nullptr) != Gdiplus::Ok)
            throw std::runtime_error("GdiplusStartup(tray PNG) failed");
        struct Shutdown final { ULONG_PTR token; ~Shutdown() { Gdiplus::GdiplusShutdown(token); } } shutdown{token};
        Gdiplus::Bitmap source(stream.get());
        const int width = GetSystemMetrics(SM_CXSMICON);
        const int height = GetSystemMetrics(SM_CYSMICON);
        Gdiplus::Bitmap scaled(width, height, PixelFormat32bppARGB);
        if (source.GetLastStatus() != Gdiplus::Ok || scaled.GetLastStatus() != Gdiplus::Ok)
            throw std::runtime_error("Could not decode root icon.png as a tray icon");
        {
            Gdiplus::Graphics graphics(&scaled);
            if (graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic) != Gdiplus::Ok ||
                graphics.DrawImage(&source, 0, 0, width, height) != Gdiplus::Ok)
                throw std::runtime_error("Could not resize tray PNG");
        }
        if (scaled.GetHICON(&trayIcon_) != Gdiplus::Ok)
            throw std::runtime_error("Could not create tray icon from PNG");
    }

    struct Pairing final {
        unlock_windows::enrollment::Console target;
        ULONGLONG deadline = 0;
        bool replace = false;
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

    void startPairing(bool replace, bool remove = false) {
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
            const auto helper = std::filesystem::path(executable).parent_path() / L"unlock_pairing_tool.exe";
            const DWORD attributes = GetFileAttributesW(helper.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
                throw std::runtime_error("unlock_pairing_tool.exe must exist beside the GATT host");
            auto job = std::make_shared<Pairing>();
            job->target = target;
            job->deadline = GetTickCount64() + unlock_windows::enrollment::kPairingLifetime;
            job->replace = replace;
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
            if (pairing_ == job) launchHelper(job, L"--bluetooth " + (remove ? std::wstring(L"clear remove ") :
                job->channelName + (replace ? L" replace " : L" first ")) + lifetimeArguments(job));
        } catch (...) {
            const auto error = exceptionText();
            state_->record(L"Pairing start: " + error, true);
            finishPairing("enrollment_error");
            MessageBoxW(window_, error.c_str(), L"无法开启手机配对", MB_OK | MB_ICONERROR);
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
        if (savedReloadFailed) pairingOutcome_ += job->remove ? L"：登记已移除，服务重新加载失败" : L"：公钥已保存，服务重新加载失败";
        state_->record(L"Pairing finished: " + pairingOutcome_, savedReloadFailed || std::string_view(result) == "enrollment_error");
        if (job->session) {
            try { host_.enrollmentResult(job->session, result, savedReloadFailed); }
            catch (...) { state_->record(L"Pairing result notification: " + exceptionText(), true); }
        }
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
                    state_->record(L"PairingTool ready; desktop pairing advertising enabled", false);
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
                            else throw hresult_error(HRESULT_FROM_WIN32(win32), L"ShellExecuteExW(PairingTool)");
                        } else {
                            unlock_windows::enrollment::Handle process;
                            process.value = launch.hProcess;
                            if (!process.value) throw std::runtime_error("PairingTool returned no process handle");
                        const DWORD helperPid = GetProcessId(process.value);
                        requireWin32(helperPid != 0, L"GetProcessId(PairingTool)");
                        state->post([this, job, helperPid] {
                            if (pairing_ == job) job->helperPid = helperPid;
                        });
                            if (WaitForSingleObject(process.value, INFINITE) == WAIT_FAILED) requireWin32(FALSE, L"WaitForSingleObject(PairingTool)");
                            requireWin32(GetExitCodeProcess(process.value, &code), L"GetExitCodeProcess(PairingTool)");
                        }
                    }
                } catch (...) { error = exceptionText(); }
                state->post([this, state, job, code, error] {
                    launchOutstanding_ = false;
                    if (!error.empty()) state->record(L"PairingTool launch: " + error, true);
                    if (pairing_ != job) {
                        if (code == static_cast<DWORD>(unlock_windows::enrollment::ExitCode::savedReloadFailed)) {
                            pairingOutcome_ = job->remove ? L"登记已移除，服务加载失败；操作窗口随后结束" :
                                L"公钥已保存，服务加载失败；配对窗口随后结束";
                            state->record(pairingOutcome_, true);
                            try { if (job->session) host_.enrollmentResult(job->session, "enrollment_error", true); }
                            catch (...) { state->record(L"Late enrollment failure notification: " + exceptionText(), true); }
                            return;
                        }
                        if (code == static_cast<DWORD>(unlock_windows::enrollment::ExitCode::saved) ||
                            code == static_cast<DWORD>(unlock_windows::enrollment::ExitCode::alreadyRegistered))
                            state->record(L"PairingTool committed before cancellation was observed; verify current enrollment", true);
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
            condition_ = L"非当前物理控制台会话，广播停止";
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
        condition_ = locked ? L"锁屏" : L"已解锁，广播停止";
        return locked;
    }

    void reconcile(bool recheck) {
        if (closing_) return;
        bool locked = false;
        bool lifecycleConfirmed = false;
        std::wstring currentError;
        try {
            if (!sessionRegistered_) {
                if (!recheck) throw hresult_error(E_FAIL, L"WTS notifications are not registered; use 重新检查");
                requireWin32(WTSRegisterSessionNotification(window_, NOTIFY_FOR_ALL_SESSIONS),
                    L"WTSRegisterSessionNotification");
                sessionRegistered_ = true;
            }
            locked = queryLocked();
            checkPairing();
            if (suspended_ || endingSession_) {
                locked = false;
                condition_ = L"会话结束或睡眠，广播停止";
            }
        } catch (...) {
            currentError = exceptionText();
            locked = false;
            finishPairing("enrollment_cancelled");
            condition_ = L"会话状态无法确认，广播停止";
        }
        try {
            if (host_.initialized()) {
                const bool advertising = locked || (pairing_ && !pairing_->remove && pairing_->helperReady);
                if (pairing_) condition_ = pairing_->remove ? L"移除登记中，等待本地确认" :
                    !pairing_->helperReady ? L"配对中，等待 UAC／工具就绪" :
                    pairing_->session ? L"配对中，等待指纹确认" : L"配对中，等待手机登记（两分钟）";
                if (recheck && advertising && host_.status() != GattServiceProviderAdvertisementStatus::Started &&
                    host_.status() != GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData)
                    host_.retryAdvertising();
                host_.advertise(advertising);
                const auto status = host_.status();
                lifecycleConfirmed = currentError.empty() && (advertising
                    ? status == GattServiceProviderAdvertisementStatus::Started
                    : status == GattServiceProviderAdvertisementStatus::Stopped ||
                        status == GattServiceProviderAdvertisementStatus::Created);
                if (advertising) {
                    if (status == GattServiceProviderAdvertisementStatus::Started) {
                        if (!pairing_) condition_ = L"锁屏，正在广播";
                    }
                    else if (status == GattServiceProviderAdvertisementStatus::Aborted)
                        throw hresult_error(E_FAIL, L"GATT advertising aborted; use 重新检查");
                    else if (status == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData)
                        throw hresult_error(E_FAIL, L"GATT started without all advertisement data");
                    else condition_ = L"广播启动中";
                } else if (status == GattServiceProviderAdvertisementStatus::Started ||
                    status == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData)
                    condition_ += L"（广播停止待确认）";
            } else currentError += L" GATT initialization failed; restart the EXE: " + initializationError_;
        } catch (...) {
            if (!currentError.empty()) currentError += L"; ";
            currentError += exceptionText();
        }
        if (!currentError.empty() && currentError != lastError_) state_->record(currentError, false);
        if (lifecycleConfirmed) lastError_.clear();
        else if (!currentError.empty()) lastError_ = currentError;
        updateTray();
    }

    NOTIFYICONDATAW trayData() const {
        NOTIFYICONDATAW data{};
        data.cbSize = sizeof(data);
        data.hWnd = window_;
        data.uID = 1;
        data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        data.uCallbackMessage = kTray;
        data.hIcon = trayIcon_;
        const auto text = !lastError_.empty() ? L"错误；" + condition_ : condition_;
        wcsncpy_s(data.szTip, text.c_str(), _TRUNCATE);
        return data;
    }

    void addTray() {
        auto data = trayData();
        if (!Shell_NotifyIconW(NIM_ADD, &data)) throw hresult_error(E_FAIL, L"Shell_NotifyIconW(NIM_ADD) failed");
        trayAdded_ = true;
    }

    void updateTray() {
        auto data = trayData();
        if (!Shell_NotifyIconW(NIM_MODIFY, &data)) throw hresult_error(E_FAIL, L"Shell_NotifyIconW(NIM_MODIFY) failed");
    }

    void showDetails() {
        std::wstring details = condition_ + L"\r\nProcess session=" + std::to_wstring(session_) +
            L"\r\nConsole session=" + std::to_wstring(WTSGetActiveConsoleSessionId()) +
            L"\r\n当前生命周期错误：" + lastError_ + L"\r\n";
        details += L"最近登记结果：" + pairingOutcome_ + L"\r\n";
        { std::lock_guard lock(state_->mutex); details += L"最近通信／回调错误（历史记录）：" +
            state_->transportError + L"\r\n历史诊断：\r\n" + state_->diagnostics; }
        MessageBoxW(window_, details.c_str(), L"GATT 状态详情", MB_OK | MB_ICONINFORMATION);
    }

    void menu() {
        HMENU popup = CreatePopupMenu();
        if (!popup) requireWin32(FALSE, L"CreatePopupMenu");
        struct MenuHandle final { HMENU value; ~MenuHandle() { DestroyMenu(value); } } handle{popup};
        requireWin32(AppendMenuW(popup, MF_STRING, 1, L"状态详情"), L"AppendMenuW");
        requireWin32(AppendMenuW(popup, MF_STRING, 2, L"重新检查"), L"AppendMenuW");
        const UINT available = pairing_ || launchOutstanding_ ? MF_GRAYED : 0;
        requireWin32(AppendMenuW(popup, MF_STRING | available, 4, L"配对手机"), L"AppendMenuW");
        requireWin32(AppendMenuW(popup, MF_STRING | available, 5, L"更换手机"), L"AppendMenuW");
        requireWin32(AppendMenuW(popup, MF_STRING | available, 7, L"移除手机登记…"), L"AppendMenuW");
        if (pairing_) requireWin32(AppendMenuW(popup, MF_STRING, 6, pairing_->remove ? L"取消移除" : L"取消配对"), L"AppendMenuW");
        requireWin32(AppendMenuW(popup, MF_SEPARATOR, 0, nullptr), L"AppendMenuW");
        requireWin32(AppendMenuW(popup, MF_STRING, 3, L"退出"), L"AppendMenuW");
        POINT point{};
        requireWin32(GetCursorPos(&point), L"GetCursorPos");
        SetForegroundWindow(window_);
        const auto command = TrackPopupMenu(popup, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
            point.x, point.y, 0, window_, nullptr);
        if (command == 1) showDetails();
        if (command == 2) {
            reconcile(true);
        }
        if (command == 3) requireWin32(PostMessageW(window_, WM_CLOSE, 0, 0), L"PostMessageW(WM_CLOSE)");
        if (command == 4 || command == 5) startPairing(command == 5);
        if (command == 6) { finishPairing("enrollment_cancelled"); reconcile(false); }
        if (command == 7) startPairing(false, true);
        requireWin32(PostMessageW(window_, WM_NULL, 0, 0), L"PostMessageW(WM_NULL)");
    }

    void dispatch() {
        std::deque<std::function<void()>> pending;
        { std::lock_guard lock(state_->mutex); pending.swap(state_->pending); }
        for (auto& action : pending) {
            if (closing_) break;
            action();
        }
        reconcile(false);
    }

    void close() {
        if (closing_) return;
        closing_ = true;
        try { finishPairing("enrollment_cancelled"); }
        catch (...) { state_->record(L"Pairing shutdown: " + exceptionText(), true); }
        host_.shutdown();
        if (window_) {
            if (sessionRegistered_ && !WTSUnRegisterSessionNotification(window_))
                state_->record(L"WTSUnRegisterSessionNotification Win32=" + std::to_wstring(GetLastError()), true);
            KillTimer(window_, 1);
            if (trayAdded_) {
                auto data = trayData();
                if (!Shell_NotifyIconW(NIM_DELETE, &data)) state_->record(L"Shell_NotifyIconW(NIM_DELETE) failed", true);
            }
            DestroyWindow(window_);
            window_ = nullptr;
        }
        if (trayIcon_) { DestroyIcon(trayIcon_); trayIcon_ = nullptr; }
        if (singleton_) { CloseHandle(singleton_); singleton_ = nullptr; }
    }

    static LRESULT CALLBACK windowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* self = reinterpret_cast<TrayHost*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<TrayHost*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(window, message, wparam, lparam);
        try {
            if (message == self->taskbarCreated_ && self->taskbarCreated_) { self->addTray(); return 0; }
            switch (message) {
            case kDispatch: self->dispatch(); return 0;
            case WM_TIMER: self->dispatch(); return 0;
            case WM_WTSSESSION_CHANGE:
                if (self->pairing_ && ((static_cast<DWORD>(lparam) == self->session_ &&
                    (wparam == WTS_SESSION_LOCK || wparam == WTS_SESSION_LOGOFF || wparam == WTS_CONSOLE_DISCONNECT || wparam == WTS_REMOTE_CONNECT)) ||
                    WTSGetActiveConsoleSessionId() != self->session_)) self->finishPairing("enrollment_cancelled");
                if (wparam == WTS_SESSION_LOGOFF && static_cast<DWORD>(lparam) == self->session_) self->close();
                else self->reconcile(false);
                return 0;
            case WM_POWERBROADCAST:
                if (wparam == PBT_APMSUSPEND) self->suspended_ = true;
                if (wparam == PBT_APMRESUMEAUTOMATIC || wparam == PBT_APMRESUMESUSPEND) self->suspended_ = false;
                self->reconcile(false);
                return TRUE;
            case WM_QUERYENDSESSION:
                self->endingSession_ = true;
                self->reconcile(false);
                return TRUE;
            case WM_ENDSESSION:
                if (wparam) self->close();
                else { self->endingSession_ = false; self->reconcile(false); }
                return 0;
            case kTray:
                if (lparam == WM_RBUTTONUP) self->menu();
                if (lparam == WM_LBUTTONDBLCLK) self->showDetails();
                return 0;
            case WM_CLOSE: self->close(); return 0;
            case WM_DESTROY: PostQuitMessage(0); return 0;
            }
        } catch (...) {
            self->lastError_ = exceptionText();
            self->state_->record(self->lastError_, true);
            self->close();
            MessageBoxW(nullptr, self->lastError_.c_str(), L"GATT 错误，进程已停止", MB_OK | MB_ICONERROR);
            return message == WM_QUERYENDSESSION ? TRUE : 0;
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }

    std::shared_ptr<CallbackState> state_;
    GattHost host_;
    HWND window_ = nullptr;
    HANDLE singleton_ = nullptr;
    HICON trayIcon_ = nullptr;
    DWORD session_ = 0;
    UINT taskbarCreated_ = 0;
    bool sessionRegistered_ = false;
    bool trayAdded_ = false;
    bool closing_ = false;
    bool suspended_ = false;
    bool endingSession_ = false;
    std::wstring condition_ = L"广播停止";
    std::wstring lastError_;
    std::wstring initializationError_;
    std::shared_ptr<Pairing> pairing_;
    bool launchOutstanding_ = false;
    std::wstring helperPath_;
    std::wstring pairingOutcome_;
};

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    try {
        init_apartment(apartment_type::multi_threaded);
        struct Apartment final { ~Apartment() { uninit_apartment(); } } apartment;
        TrayHost app;
        return app.run(instance);
    } catch (...) {
        const auto error = exceptionText();
        MessageBoxW(nullptr, error.c_str(), L"GATT host 启动失败", MB_OK | MB_ICONERROR);
        return 1;
    }
}
