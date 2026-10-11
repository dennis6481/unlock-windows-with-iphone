// Created by Rui MA on 10 Oct 2026

#include <Windows.h>
#undef GetCurrentTime
#include <wtsapi32.h>
#include "../Bluetooth/SystemBleSession.h"
#include <winrt/Windows.Devices.Bluetooth.h>
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#include <winrt/Windows.Devices.Enumeration.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.Streams.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace winrt;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::Advertisement;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Foundation;
using namespace unlock_windows::system_ble;

constexpr wchar_t kDiagnosticService[] = L"UnlockWindowsSystemBleDiagnostic";
constexpr DWORD kPreparationMs = 10'000;
std::atomic<std::uint64_t> generation{0};
std::atomic<DWORD> consoleSession{0xffffffff};
handle stopEvent;
SERVICE_STATUS_HANDLE statusHandle = nullptr;
std::mutex statusMutex;

std::wstring exceptionText() {
    try { throw; }
    catch (const hresult_error& error) {
        return L"HRESULT=" + std::to_wstring(static_cast<std::uint32_t>(error.code().value)) +
            L"; " + std::wstring(error.message());
    }
    catch (const std::exception& error) { return std::wstring(to_hstring(error.what())); }
    catch (...) { return L"Unknown exception"; }
}

void require(bool condition, const wchar_t* message) {
    if (!condition) throw hresult_error(E_FAIL, message);
}

bool stopRequested(DWORD waitMs) {
    const DWORD result = WaitForSingleObject(stopEvent.get(), waitMs);
    if (result == WAIT_FAILED) throw_last_error();
    require(result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT, L"Unexpected diagnostic stop-event wait result.");
    return result == WAIT_OBJECT_0;
}

struct Logger final {
    std::mutex mutex;
    std::ofstream stream;
    std::atomic<bool> failed{false};

    Logger() {
        std::wstring executable(32768, L'\0');
        const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        check_bool(length && length < executable.size());
        executable.resize(length);
        const auto path = std::filesystem::path(executable).parent_path() / L"SystemBleDiagnostic.log";
        stream.open(path, std::ios::binary | std::ios::app);
        require(stream.is_open(), L"Cannot open SystemBleDiagnostic.log beside the diagnostic EXE.");
    }

    void write(const std::wstring& message) noexcept {
        try {
            const auto line = L"[" + std::to_wstring(GetTickCount64()) + L" ms; pid=" +
                std::to_wstring(GetCurrentProcessId()) + L"] " + message + L"\r\n";
            OutputDebugStringW(line.c_str());
            std::lock_guard lock(mutex);
            stream << to_string(line);
            stream.flush();
            if (!stream) throw std::runtime_error("diagnostic log write failed");
        } catch (...) {
            failed = true;
            OutputDebugStringW(L"System BLE diagnostic log write failed; this run cannot pass.\n");
        }
    }
};

void listEndpoints() {
    for (const bool ble : {false, true}) {
        const auto items = pairedEndpoints(ble).get();
        std::wcout << (ble ? L"BLE" : L"Bluetooth Classic") << L" paired endpoints:\n";
        for (const auto& item : items) {
            const auto id = containerId(item);
            std::wcout << L"  name=" << item.Name().c_str() << L"\n  container=" <<
                (id ? to_hstring(*id).c_str() : L"UNAVAILABLE") << L"\n  endpoint=" << item.Id().c_str() << L"\n";
        }
    }
    std::wcout << L"Select a container with exactly one Classic and one BLE endpoint. Names are display text only.\n";
}

struct Run final {
    std::shared_ptr<Logger> log;
    const std::uint64_t ticket = generation.load();
    const std::uint64_t started = GetTickCount64();
    const std::uint64_t deadline = started + kOperationLifetimeMs;
    std::atomic<bool> invalid{false}, passed{false};
    explicit Run(std::shared_ptr<Logger> value) : log(std::move(value)) {}
    void invalidate(const std::wstring& reason) { invalid = true; log->write(L"INVALIDATED: " + reason); }
};

IAsyncAction probe(const std::shared_ptr<Run> run, guid target, int threshold) {
    co_await resume_background();
    const auto cancellation = co_await get_cancellation_token();
    try {
        const auto classicItems = pairedEndpoints(false).get();
        const auto bleItems = pairedEndpoints(true).get();
        const auto classic = uniqueEndpoint(classicItems, target);
        const auto ble = uniqueEndpoint(bleItems, target);
        BindingRecord record{L"diagnostic", std::wstring(classic.Id()), std::wstring(ble.Id()), target,
            std::wstring(ble.Name()), threshold};
        run->log->write(L"BEGIN shared system BLE verification; unique Classic/BLE container; threshold=" + std::to_wstring(threshold));
        Session session(record, [run](const std::string& message) { run->log->write(std::wstring(winrt::to_hstring(message))); });
        session.beginRequest(run->started, [run, cancellation] {
            return !run->invalid && !cancellation() && generation.load() == run->ticket &&
                WTSGetActiveConsoleSessionId() == consoleSession.load() && !run->log->failed;
        });
        session.verify();
        const auto proof = session.evidence();
        run->log->write(L"Cached-mode ANCS structure and protected Uncached CCCD verification/unsubscribe completed; RSSI=" +
            std::to_wstring(proof.rssi) + L" dBm; age=" + std::to_wstring(GetTickCount64() - proof.rssiAt) + L" ms");
        session.close();
        require(!run->invalid && generation.load() == run->ticket && GetTickCount64() < run->deadline && !cancellation(),
            L"Diagnostic invalidated before completion");
        require(proof.failure == Failure::none && freshEvidence(proof.communicationAt, run->started, GetTickCount64()) &&
            freshEvidence(proof.rssiAt, run->started, GetTickCount64()), L"Evidence expired before diagnostic completion");
        run->passed = true;
        run->log->write(L"PASS: diagnostic evidence only; no credential or Windows unlock was requested");
    } catch (...) { run->log->write(L"FAIL: " + exceptionText()); run->invalid = true; }
}
void reportState(DWORD state, DWORD error = NO_ERROR) {
    std::lock_guard lock(statusMutex);
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ?
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_POWEREVENT : 0;
    status.dwWin32ExitCode = error == NO_ERROR ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR;
    status.dwServiceSpecificExitCode = error;
    status.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 5000 : 0;
    check_bool(SetServiceStatus(statusHandle, &status));
}

DWORD WINAPI control(DWORD code, DWORD event, void* data, void*) noexcept {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        ++generation;
        return SetEvent(stopEvent.get()) ? NO_ERROR : GetLastError();
    }
    if (code == SERVICE_CONTROL_SESSIONCHANGE && data) {
        const auto notification = static_cast<WTSSESSION_NOTIFICATION*>(data);
        if (notification->dwSessionId == consoleSession.load()) ++generation;
        return NO_ERROR;
    }
    if (code == SERVICE_CONTROL_POWEREVENT) {
        if (event == PBT_APMSUSPEND || event == PBT_APMRESUMEAUTOMATIC) ++generation;
        return NO_ERROR;
    }
    return code == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}

void verifyServiceIdentity(const std::shared_ptr<Logger>& log) {
    DWORD session = 0xffffffff;
    check_bool(ProcessIdToSessionId(GetCurrentProcessId(), &session));
    handle token;
    check_bool(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.put()));
    DWORD required = 0;
    if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &required) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        throw hresult_error(E_FAIL, L"Cannot obtain service token SID size.");
    std::vector<std::uint8_t> bytes(required);
    check_bool(GetTokenInformation(token.get(), TokenUser, bytes.data(), required, &required));
    const bool system = IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, WinLocalSystemSid) != FALSE;
    log->write(L"Process identity: LocalSystem=" + std::to_wstring(system) + L"; session=" + std::to_wstring(session));
    require(system && session == 0, L"This probe requires actual LocalSystem in Session 0; elevated desktop is not equivalent.");
}

void recordConsole(const std::shared_ptr<Logger>& log) {
    const DWORD session = consoleSession.load();
    require(WTSGetActiveConsoleSessionId() == session, L"Physical console changed before diagnostic start.");
    wchar_t* buffer = nullptr;
    DWORD bytes = 0;
    check_bool(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSSessionInfoEx, &buffer, &bytes));
    const bool valid = buffer && bytes >= sizeof(WTSINFOEXW) && reinterpret_cast<WTSINFOEXW*>(buffer)->Level == 1;
    const LONG flags = valid ? reinterpret_cast<WTSINFOEXW*>(buffer)->Data.WTSInfoExLevel1.SessionFlags : -1;
    if (buffer) WTSFreeMemory(buffer);
    require(valid && (flags == WTS_SESSIONSTATE_LOCK || flags == WTS_SESSIONSTATE_UNLOCK),
        L"Console session-state evidence unavailable.");
    log->write(L"Physical console session=" + std::to_wstring(session) + L"; SessionFlags=" +
        std::to_wstring(flags) + L" (0=locked, 1=unlocked)");
}

guid selectedContainer{};
int selectedThreshold = kDefaultThreshold;

void WINAPI serviceMain(DWORD, wchar_t**) noexcept {
    std::shared_ptr<Logger> log;
    try {
        statusHandle = RegisterServiceCtrlHandlerExW(kDiagnosticService, control, nullptr);
        check_bool(statusHandle != nullptr);
        reportState(SERVICE_START_PENDING);
        init_apartment(apartment_type::multi_threaded);
        log = std::make_shared<Logger>();
        verifyServiceIdentity(log);
        consoleSession = WTSGetActiveConsoleSessionId();
        require(consoleSession.load() != 0xffffffff && consoleSession.load() != 0, L"No physical-console user session for this test.");
        reportState(SERVICE_RUNNING);
        log->write(L"Preparation window: 10 seconds to lock PC/phone. This is a one-shot diagnostic, not production authentication.");
        if (!stopRequested(kPreparationMs)) {
            const auto run = std::make_shared<Run>(log);
            recordConsole(log);
            auto action = probe(run, selectedContainer, selectedThreshold);
            bool interrupted = false;
            while (action.Status() == AsyncStatus::Started) {
                if (stopRequested(100) ||
                    GetTickCount64() >= run->deadline || generation.load() != run->ticket) {
                    run->invalidate(L"Stop, deadline, power or console event; no late result accepted");
                    action.Cancel();
                    interrupted = true;
                    log->write(L"FAIL: pending operation invalidated. Connection cancellation/CCCD cleanup may not complete before process exit; no retry in this process.");
                    break;
                }
            }
            if (!interrupted) action.get();
            reportState(SERVICE_STOP_PENDING);
            const bool passed = !interrupted && run->passed && !run->invalid && !log->failed && generation.load() == run->ticket &&
                GetTickCount64() < run->deadline;
            log->write(passed ? L"SCM result: diagnostic succeeded" : L"SCM result: diagnostic failed/invalidated");
            reportState(SERVICE_STOPPED, passed && !log->failed ? NO_ERROR : ERROR_INVALID_DATA);
        } else {
            log->write(L"FAIL: stopped before diagnostic request started.");
            reportState(SERVICE_STOPPED, ERROR_CANCELLED);
        }
    } catch (...) {
        const auto message = L"Service diagnostic failed: " + exceptionText();
        if (log) log->write(message); else OutputDebugStringW(message.c_str());
        if (statusHandle) {
            try { reportState(SERVICE_STOPPED, ERROR_INVALID_DATA); }
            catch (...) { OutputDebugStringW(L"Cannot report diagnostic service failure to SCM.\n"); }
        }
    }
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--list") {
            init_apartment(apartment_type::multi_threaded);
            listEndpoints();
            return 0;
        }
        if ((argc != 3 && argc != 4) || std::wstring_view(argv[1]) != L"--service") {
            std::wcerr << L"Usage: unlock_system_ble_diagnostic --list\n"
                L"  SCM ImagePath: unlock_system_ble_diagnostic --service <system-container-GUID> [RSSI-threshold]\n"
                L"  Service name: " << kDiagnosticService << L"\n";
            return 2;
        }
        selectedContainer = guid{std::wstring_view(argv[2])};
        require(selectedContainer != guid{}, L"Nonzero system container GUID required.");
        if (argc == 4) {
            std::size_t consumed = 0;
            selectedThreshold = std::stoi(argv[3], &consumed);
            require(consumed == std::wstring_view(argv[3]).size() && selectedThreshold >= kMinimumThreshold &&
                selectedThreshold <= kMaximumThreshold, L"RSSI threshold outside supported slider range.");
        }
        stopEvent.attach(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        check_bool(static_cast<bool>(stopEvent));
        SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t*>(kDiagnosticService), serviceMain}, {nullptr, nullptr}};
        check_bool(StartServiceCtrlDispatcherW(table));
        return 0;
    } catch (...) {
        const auto message = exceptionText() + L"\n";
        OutputDebugStringW(message.c_str());
        std::wcerr << message;
        return 1;
    }
}
