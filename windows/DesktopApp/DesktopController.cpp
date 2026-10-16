// Created by Rui MA on 11 Oct 2026

#include "DesktopController.h"
#include "DesktopApp.h"
#include "../Enrollment/BindingClient.h"
#include "../Enrollment/EnrollmentSession.h"
#include <condition_variable>
#include <deque>
#include <mutex>
#include <chrono>
#include <cwchar>
#include <iterator>

namespace unlock_windows::desktop_app {
using namespace saved_credential;
namespace {
const wchar_t* diagnosticSourceName(DiagnosticSource source) {
    switch (source) {
    case DiagnosticSource::desktop: return L"Desktop";
    case DiagnosticSource::tray: return L"Tray";
    case DiagnosticSource::dashboard: return L"Dashboard";
    case DiagnosticSource::password: return L"Password";
    case DiagnosticSource::binding: return L"Binding";
    case DiagnosticSource::about: return L"About";
    case DiagnosticSource::setup: return L"Setup";
    case DiagnosticSource::service: return L"Service";
    case DiagnosticSource::serviceIpc: return L"Service IPC";
    case DiagnosticSource::lastUnlock: return L"Last Unlock";
    }
    throw std::invalid_argument("Unknown desktop diagnostic source");
}

std::wstring diagnosticPrefix(DiagnosticSource source, std::optional<NoticeSeverity> severity) {
    const wchar_t* level = L"RAW";
    if (severity) {
        switch (*severity) {
        case NoticeSeverity::information: level = L"INFO"; break;
        case NoticeSeverity::warning: level = L"WARN"; break;
        case NoticeSeverity::error: level = L"ERROR"; break;
        default: throw std::invalid_argument("Unknown desktop diagnostic severity");
        }
    }
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t timestamp[32]{};
    if (std::swprintf(timestamp, std::size(timestamp), L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
        static_cast<unsigned>(time.wYear), static_cast<unsigned>(time.wMonth), static_cast<unsigned>(time.wDay),
        static_cast<unsigned>(time.wHour), static_cast<unsigned>(time.wMinute),
        static_cast<unsigned>(time.wSecond), static_cast<unsigned>(time.wMilliseconds)) < 0)
        throw std::runtime_error("Could not format desktop diagnostic time");
    return L"\t" + std::wstring(timestamp) + L" [" + level + L"] [" + diagnosticSourceName(source) +
        L"] tickMs=" + std::to_wstring(GetTickCount64()) + L" ";
}
}

struct ControllerState final {
    std::mutex mutex;
    std::condition_variable wake;
    std::deque<TrayCommand> commands;
    bool stopping = false, ready = false, failed = false, busy = false;
    std::optional<DashboardSnapshot> snapshot;
    std::vector<DesktopNotice> notices;
    std::wstring diagnostics, error, serviceDiagnostic;
    std::wstring queryDiagnostic, lastUnlockDiagnostic;
    std::function<bool()> notify;
    winrt::handle setupCancellation;

    void record(DiagnosticSource source, std::optional<NoticeSeverity> severity,
                const std::wstring& value, bool failure = false) {
        const auto prefix = diagnosticPrefix(source, severity);
        std::wstring entries;
        for (std::size_t start = 0; start < value.size();) {
            const auto end = value.find(L'\n', start);
            auto line = value.substr(start, end == std::wstring::npos ? end : end - start);
            if (!line.empty() && line.back() == L'\r') line.pop_back();
            if (!line.empty()) {
                entries += prefix + line + L"\r\n";
            }
            if (end == std::wstring::npos) break;
            start = end + 1;
        }
        if (!entries.empty()) OutputDebugStringW(entries.c_str());
        std::lock_guard lock(mutex);
        diagnostics += entries;
        if (diagnostics.size() > 16000) diagnostics.erase(0, diagnostics.find(L'\n', 8000) + 1);
        if (failure) error = value;
    }
    void recordChangedError(DiagnosticSource source, std::wstring& previous, const std::wstring& message) {
        const auto current = message.empty() ? std::wstring{} : std::wstring(diagnosticSourceName(source)) + L": " + message;
        if (previous == current) return;
        previous = current;
        if (!message.empty()) record(source, NoticeSeverity::error, message);
    }
    void publish() {
        DashboardSnapshot status;
        auto querySource = DiagnosticSource::desktop;
        try {
            const auto console = enrollment::queryConsole();
            if (console.locked) return;
            const auto lockedDuringQuery = [&console] {
                const auto current = enrollment::queryConsole();
                return current.locked && current.session == console.session && current.sid == console.sid;
            };
            std::wstring serviceMessage;
            bool serviceQueryFailed = false;
            querySource = DiagnosticSource::serviceIpc;
            Packet response;
            CallDiagnostics callDiagnostics;
            if (!call(Operation::serviceDiagnostics, SensitiveBytes{}, response, kPipeTransferLifetimeMs, &callDiagnostics)) {
                serviceQueryFailed = true;
                serviceMessage = L"Diagnostics query failed; stage=" + std::wstring(callStageName(callDiagnostics.stage)) +
                    L"; win32=" + std::to_wstring(callDiagnostics.win32Error);
            } else if (response.result != Result::success) {
                if (response.result == Result::rejected && lockedDuringQuery()) return;
                serviceQueryFailed = true;
                serviceMessage = L"Diagnostics query rejected; result=" + std::to_wstring(static_cast<unsigned>(response.result));
            } else if (!response.payload.value.empty()) {
                serviceMessage = winrt::to_hstring(std::string(response.payload.value.begin(), response.payload.value.end()));
            }
            if (serviceMessage != serviceDiagnostic) {
                std::size_t overlap = 0;
                for (std::size_t start = 0; start < serviceDiagnostic.size();) {
                    if (serviceMessage.starts_with(serviceDiagnostic.substr(start))) {
                        overlap = serviceDiagnostic.size() - start;
                        break;
                    }
                    const auto end = serviceDiagnostic.find(L'\n', start);
                    if (end == std::wstring::npos) break;
                    start = end + 1;
                }
                const auto newMessage = serviceMessage.substr(overlap);
                serviceDiagnostic = serviceMessage;
                if (!newMessage.empty()) record(serviceQueryFailed ? DiagnosticSource::serviceIpc : DiagnosticSource::service,
                    serviceQueryFailed ? std::optional{NoticeSeverity::error} : std::nullopt, newMessage);
            }
            querySource = DiagnosticSource::binding;
            try {
                const auto binding = enrollment::readBinding();
                status.binding = binding;
                status.status = binding.state == system_ble::BindingState::bound ? L"iPhone bound" :
                    L"Bind an iPhone";
            } catch (const enrollment::BindingStatusRejected&) {
                if (lockedDuringQuery()) return;
                throw;
            }
            if (status.binding->state == system_ble::BindingState::bound) {
                try {
                    Packet history;
                    CallDiagnostics diagnostics;
                    if (!call(Operation::lastUnlockStatus, SensitiveBytes{}, history, kPipeTransferLifetimeMs, &diagnostics))
                        throw std::runtime_error("Last unlock query failed; stage=" +
                            winrt::to_string(callStageName(diagnostics.stage)) + "; win32=" +
                            std::to_string(diagnostics.win32Error));
                    if (history.result != Result::success) {
                        if (history.result == Result::rejected && lockedDuringQuery()) return;
                        throw std::runtime_error("Last unlock query rejected; result=" +
                            std::to_string(static_cast<unsigned>(history.result)));
                    }
                    if (!decodeLastUnlock(history.payload.value.data(), history.payload.value.size(), status.lastUnlock) ||
                        (status.lastUnlock && status.lastUnlock->completedAt > GetTickCount64()))
                        throw std::runtime_error("Last unlock reply is invalid.");
                } catch (...) { status.lastUnlock.reset(); status.error = winrt::to_message(); }
                recordChangedError(DiagnosticSource::lastUnlock, lastUnlockDiagnostic, status.error);
            } else {
                lastUnlockDiagnostic.clear();
            }
            queryDiagnostic.clear();
        } catch (...) {
            status.error = winrt::to_message(); status.status = L"Binding status unavailable";
            recordChangedError(querySource, queryDiagnostic, status.error);
        }
        {
            std::lock_guard lock(mutex);
            status.busy = busy;
            if (!error.empty()) status.error += (status.error.empty() ? L"" : L"\n") + error;
            status.diagnostics = diagnostics;
            snapshot = std::move(status);
        }
        if (!notify()) record(DiagnosticSource::desktop, NoticeSeverity::error,
            L"Status dispatcher rejected; timer will observe status");
    }
    void notice(DiagnosticSource source, const std::wstring& value) {
        record(source, NoticeSeverity::error, value, true);
        { std::lock_guard lock(mutex); notices.push_back({value, L"Setup needs attention", NoticeSeverity::error}); }
        if (!notify()) record(DiagnosticSource::desktop, NoticeSeverity::error, L"Notice dispatcher rejected");
    }
    bool stopRequested() { std::lock_guard lock(mutex); return stopping; }

    void execute(TrayCommand command) {
        if (command == TrayCommand::status) return;
        const auto target = enrollment::queryConsole();
        if (target.locked || target.sid != system_ble::EnrollmentStore::currentUserSid() || enrollment::elevatedAdmin())
            throw std::runtime_error("Use the ordinary target user's unlocked physical console");
        if (command == TrayCommand::continueSetup) {
            std::wstring eventName;
            auto cancellation = enrollment::createSetupCancellation(target.sid, eventName);
            {
                std::lock_guard lock(mutex);
                if (stopping) return;
                setupCancellation = std::move(cancellation);
            }
            DWORD result = 0;
            try {
                result = enrollment::launchHelper(std::wstring(kSavedPasswordRole) + L" " + kSetupRole +
                    L" " + kSetupCancelArgument + L" \"" + eventName + L"\"");
            } catch (const winrt::hresult_error& failure) {
                { std::lock_guard lock(mutex); setupCancellation.close(); }
                if (failure.code() == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
                    record(DiagnosticSource::setup, NoticeSeverity::information, L"Elevation cancelled");
                    return;
                }
                throw;
            }
            { std::lock_guard lock(mutex); setupCancellation.close(); }
            if (result == static_cast<DWORD>(SetupResult::cancelled) || stopRequested()) return;
            if (result != static_cast<DWORD>(SetupResult::credentialReady)) throw std::runtime_error("Saving the password did not complete");
            const auto current = enrollment::queryConsole();
            if (current.locked || current.session != target.session || current.sid != target.sid)
                throw std::runtime_error("The console account changed during setup");
            const auto binding = enrollment::readBinding();
            if (binding.state == system_ble::BindingState::bound) {
                if (binding.record.accountSid != target.sid) throw std::runtime_error("The bound phone belongs to a different account");
                { std::lock_guard lock(mutex); notices.push_back({L"Password and iPhone binding are saved. Lock this PC and click Unlock to try it.", L"Setup configured", NoticeSeverity::information}); }
                return;
            }
        }
    }
};

DesktopController::DesktopController(std::function<bool()> wake) : state_(std::make_shared<ControllerState>()) { state_->notify = std::move(wake); }
void DesktopController::start() {
    thread_ = std::thread([state = state_] {
        try {
            winrt::init_apartment(winrt::apartment_type::multi_threaded);
            struct Apartment final { ~Apartment() { winrt::uninit_apartment(); } } apartment;
            { std::lock_guard lock(state->mutex); state->ready = true; }
            for (;;) {
                TrayCommand command = TrayCommand::status;
                {
                    std::unique_lock lock(state->mutex);
                    state->wake.wait_for(lock, std::chrono::seconds(1), [&] { return state->stopping || !state->commands.empty(); });
                    if (state->stopping) break;
                    if (!state->commands.empty()) { command = state->commands.front(); state->commands.pop_front(); }
                    state->busy = command != TrayCommand::status;
                }
                if (command != TrayCommand::status) state->publish();
                try { state->execute(command); }
                catch (...) {
                    const auto message = std::wstring(winrt::to_message());
                    if (state->stopRequested()) state->record(DiagnosticSource::setup, NoticeSeverity::error, message, true);
                    else state->notice(DiagnosticSource::setup, message);
                }
                { std::lock_guard lock(state->mutex); state->busy = false; }
                if (!state->stopRequested()) state->publish();
            }
        } catch (...) {
            state->notice(DiagnosticSource::desktop, std::wstring(winrt::to_message()));
            std::lock_guard lock(state->mutex); state->failed = true;
        }
        { std::lock_guard lock(state->mutex); state->stopping = true; }
        if (!state->notify()) state->record(DiagnosticSource::desktop, NoticeSeverity::error, L"Shutdown dispatcher rejected");
    });
}
bool DesktopController::command(TrayCommand command) {
    std::lock_guard lock(state_->mutex);
    if (state_->stopping || (command != TrayCommand::status && (state_->busy || !state_->commands.empty()))) return false;
    if (state_->commands.empty()) state_->commands.push_back(command);
    state_->wake.notify_one(); return true;
}
void DesktopController::requestStop() {
    std::wstring failure;
    {
        std::lock_guard lock(state_->mutex);
        state_->stopping = true; state_->commands.clear();
        if (state_->setupCancellation && !SetEvent(state_->setupCancellation.get()))
            failure = L"Setup cancellation failed; win32=" + std::to_wstring(GetLastError());
    }
    if (!failure.empty()) state_->record(DiagnosticSource::setup, NoticeSeverity::error, failure);
    state_->wake.notify_one();
}
DesktopUpdate DesktopController::takeUpdate() {
    std::lock_guard lock(state_->mutex);
    DesktopUpdate update{state_->ready, state_->stopping, state_->failed, std::move(state_->snapshot), {}};
    state_->snapshot.reset(); update.notices.swap(state_->notices); return update;
}
bool DesktopController::ended() {
    if (!thread_.joinable()) return true;
    const auto result = WaitForSingleObject(thread_.native_handle(), 0);
    enrollment::require(result != WAIT_FAILED, "Observe desktop worker"); return result == WAIT_OBJECT_0;
}
void DesktopController::join() {
    if (thread_.joinable()) { if (!ended()) throw std::logic_error("Desktop worker is still running"); thread_.join(); }
}
void DesktopController::record(DiagnosticSource source, NoticeSeverity severity, const std::wstring& message) {
    state_->record(source, severity, message);
}
std::function<void(std::wstring)> DesktopController::errorReporter(DiagnosticSource source, std::wstring title, bool notify) {
    return [state = state_, source, title = std::move(title), notify](std::wstring message) {
        state->record(source, NoticeSeverity::error, message);
        if (notify) { std::lock_guard lock(state->mutex); state->notices.push_back({message, title, NoticeSeverity::error}); }
    };
}
}
