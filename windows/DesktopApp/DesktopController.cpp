// Created by Rui MA on 11 Oct 2026

#include "DesktopController.h"
#include "DesktopApp.h"
#include "../Enrollment/BindingClient.h"
#include "../Enrollment/EnrollmentSession.h"
#include <condition_variable>
#include <deque>
#include <mutex>
#include <chrono>

namespace unlock_windows::desktop_app {
using namespace saved_credential;
struct ControllerState final {
    std::mutex mutex;
    std::condition_variable wake;
    std::deque<TrayCommand> commands;
    bool stopping = false, ready = false, failed = false, busy = false;
    std::optional<DashboardSnapshot> snapshot;
    std::vector<DesktopNotice> notices;
    std::wstring diagnostics, error, serviceDiagnostic;
    std::function<bool()> notify;
    winrt::handle setupCancellation;

    void record(const std::wstring& value, bool failure = false) {
        OutputDebugStringW((value + L"\n").c_str());
        std::lock_guard lock(mutex);
        diagnostics += L"tickMs=" + std::to_wstring(GetTickCount64()) + L" " + value + L"\r\n";
        if (diagnostics.size() > 16000) diagnostics.erase(0, diagnostics.find(L'\n', 8000) + 1);
        if (failure) error = value;
    }
    void publish() {
        DashboardSnapshot status;
        try {
            const auto console = enrollment::queryConsole();
            if (console.locked) return;
            const auto lockedDuringQuery = [&console] {
                const auto current = enrollment::queryConsole();
                return current.locked && current.session == console.session && current.sid == console.sid;
            };
            std::wstring serviceMessage;
            Packet response;
            CallDiagnostics callDiagnostics;
            if (!call(Operation::serviceDiagnostics, SensitiveBytes{}, response, kPipeTransferLifetimeMs, &callDiagnostics)) {
                serviceMessage = L"Service diagnostics query failed (Win32 " + std::to_wstring(callDiagnostics.win32Error) +
                    L"). Ensure the installed service supports serviceDiagnostics.";
            } else if (response.result != Result::success) {
                if (response.result == Result::rejected && lockedDuringQuery()) return;
                serviceMessage = L"Service diagnostics query rejected (result " + std::to_wstring(static_cast<unsigned>(response.result)) + L").";
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
                if (!newMessage.empty()) record(L"[Service] " + newMessage);
            }
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
                        throw std::runtime_error("Last unlock query failed at " +
                            winrt::to_string(callStageName(diagnostics.stage)) + " (Win32 " +
                            std::to_string(diagnostics.win32Error) + ").");
                    if (history.result != Result::success) {
                        if (history.result == Result::rejected && lockedDuringQuery()) return;
                        throw std::runtime_error("Last unlock query rejected (result " +
                            std::to_string(static_cast<unsigned>(history.result)) + ").");
                    }
                    if (!decodeLastUnlock(history.payload.value.data(), history.payload.value.size(), status.lastUnlock) ||
                        (status.lastUnlock && status.lastUnlock->completedAt > GetTickCount64()))
                        throw std::runtime_error("Last unlock reply is invalid.");
                } catch (...) { status.lastUnlock.reset(); status.error = winrt::to_message(); }
            }
        } catch (...) { status.error = winrt::to_message(); status.status = L"Binding status unavailable"; }
        {
            std::lock_guard lock(mutex);
            status.busy = busy;
            if (!error.empty()) status.error += (status.error.empty() ? L"" : L"\n") + error;
            status.diagnostics = diagnostics;
            snapshot = std::move(status);
        }
        if (!notify()) OutputDebugStringW(L"Desktop status dispatcher rejected; timer will observe status\n");
    }
    void notice(const std::wstring& value) {
        record(value, true);
        { std::lock_guard lock(mutex); notices.push_back({value, L"Setup needs attention", NoticeSeverity::error}); }
        if (!notify()) OutputDebugStringW(L"Desktop notice dispatcher rejected\n");
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
                    record(L"Setup elevation cancelled");
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
                state->publish();
                try { state->execute(command); }
                catch (...) {
                    const auto message = std::wstring(winrt::to_message());
                    if (state->stopRequested()) state->record(message, true);
                    else state->notice(message);
                }
                { std::lock_guard lock(state->mutex); state->busy = false; }
                if (!state->stopRequested()) state->publish();
            }
        } catch (...) {
            state->notice(std::wstring(winrt::to_message()));
            std::lock_guard lock(state->mutex); state->failed = true;
        }
        { std::lock_guard lock(state->mutex); state->stopping = true; }
        if (!state->notify()) OutputDebugStringW(L"Desktop shutdown dispatcher rejected\n");
    });
}
bool DesktopController::command(TrayCommand command) {
    std::lock_guard lock(state_->mutex);
    if (state_->stopping || (command != TrayCommand::status && (state_->busy || !state_->commands.empty()))) return false;
    if (state_->commands.empty()) state_->commands.push_back(command);
    state_->wake.notify_one(); return true;
}
void DesktopController::requestStop() {
    std::lock_guard lock(state_->mutex);
    state_->stopping = true; state_->commands.clear();
    if (state_->setupCancellation && !SetEvent(state_->setupCancellation.get())) {
        const auto message = L"Desktop setup cancellation failed; win32=" + std::to_wstring(GetLastError()) + L"\n";
        OutputDebugStringW(message.c_str());
    }
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
void DesktopController::record(const std::wstring& message) { state_->record(message); }
std::function<void(std::wstring)> DesktopController::errorReporter(std::wstring title, bool notify) {
    return [state = state_, title = std::move(title), notify](std::wstring message) {
        state->record(message);
        if (notify) { std::lock_guard lock(state->mutex); state->notices.push_back({message, title, NoticeSeverity::error}); }
    };
}
}
