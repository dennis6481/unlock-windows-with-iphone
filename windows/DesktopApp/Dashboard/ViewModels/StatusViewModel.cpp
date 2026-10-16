// Created by Rui MA on 16 Oct 2026

#include "StatusViewModel.h"
#include "StatusViewModel.g.cpp"
#include "PairedDevice.h"
#include "../../DesktopErrors.h"
#include "../../../Enrollment/BindingClient.h"
#include "../../../Enrollment/EnrollmentSession.h"
#include "../../../Bluetooth/SystemBleSession.h"
#include <winrt/Windows.System.h>
#include <map>
#include <chrono>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows;
using namespace unlock_windows::desktop_app::dashboard_ui;
using namespace saved_credential;
using Microsoft::UI::Xaml::Visibility;
using namespace Windows::Devices::Enumeration;

/// Own the existing enrollment operation lifetime independently of the cached view.
struct StatusViewModel::BindingSession : std::enable_shared_from_this<BindingSession> {
    weak_ref<StatusViewModel> owner;
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher{nullptr};
    std::map<std::wstring, DeviceInformation> items;
    std::wstring selectedKey, eventName, status;
    std::vector<std::function<void()>> revoke;
    handle cancelEvent;
    enrollment::Console target;
    BindingSummary original;
    bool busy = false, scanning = false, scanAgain = false, stopping = false, remove = false;
    std::uint64_t generation = 0, listRevision = 0;

    /// Capture the view model without extending its lifetime through watchers.
    explicit BindingSession(weak_ref<StatusViewModel> model) : owner(std::move(model)) {}
    /// Publish only while this is still the view model's active enrollment session.
    void publish() {
        if (auto model = owner.get(); model && model->session_.get() == this && !model->stopped_) model->Publish();
    }
    /// Preserve console identity, generation and cancellation checks before each step.
    void check(std::uint64_t ticket) {
        const auto current = enrollment::queryConsole();
        if (stopping || generation != ticket || current.locked || current.sid != target.sid || current.session != target.session)
            throw hresult_error(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"Binding cancelled or console account changed");
        if (cancelEvent && WaitForSingleObject(cancelEvent.get(), 0) != WAIT_TIMEOUT)
            throw hresult_error(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"Binding cancelled by the desktop host");
    }
    /// Publish the existing enrollment status without touching a control.
    void message(const std::wstring& value) { status = value; OutputDebugStringW((value + L"\n").c_str()); publish(); }
    /// Rebuild the paired-device projections while preserving a valid selection.
    void render() {
        const auto model = owner.get();
        if (!model || model->session_.get() != this || stopping) return;
        model->rendering_ = true;
        model->devices_.Clear();
        model->selected_ = nullptr;
        for (const auto& [id, item] : items) {
            if (!item.Pairing().IsPaired()) continue;
            auto choice = make<PairedDevice>(hstring{id}, item.Name());
            model->devices_.Append(choice);
            if (id == selectedKey) model->selected_ = choice;
        }
        if (!model->selected_) selectedKey.clear();
        model->rendering_ = false;
        model->Notify({L"SelectedDevice"});
        publish();
    }
    /// Preserve watcher updates and list revisions on the owning UI apartment.
    void watch() {
        auto watcher = DeviceInformation::CreateWatcher(system_ble::deviceSelector(),
            single_threaded_vector<hstring>({L"System.Devices.Aep.IsPaired"}), DeviceInformationKind::AssociationEndpoint);
        const auto weak = weak_from_this();
        auto post = [weak](std::function<void(BindingSession&)> action) {
            if (auto self = weak.lock()) {
                if (!self->dispatcher.TryEnqueue([weak, action = std::move(action)] {
                    if (auto current = weak.lock(); current && !current->stopping) {
                        try { ++current->listRevision; action(*current); current->render(); }
                        catch (...) { current->message(currentException()); }
                    }
                })) OutputDebugStringW(L"Binding device update dispatcher rejected\n");
            }
        };
        const auto added = watcher.Added([post](const auto&, DeviceInformation item) {
            post([item](auto& self) { self.items.insert_or_assign(std::wstring(item.Id()), item); });
        });
        const auto updated = watcher.Updated([post](const auto&, DeviceInformationUpdate update) {
            post([update](auto& self) {
                const auto found = self.items.find(std::wstring(update.Id()));
                if (found != self.items.end()) found->second.Update(update);
                else self.scan();
            });
        });
        const auto removed = watcher.Removed([post](const auto&, DeviceInformationUpdate update) {
            post([update](auto& self) { self.items.erase(std::wstring(update.Id())); });
        });
        const auto stopped = watcher.Stopped([post](const auto&, const auto&) {
            post([](auto& self) { self.message(L"Device enumeration stopped. Reopen the app to update the device list."); });
        });
        revoke.push_back([watcher, added, updated, removed, stopped] {
            watcher.Added(added); watcher.Updated(updated); watcher.Removed(removed); watcher.Stopped(stopped);
            if (watcher.Status() == DeviceWatcherStatus::Started || watcher.Status() == DeviceWatcherStatus::EnumerationCompleted) watcher.Stop();
        });
        watcher.Start();
    }
    /// Preserve coalesced scans and discard snapshots overtaken by watcher updates.
    fire_and_forget scan() {
        if (stopping) co_return;
        auto lifetime = shared_from_this();
        if (scanning) { scanAgain = true; co_return; }
        scanning = true;
        const auto revision = listRevision;
        try {
            const auto bleItems = co_await system_ble::pairedEndpoints();
            if (!stopping && revision == listRevision) {
                items.clear();
                for (auto item : bleItems) items.insert_or_assign(std::wstring(item.Id()), item);
                render();
            } else if (!stopping) scanAgain = true;
        } catch (...) { if (!stopping) message(currentException()); }
        scanning = false;
        if (scanAgain && !stopping) { scanAgain = false; scan(); }
        if (stopping && !busy) finish();
    }
    /// Enter the same binding/removal busy state before submitting work.
    void start(bool clear = false) {
        if (busy || stopping) return;
        remove = clear; busy = true;
        if (auto model = owner.get()) model->saveError_.clear();
        message(L"");
        run();
    }
    /// Preserve binding request order, elevation, 100 ms progress polling and readback.
    fire_and_forget run() {
        auto lifetime = shared_from_this();
        const auto ticket = generation;
        apartment_context foreground;
        std::wstring failure;
        bool bindingChanged = false;
        try {
            check_bool(ResetEvent(cancelEvent.get()));
            check(ticket);
            co_await resume_background(); original = enrollment::readBinding(); co_await foreground;
            check(ticket);
            if (remove) {
                SensitiveBytes bytes;
                if (!encodeBindingRemoval({original, eventName}, bytes)) throw hresult_error(E_INVALIDARG);
                co_await resume_background(); enrollment::manageBinding(Operation::removeBinding, bytes); co_await foreground;
                bindingChanged = true;
                message(L"Product binding removed. Windows pairing is unchanged.");
            } else {
                if (original.state == system_ble::BindingState::bound)
                    throw hresult_error(E_FAIL, L"Remove the current iPhone binding before binding another device");
                if (!items.contains(selectedKey)) throw hresult_error(E_FAIL, L"Select a paired device first");
                const auto endpointId = selectedKey;
                auto selected = items.at(endpointId);
                if (!selected.Pairing().IsPaired()) throw hresult_error(E_FAIL, L"Finish pairing in Windows Bluetooth settings, then return and select the device");
                check(ticket);
                const auto paired = co_await system_ble::pairedEndpoints();
                check(ticket);
                const auto bleItem = system_ble::findUniqueEndpoint(paired, hstring{endpointId});
                if (!bleItem || !bleItem.Pairing().IsPaired())
                    throw hresult_error(E_FAIL, L"The selected BLE endpoint is no longer paired. Pair it in Windows Bluetooth settings, then select it again.");
                BindingChange change{original, {target.sid, {}, std::wstring(bleItem.Id()),
                    {}, std::wstring(bleItem.Name()), system_ble::kDefaultThreshold}, eventName};
                SensitiveBytes bytes;
                if (!encodeBindingChange(change, bytes)) throw hresult_error(E_INVALIDARG, L"Invalid system binding");
                co_await resume_background(); enrollment::manageBinding(Operation::beginBinding, bytes); co_await foreground;
                for (;;) {
                    check(ticket); co_await resume_background();
                    Packet response;
                    if (!call(Operation::bindingTaskStatus, SensitiveBytes{}, response)) throw std::runtime_error("Binding task status unavailable");
                    AuthenticationStatus progress;
                    if (response.result != Result::success || !decodeAuthenticationStatus(response.payload.value.data(), response.payload.value.size(), progress))
                        throw std::runtime_error("Binding status rejected or malformed");
                    co_await foreground;
                    if (progress.stage == AuthenticationStage::failed) throw hresult_error(E_FAIL, authenticationStatusText(progress));
                    if (progress.stage == AuthenticationStage::completed) { message(L"iPhone binding saved. Lock this PC and click Unlock to try it."); break; }
                    if (progress.stage != AuthenticationStage::verifying) throw hresult_error(E_FAIL, L"No active binding task");
                    co_await resume_after(std::chrono::milliseconds(100)); co_await foreground;
                }
                bindingChanged = true;
            }
            co_await resume_background(); original = enrollment::readBinding(); co_await foreground;
        } catch (...) { failure = currentException(); }
        co_await foreground;
        if (!failure.empty()) {
            message(failure);
            if (auto model = owner.get(); model && !model->stopped_) {
                model->saveError_ = failure; model->reportError_(failure);
            }
        }
        busy = false;
        publish();
        if (stopping && !scanning) finish(); else if (!stopping) scan();
        if (bindingChanged && failure.empty() && !stopping) {
            if (auto model = owner.get(); model && !model->stopped_ && model->session_.get() == this) {
                try {
                    model->resetSession_ = original.state != system_ble::BindingState::bound;
                    model->saveError_.clear();
                    model->SuccessOpen(!model->resetSession_);
                    model->refreshSnapshot_(true);
                } catch (...) {
                    failure = currentException(); message(failure);
                    model->saveError_ = failure; model->reportError_(failure);
                }
                model->Publish();
            }
        }
    }
    /// Cancel without releasing watchers before active asynchronous work drains.
    void stop() {
        if (stopping) return;
        stopping = true; ++generation;
        if (cancelEvent && !SetEvent(cancelEvent.get())) message(L"Binding cancellation event could not be signalled");
        if (!busy && !scanning) finish();
    }
    /// Release the existing watcher event registrations after work finishes.
    void finish() { for (auto& action : revoke) action(); revoke.clear(); }
    /// Verify the ordinary console user before creating cancellation and enumeration resources.
    void initialize() {
        dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
        target = enrollment::queryConsole();
        if (target.locked || target.sid != system_ble::EnrollmentStore::currentUserSid() || enrollment::elevatedAdmin())
            throw hresult_error(E_ACCESSDENIED, L"Bind from the ordinary target user's unlocked physical console");
        cancelEvent = enrollment::createCancellation(target.sid, eventName);
        watch(); scan();
    }
};

StatusViewModel::StatusViewModel() {
    const auto weak = get_weak();
    using desktop_app::ViewModelCommand;
    bind_ = make_self<ViewModelCommand>([weak] { if (auto model = weak.get()) model->StartBinding(false); },
        [weak] { auto model = weak.get(); return model && model->BindingEnabled() && model->session_ &&
            !model->session_->selectedKey.empty() && !model->session_->busy && !model->session_->stopping; });
    remove_ = make_self<ViewModelCommand>([weak] { if (auto model = weak.get()) model->StartBinding(true); },
        [weak] { auto model = weak.get(); return model && model->ManagementEnabled(); });
    save_ = make_self<ViewModelCommand>([weak] { SaveRange(weak); },
        [weak] { auto model = weak.get(); return model && model->CanFinishRange() && model->binding_ &&
            model->binding_->state == system_ble::BindingState::bound && model->RangeDirty(); });
    settings_ = make_self<ViewModelCommand>([weak] { OpenSettings(weak); },
        [weak] { auto model = weak.get(); return model && model->BindingEnabled(); });
}
hstring StatusViewModel::DeviceName() const {
    if (!snapshot_.binding) return L"Binding status unavailable";
    if (snapshot_.binding->state != system_ble::BindingState::bound) return L"No iPhone bound";
    return snapshot_.binding->record.displayName.empty() ? hstring{L"Name unavailable"} : hstring{snapshot_.binding->record.displayName};
}
hstring StatusViewModel::LastUnlock() const { return hstring{desktop_app::lastUnlockText(snapshot_.lastUnlock, GetTickCount64())}; }
hstring StatusViewModel::Error() const { return hstring{saveError_.empty() ? snapshot_.error : saveError_}; }
void StatusViewModel::SuccessOpen(bool value) {
    if (success_ == value) return;
    success_ = value;
    if (value) { successVisible_ = true; Notify({L"SuccessVisibility"}); }
    Notify({L"SuccessOpen"});
}
void StatusViewModel::SuccessClosed() { successVisible_ = false; Notify({L"SuccessVisibility"}); }
Visibility StatusViewModel::SuccessVisibility() const { return successVisible_ ? Visibility::Visible : Visibility::Collapsed; }
Visibility StatusViewModel::BoundVisibility() const { return snapshot_.binding && snapshot_.binding->state == system_ble::BindingState::bound ? Visibility::Visible : Visibility::Collapsed; }
Visibility StatusViewModel::BindingVisibility() const { return snapshot_.binding && snapshot_.binding->state != system_ble::BindingState::bound && session_ ? Visibility::Visible : Visibility::Collapsed; }
Visibility StatusViewModel::EmptyVisibility() const { return devices_.Size() ? Visibility::Collapsed : Visibility::Visible; }
Visibility StatusViewModel::ProgressVisibility() const { return BindingBusy() ? Visibility::Visible : Visibility::Collapsed; }
bool StatusViewModel::BindingEnabled() const { return snapshot_.binding.has_value() && !snapshot_.busy && !saving_ && !stopped_; }
bool StatusViewModel::DevicesEnabled() const { return !session_ || !session_->busy; }
bool StatusViewModel::ManagementEnabled() const { return BoundVisibility() == Visibility::Visible && !snapshot_.busy && !Busy() && !stopped_; }
bool StatusViewModel::BindingBusy() const { return session_ && session_->busy && !session_->remove; }
hstring StatusViewModel::BindingMessage() const { return session_ ? hstring{session_->status} : hstring{}; }
hstring StatusViewModel::BindLabel() const { return BindingBusy() ? L"Binding\u2026" : L"Bind selected device"; }
hstring StatusViewModel::BindAutomationName() const { return BindingBusy() ? L"Binding in progress" : L"Bind selected device"; }
bool StatusViewModel::Busy() const { return saving_ || (session_ && session_->busy); }
void StatusViewModel::SelectedDevice(const UnlockDesktop::PairedDevice& device) {
    if (rendering_) return;
    selected_ = device;
    if (session_) session_->selectedKey = device ? std::wstring(device.EndpointId()) : std::wstring{};
    Notify({L"SelectedDevice"}); bind_->Invalidate();
}
void StatusViewModel::SetHost(std::function<void(bool)> refresh, desktop_app::Dashboard::ReportError reportError) {
    refreshSnapshot_ = std::move(refresh); reportError_ = std::move(reportError);
}
bool StatusViewModel::Update(const desktop_app::DashboardSnapshot& snapshot) {
    if (snapshot.binding && snapshot.binding->state != system_ble::BindingState::bound && binding_ &&
        binding_->state == system_ble::BindingState::bound) SuccessOpen(false);
    snapshot_ = snapshot;
    const bool bound = BoundVisibility() == Visibility::Visible;
    const bool reset = resetSession_ && snapshot.binding && !bound && !Busy();
    if ((bound || reset) && session_ && !session_->busy) {
        session_->stop(); session_.reset(); selected_ = nullptr; devices_.Clear();
        Notify({L"SelectedDevice"});
    }
    if (reset) { saveError_.clear(); resetSession_ = false; }
    if (snapshot.binding && !bound && !snapshot.busy && !session_ && !stopped_) {
        try { EnsureSession(); }
        catch (...) {
            const auto failure = currentException();
            if (failure != saveError_) reportError_(failure);
            saveError_ = failure;
        }
    }
    bool resetRange = false;
    if (!saving_) {
        resetRange = binding_ != snapshot.binding || snapshot.busy || stopped_;
        binding_ = snapshot.binding;
    }
    Publish();
    return resetRange;
}
void StatusViewModel::EnsureSession() {
    if (session_) return;
    auto session = std::make_shared<BindingSession>(get_weak());
    session_ = session;
    try { session->initialize(); }
    catch (...) { session->stop(); session_.reset(); throw; }
}
void StatusViewModel::Refresh() { if (session_ && !stopped_) session_->scan(); }
void StatusViewModel::StartBinding(bool remove) {
    if (stopped_ || snapshot_.busy || Busy()) return;
    if (remove && (!binding_ || binding_->state != system_ble::BindingState::bound)) return;
    try { EnsureSession(); session_->start(remove); Publish(); }
    catch (...) { saveError_ = currentException(); reportError_(saveError_); Publish(); }
}
bool StatusViewModel::RangeDirty() const { return binding_ && nearestDistanceThreshold(-range_) != nearestDistanceThreshold(binding_->record.threshold); }
void StatusViewModel::ResetRange() {
    if (saving_) return;
    range_ = -nearestDistanceThreshold(binding_ ? binding_->record.threshold : system_ble::kDefaultThreshold);
    Notify({L"RangeValue"});
}
void StatusViewModel::RangeSchedulingFailed() {
    saveError_ = L"Unable to schedule the unlock range change.";
    reportError_(saveError_); Publish();
}
void StatusViewModel::Publish() {
    Notify({L"DeviceName", L"LastUnlock", L"Error", L"ErrorOpen", L"BoundVisibility", L"BindingVisibility",
        L"EmptyVisibility", L"ProgressVisibility", L"BindingEnabled", L"DevicesEnabled", L"ManagementEnabled",
        L"BindingBusy", L"BindingMessage", L"BindLabel", L"BindAutomationName"});
    bind_->Invalidate(); remove_->Invalidate(); save_->Invalidate(); settings_->Invalidate();
}
fire_and_forget StatusViewModel::SaveRange(weak_ref<StatusViewModel> weak) {
    auto model = weak.get();
    if (!model || !model->CanFinishRange() || !model->binding_ ||
        model->binding_->state != system_ble::BindingState::bound || !model->RangeDirty()) co_return;
    model->saving_ = true; model->Publish();
    BindingChange change{*model->binding_, model->binding_->record, {}};
    change.candidate.threshold = -static_cast<int>(model->range_);
    try { model->cancellation_ = enrollment::createCancellation(change.candidate.accountSid, change.cancelEvent); }
    catch (...) {
        model->saving_ = false; model->saveError_ = currentException(); model->reportError_(model->saveError_);
        model->ResetRange(); model->Publish(); co_return;
    }
    apartment_context foreground;
    model = nullptr;
    std::wstring failure;
    std::optional<BindingSummary> saved;
    co_await resume_background();
    try {
        SensitiveBytes bytes;
        if (!encodeBindingChange(change, bytes)) throw std::invalid_argument("Invalid threshold request");
        enrollment::manageBinding(Operation::saveThreshold, bytes);
        saved = enrollment::readBinding();
    } catch (...) {
        failure = currentException();
        try { saved = enrollment::readBinding(); }
        catch (...) { failure += L"\n" + currentException(); }
    }
    co_await foreground;
    if (model = weak.get(); model && !model->stopped_) {
        model->saving_ = false; model->saveError_ = failure;
        if (!failure.empty()) model->reportError_(failure);
        if (saved) model->binding_ = saved;
        model->ResetRange(); model->Publish();
    }
}
fire_and_forget StatusViewModel::OpenSettings(weak_ref<StatusViewModel> weak) {
    if (auto model = weak.get(); model && model->session_) {
        const auto session = model->session_;
        model = nullptr;
        try {
            if (!co_await Windows::System::Launcher::LaunchUriAsync(Windows::Foundation::Uri{L"ms-settings:bluetooth"}))
                throw hresult_error(E_FAIL, L"Windows Bluetooth settings could not be opened");
        } catch (...) { session->message(currentException()); }
    }
}
void StatusViewModel::Stop() {
    stopped_ = true;
    if (session_) session_->stop();
    if (cancellation_ && !SetEvent(cancellation_.get()))
        reportError_(L"Binding management cancellation failed; win32=" + std::to_wstring(GetLastError()));
    Publish();
}
}
