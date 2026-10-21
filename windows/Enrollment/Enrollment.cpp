// Created by Rui MA on 26 Sep 2026

#include "BindingClient.h"
#include "../DesktopApp/Dashboard/Pages/PageControls.h"
#include "BindingView.h"
#include "EnrollmentSession.h"
#include "../Bluetooth/SystemBleSession.h"
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Windows.System.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <map>
#include <chrono>

namespace unlock_windows::desktop_app {
namespace {
using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Controls;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Foundation;
using namespace dashboard_ui;
using namespace saved_credential;

struct BindingPanel final : std::enable_shared_from_this<BindingPanel> {
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher{nullptr};
    StackPanel root{nullptr};
    ListView devices{nullptr};
    TextBlock status{nullptr};
    Button bind{nullptr}, settings{nullptr};
    TextBlock empty{nullptr};
    std::map<std::wstring, DeviceInformation> items;
    struct Choice { std::wstring endpointId, name; };
    std::map<std::wstring, Choice> choices;
    std::wstring selectedKey;
    std::vector<std::function<void()>> revoke;
    ContentDialog dialog{nullptr};
    winrt::handle cancelEvent;
    std::wstring eventName;
    enrollment::Console target;
    BindingSummary original;
    std::function<XamlRoot()> dialogRoot;
    std::function<void(std::wstring)> reportError;
    std::function<void(const BindingSummary&)> changed;
    bool busy = false, scanning = false, scanAgain = false, rendering = false, stopping = false;
    std::uint64_t generation = 0;
    std::uint64_t listRevision = 0;
    bool remove = false;

    void check(std::uint64_t ticket) {
        const auto current = enrollment::queryConsole();
        if (stopping || generation != ticket || current.locked || current.sid != target.sid || current.session != target.session)
            throw hresult_error(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"Binding cancelled or console account changed");
        if (cancelEvent && WaitForSingleObject(cancelEvent.get(), 0) != WAIT_TIMEOUT)
            throw hresult_error(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"Binding cancelled by the desktop host");
    }
    void message(const std::wstring& value) { status.Text(value); OutputDebugStringW((value + L"\n").c_str()); }

    void render() {
        rendering = true;
        devices.Items().Clear();
        choices.clear();
        for (const auto& [id, item] : items) {
            if (!item.Pairing().IsPaired()) continue;
            choices[id] = {id, std::wstring(item.Name())};
        }
        for (const auto& [key, device] : choices) {
            ListViewItem choice;
            choice.Padding({12,12,12,12});
            choice.HorizontalContentAlignment(HorizontalAlignment::Stretch);
            choice.Content(text(device.name.empty() ? L"Name unavailable" : device.name.c_str(), 16));
            choice.Tag(box_value(hstring(key))); devices.Items().Append(choice);
            if (key == selectedKey) devices.SelectedItem(choice);
        }
        if (!devices.SelectedItem()) selectedKey.clear();
        empty.Visibility(devices.Items().Size() ? Visibility::Collapsed : Visibility::Visible);
        bind.IsEnabled(!selectedKey.empty() && !busy && !stopping);
        rendering = false;
    }

    void watch() {
        auto watcher = DeviceInformation::CreateWatcher(system_ble::deviceSelector(),
            single_threaded_vector<hstring>({L"System.Devices.Aep.IsPaired"}), DeviceInformationKind::AssociationEndpoint);
        const auto weak = weak_from_this();
        auto post = [weak](std::function<void(BindingPanel&)> action) {
            if (auto self = weak.lock()) {
                if (!self->dispatcher.TryEnqueue([weak, action = std::move(action)] {
                    if (auto current = weak.lock(); current && !current->stopping) {
                        try { ++current->listRevision; action(*current); current->render(); }
                        catch (...) { current->message(currentException()); }
                    }
                })) OutputDebugStringW(L"Binding device update dispatcher rejected\n");
            }
        };
        auto added = watcher.Added([post](const auto&, DeviceInformation item) {
            post([item](auto& self) { self.items.insert_or_assign(std::wstring(item.Id()), item); });
        });
        auto updated = watcher.Updated([post](const auto&, DeviceInformationUpdate update) {
            post([update](auto& self) {
                const auto found = self.items.find(std::wstring(update.Id()));
                if (found != self.items.end()) found->second.Update(update);
                else self.scan();
            });
        });
        auto removed = watcher.Removed([post](const auto&, DeviceInformationUpdate update) {
            post([update](auto& self) { self.items.erase(std::wstring(update.Id())); });
        });
        auto stopped = watcher.Stopped([post](const auto&, const auto&) {
            post([](auto& self) { self.message(L"Device enumeration stopped. Reopen the app to update the device list."); });
        });
        revoke.push_back([watcher, added, updated, removed, stopped] {
            watcher.Added(added); watcher.Updated(updated); watcher.Removed(removed); watcher.Stopped(stopped);
            if (watcher.Status() == DeviceWatcherStatus::Started || watcher.Status() == DeviceWatcherStatus::EnumerationCompleted) watcher.Stop();
        });
        watcher.Start();
    }

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

    void start(bool clear = false) {
        if (busy || stopping) return;
        remove = clear;
        busy = true; bind.IsEnabled(false); devices.IsEnabled(false);
        reportError(L""); message(L"");
        run();
    }

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
                dialog = ContentDialog{}; dialog.XamlRoot(dialogRoot()); dialog.Title(box_value(L"Remove iPhone?"));
                dialog.Content(box_value(L"Remove this iPhone binding from the app? Windows Bluetooth pairing and the saved password will remain."));
                dialog.PrimaryButtonText(L"Remove"); dialog.CloseButtonText(L"Cancel");
                dialog.DefaultButton(ContentDialogButton::Close);
                if (co_await dialog.ShowAsync() == ContentDialogResult::Primary) {
                    dialog = nullptr; check(ticket);
                    SensitiveBytes bytes;
                    if (!encodeBindingRemoval({original, eventName}, bytes)) throw hresult_error(E_INVALIDARG);
                    co_await resume_background(); enrollment::manageBinding(Operation::removeBinding, bytes); co_await foreground;
                    bindingChanged = true;
                    message(L"Product binding removed. Windows pairing is unchanged.");
                }
            } else {
                if (original.state == system_ble::BindingState::bound)
                    throw hresult_error(E_FAIL, L"Remove the current iPhone binding before binding another device");
                if (!choices.contains(selectedKey)) throw hresult_error(E_FAIL, L"Select a paired device first");
                const auto choice = choices.at(selectedKey);
                auto selected = items.at(choice.endpointId);
                if (!selected.Pairing().IsPaired()) throw hresult_error(E_FAIL, L"Finish pairing in Windows Bluetooth settings, then return and select the device");
                check(ticket);
                const auto paired = co_await system_ble::pairedEndpoints();
                check(ticket);
                const auto bleItem = system_ble::findUniqueEndpoint(paired, hstring(choice.endpointId));
                if (!bleItem || !bleItem.Pairing().IsPaired())
                    throw hresult_error(E_FAIL, L"The selected BLE endpoint is no longer paired. Pair it in Windows Bluetooth settings, then select it again.");
                BindingChange change{original, {target.sid, {}, std::wstring(bleItem.Id()),
                    {}, std::wstring(bleItem.Name()), system_ble::kDefaultThreshold}, eventName};
                dialog = ContentDialog{}; dialog.XamlRoot(dialogRoot());
                dialog.Title(box_value(L"Bind selected iPhone?"));
                dialog.Content(box_value(hstring(change.candidate.displayName + L"\nThe service will verify pairing and protected BLE communication before saving.")));
                dialog.PrimaryButtonText(L"Confirm binding"); dialog.CloseButtonText(L"Cancel");
                dialog.DefaultButton(ContentDialogButton::Close);
                if (co_await dialog.ShowAsync() == ContentDialogResult::Primary) {
                    dialog = nullptr; check(ticket);
                    SensitiveBytes bytes;
                    if (!encodeBindingChange(change, bytes)) throw hresult_error(E_INVALIDARG, L"Invalid system binding");
                    message(L"Waiting for UAC and independent service verification…");
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
            }
            co_await resume_background(); original = enrollment::readBinding(); co_await foreground;
        } catch (...) { failure = currentException(); }
        co_await foreground;
        if (!failure.empty()) { message(failure); reportError(failure); }
        busy = false; dialog = nullptr;
        bind.IsEnabled(!selectedKey.empty()); devices.IsEnabled(true);
        if (stopping && !scanning) finish(); else if (!stopping) scan();
        if (bindingChanged && failure.empty() && !stopping) {
            try { changed(original); }
            catch (...) { failure = currentException(); message(failure); reportError(failure); }
        }
    }

    void stop() {
        if (stopping) return;
        stopping = true; ++generation;
        if (cancelEvent && !SetEvent(cancelEvent.get())) message(L"Binding cancellation event could not be signalled");
        if (dialog) dialog.Hide();
        if (!busy && !scanning) finish();
    }

    void finish() {
        for (auto& action : revoke) action(); revoke.clear();
    }

    void show() {
        dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
        target = enrollment::queryConsole();
        if (target.locked || target.sid != system_ble::EnrollmentStore::currentUserSid() || enrollment::elevatedAdmin())
            throw hresult_error(E_ACCESSDENIED, L"Bind from the ordinary target user's unlocked physical console");
        cancelEvent = enrollment::createCancellation(target.sid, eventName);
        root = StackPanel{}; devices = ListView{};
        status = TextBlock{}; empty = TextBlock{};
        bind = Button{}; settings = Button{};
        root.Spacing(12);
        auto card = Markup::XamlReader::Load(LR"(<Border
            xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
            Background="{ThemeResource CardBackgroundFillColorDefaultBrush}"
            BorderBrush="{ThemeResource CardStrokeColorDefaultBrush}"
            BorderThickness="1" CornerRadius="8" Padding="20,18"/>)").as<Border>();
        StackPanel guidance; guidance.Spacing(12);
        guidance.Children().Append(text(L"Pair your iPhone in Windows Bluetooth settings", 16));
        guidance.Children().Append(text(L"Complete pairing in Windows, then select your iPhone below and bind it to this PC."));
        settings.Content(box_value(L"Open Bluetooth settings"));
        guidance.Children().Append(settings); card.Child(guidance); root.Children().Append(card);
        root.Children().Append(text(L"Paired BLE devices", 16));
        devices.SelectionMode(ListViewSelectionMode::Single);
        ScrollViewer::SetVerticalScrollBarVisibility(devices, ScrollBarVisibility::Disabled);
        ScrollViewer::SetHorizontalScrollBarVisibility(devices, ScrollBarVisibility::Disabled);
        devices.HorizontalContentAlignment(HorizontalAlignment::Stretch);
        Automation::AutomationProperties::SetName(devices, L"BLE devices paired in Windows");
        root.Children().Append(devices);
        empty.Text(L"No paired BLE devices found. Pair your iPhone in Windows Bluetooth settings, then return here.");
        empty.TextWrapping(TextWrapping::Wrap); root.Children().Append(empty);
        bind.Content(box_value(L"Bind selected device")); bind.IsEnabled(false);
        bind.Style(Application::Current().Resources().Lookup(box_value(L"AccentButtonStyle")).as<Style>());
        bind.HorizontalAlignment(HorizontalAlignment::Right);
        root.Children().Append(bind);
        status.TextWrapping(TextWrapping::Wrap); root.Children().Append(status);
        const auto weak = weak_from_this();
        devices.SelectionChanged([weak](const auto&, const auto&) {
            if (auto self = weak.lock(); self && !self->rendering) {
                if (auto choice = self->devices.SelectedItem().try_as<ListViewItem>()) self->selectedKey = std::wstring(unbox_value<hstring>(choice.Tag()));
                else self->selectedKey.clear();
                self->bind.IsEnabled(!self->selectedKey.empty() && !self->busy && !self->stopping);
            }
        });
        bind.Click([weak](const auto&, const auto&) { if (auto self = weak.lock()) self->start(); });
        settings.Click([weak](const auto&, const auto&) { openSettings(weak); });
        watch(); scan();
    }
    static fire_and_forget openSettings(std::weak_ptr<BindingPanel> weak) {
        if (auto self = weak.lock()) {
            try {
                if (!co_await Windows::System::Launcher::LaunchUriAsync(Uri(L"ms-settings:bluetooth")))
                    throw hresult_error(E_FAIL, L"Windows Bluetooth settings could not be opened");
            } catch (...) { self->message(currentException()); }
        }
    }
};
}

BindingView createBindingView(std::function<XamlRoot()> dialogRoot,
    std::function<void(std::wstring)> reportError,
    std::function<void(const BindingSummary&)> changed) {
    auto panel = std::make_shared<BindingPanel>();
    panel->dialogRoot = std::move(dialogRoot);
    panel->reportError = std::move(reportError);
    panel->changed = std::move(changed);
    try { panel->show(); }
    catch (...) { panel->stop(); throw; }
    ContentControl content;
    content.HorizontalContentAlignment(HorizontalAlignment::Stretch);
    content.Content(panel->root);
    return {content, [panel] { panel->scan(); }, [panel] { panel->stop(); },
        [panel] { panel->start(true); }, [panel] { return panel->busy; }};
}
}
