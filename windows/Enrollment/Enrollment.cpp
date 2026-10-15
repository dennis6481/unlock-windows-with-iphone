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
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <map>
#include <chrono>
#include <cwchar>

namespace unlock_windows::desktop_app {
namespace {
using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Controls;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::Advertisement;
using namespace Windows::Foundation;
using namespace dashboard_ui;
using namespace saved_credential;

struct BindingPanel final : std::enable_shared_from_this<BindingPanel> {
    Microsoft::UI::Dispatching::DispatcherQueue dispatcher{nullptr};
    StackPanel root{nullptr};
    ListView devices{nullptr};
    TextBlock status{nullptr};
    Button bind{nullptr}, settings{nullptr}, scanButton{nullptr};
    TextBlock empty{nullptr};
    std::map<std::wstring, DeviceInformation> items;
    struct Choice {
        std::wstring endpointId, name;
        std::uint64_t address = 0;
        BluetoothAddressType addressType = BluetoothAddressType::Unspecified;
        bool paired = false, connectable = false;
        int rssi = 0;
    };
    std::map<std::wstring, Choice> advertisements;
    struct Row { ListViewItem item; TextBlock title, detail; };
    std::map<std::wstring, Row> rows;
    BluetoothLEAdvertisementWatcher advertisementWatcher{nullptr};
    BluetoothLEAdvertisementWatcher::Received_revoker advertisementReceived;
    BluetoothLEAdvertisementWatcher::Stopped_revoker advertisementStopped;
    Microsoft::UI::Dispatching::DispatcherQueueTimer scanTimer{nullptr}, pairingMonitor{nullptr};
    IAsyncOperation<DevicePairingResult> pairingOperation{nullptr};
    bool visible = false;
    std::uint64_t scanGeneration = 0;
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
            throw hresult_error(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"Pairing cancelled or console account changed");
        if (cancelEvent && WaitForSingleObject(cancelEvent.get(), 0) != WAIT_TIMEOUT)
            throw hresult_error(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"Pairing cancelled by the desktop host");
    }
    void message(const std::wstring& value) { status.Text(value); OutputDebugStringW((value + L"\n").c_str()); }

    bool canPair() const {
        const auto found = choices.find(selectedKey);
        return found != choices.end() && (found->second.paired || found->second.connectable);
    }

    static std::wstring addressText(std::uint64_t address) {
        wchar_t value[18]{};
        swprintf_s(value, L"%02X:%02X:%02X:%02X:%02X:%02X",
            static_cast<unsigned>((address >> 40) & 255), static_cast<unsigned>((address >> 32) & 255),
            static_cast<unsigned>((address >> 24) & 255), static_cast<unsigned>((address >> 16) & 255),
            static_cast<unsigned>((address >> 8) & 255), static_cast<unsigned>(address & 255));
        return value;
    }

    void render() {
        rendering = true;
        choices = advertisements;
        for (const auto& [id, item] : items) {
            if (!item.Pairing().IsPaired()) continue;
            choices[id] = {id, std::wstring(item.Name()), 0, BluetoothAddressType::Unspecified, true, true};
        }
        // Merge only after resolving a broadcast to an actual BLE endpoint ID.
        for (auto entry = choices.begin(); entry != choices.end();) {
            if (entry->first != entry->second.endpointId && !entry->second.endpointId.empty() &&
                choices.contains(entry->second.endpointId)) {
                auto& paired = choices.at(entry->second.endpointId);
                paired.address = entry->second.address; paired.addressType = entry->second.addressType;
                paired.rssi = entry->second.rssi;
                if (paired.name.empty()) paired.name = entry->second.name;
                if (selectedKey == entry->first) selectedKey = entry->second.endpointId;
                entry = choices.erase(entry);
            } else ++entry;
        }
        for (auto row = rows.begin(); row != rows.end();) {
            if (!choices.contains(row->first)) {
                std::uint32_t index;
                if (devices.Items().IndexOf(row->second.item, index)) devices.Items().RemoveAt(index);
                row = rows.erase(row);
            } else ++row;
        }
        for (const auto& [key, device] : choices) {
            auto found = rows.find(key);
            if (found == rows.end()) {
                Row row{ListViewItem{}, TextBlock{}, TextBlock{}};
                row.item.Padding({12,12,12,12});
                row.item.HorizontalContentAlignment(HorizontalAlignment::Stretch);
                row.title.FontSize(16); row.detail.TextWrapping(TextWrapping::Wrap);
                StackPanel content; content.Spacing(4);
                content.Children().Append(row.title); content.Children().Append(row.detail);
                row.item.Content(content); row.item.Tag(box_value(hstring(key)));
                devices.Items().Append(row.item);
                found = rows.emplace(key, std::move(row)).first;
            }
            auto& row = found->second;
            row.title.Text(device.name.empty() ? L"Name unavailable" : device.name);
            std::wstring detail = device.paired ? L"Paired in Windows" :
                device.connectable ? L"Windows pairing checked when selected" : L"Not connectable; cannot pair";
            if (device.address) detail += L" | " + addressText(device.address) +
                L" | " + std::to_wstring(device.rssi) + L" dBm";
            else if (const auto item = items.find(key); item != items.end()) {
                const auto properties = item->second.Properties();
                if (properties.HasKey(L"System.Devices.Aep.DeviceAddress")) {
                    const auto address = properties.Lookup(L"System.Devices.Aep.DeviceAddress").try_as<IPropertyValue>();
                    if (address && address.Type() == PropertyType::String) detail += L" | " + std::wstring(address.GetString());
                }
            }
            row.detail.Text(detail);
            if (key == selectedKey) devices.SelectedItem(row.item);
        }
        if (!choices.contains(selectedKey)) selectedKey.clear();
        empty.Visibility(choices.empty() ? Visibility::Visible : Visibility::Collapsed);
        bind.IsEnabled(canPair() && !busy && !stopping);
        rendering = false;
    }

    void stopAdvertisements() {
        ++scanGeneration;
        if (scanTimer) { scanTimer.Stop(); scanTimer = nullptr; }
        advertisementReceived.revoke(); advertisementStopped.revoke();
        if (advertisementWatcher) { advertisementWatcher.Stop(); advertisementWatcher = nullptr; }
        if (scanButton) scanButton.IsEnabled(visible && !busy && !stopping);
    }

    void scanAdvertisements() {
        if (!visible || busy || stopping) return;
        stopAdvertisements();
        advertisements.clear(); render();
        const auto ticket = scanGeneration;
        advertisementWatcher = BluetoothLEAdvertisementWatcher{};
        advertisementWatcher.ScanningMode(BluetoothLEScanningMode::Active);
        const auto weak = weak_from_this();
        const auto queue = dispatcher;
        advertisementReceived = advertisementWatcher.Received(auto_revoke,
            [weak, queue, ticket](const auto&, const BluetoothLEAdvertisementReceivedEventArgs& args) {
                // Keep WinRT property reads on the UI continuation, where errors can be surfaced.
                if (!queue.TryEnqueue([weak, ticket, args] {
                    if (auto self = weak.lock(); self && self->visible && !self->busy &&
                        !self->stopping && ticket == self->scanGeneration) {
                        try {
                            const auto address = args.BluetoothAddress();
                            const auto type = args.BluetoothAddressType();
                            const auto key = L"advertisement:" + std::to_wstring(address) + L":" +
                                std::to_wstring(static_cast<int>(type));
                            auto& entry = self->advertisements[key];
                            entry.address = address; entry.addressType = type;
                            const auto name = args.Advertisement().LocalName();
                            if (!name.empty()) entry.name = std::wstring(name);
                            if (!args.IsScanResponse()) entry.connectable = args.IsConnectable();
                            entry.rssi = args.RawSignalStrengthInDBm();
                            self->render();
                        } catch (...) { self->stopAdvertisements(); self->message(currentException()); }
                    }
                })) OutputDebugStringW(L"BLE discovery dispatcher rejected advertisement\n");
            });
        advertisementStopped = advertisementWatcher.Stopped(auto_revoke,
            [weak, queue, ticket](const auto&, const BluetoothLEAdvertisementWatcherStoppedEventArgs& args) {
                if (!queue.TryEnqueue([weak, ticket, args] {
                    if (auto self = weak.lock(); self && !self->stopping && ticket == self->scanGeneration) {
                        try {
                            const auto error = args.Error();
                            self->stopAdvertisements();
                            self->message(L"BLE scan stopped; Bluetooth error=" + std::to_wstring(static_cast<int>(error)));
                        } catch (...) { self->message(currentException()); }
                    }
                })) OutputDebugStringW(L"BLE discovery dispatcher rejected stopped event\n");
            });
        scanTimer = dispatcher.CreateTimer();
        scanTimer.IsRepeating(false); scanTimer.Interval(std::chrono::seconds(30));
        scanTimer.Tick([weak, ticket](const auto&, const auto&) {
            if (auto self = weak.lock(); self && ticket == self->scanGeneration) {
                try { self->stopAdvertisements(); self->message(L"Scan complete. Select an iPhone or choose Scan again."); }
                catch (...) { self->message(currentException()); }
            }
        });
        try { advertisementWatcher.Start(); scanTimer.Start(); scanButton.IsEnabled(false); message(L"Scanning nearby BLE devices…"); }
        catch (...) { stopAdvertisements(); throw; }
    }

    void setVisible(bool value) {
        if (visible == value || stopping) return;
        visible = value;
        if (value) {
            scan();
            try { scanAdvertisements(); } catch (...) { message(currentException()); }
        } else {
            stopAdvertisements();
            if (busy) {
                ++generation;
                if (!SetEvent(cancelEvent.get())) message(L"Pair cancellation event could not be signalled");
                if (dialog) dialog.Hide();
                if (pairingOperation) {
                    try { pairingOperation.Cancel(); } catch (...) { message(currentException()); }
                }
            }
        }
    }

    void watch() {
        auto watcher = DeviceInformation::CreateWatcher(system_ble::deviceSelector(),
            single_threaded_vector<hstring>({L"System.Devices.Aep.IsPaired", L"System.Devices.Aep.DeviceAddress"}), DeviceInformationKind::AssociationEndpoint);
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
        busy = true; stopAdvertisements(); bind.IsEnabled(false); devices.IsEnabled(false);
        reportError(L""); message(L"");
        run();
    }

    fire_and_forget confirmPairing(DevicePairingRequestedEventArgs args, std::uint64_t ticket, apartment_context foreground) {
        auto lifetime = shared_from_this();
        const auto deferral = args.GetDeferral();
        try {
            co_await foreground;
            check(ticket);
            if (args.PairingKind() != DevicePairingKinds::ConfirmPinMatch)
                throw hresult_error(E_FAIL, L"Unsupported Bluetooth pairing confirmation");
            dialog = ContentDialog{}; dialog.XamlRoot(dialogRoot());
            dialog.Title(box_value(L"Do the pairing numbers match?"));
            dialog.Content(box_value(L"Compare this number with your iPhone: " + args.Pin() +
                L"\nAccept only if both devices show the same number."));
            dialog.PrimaryButtonText(L"Numbers match"); dialog.CloseButtonText(L"Cancel");
            dialog.DefaultButton(ContentDialogButton::Close);
            const auto answer = co_await dialog.ShowAsync();
            dialog = nullptr;
            check(ticket);
            if (answer == ContentDialogResult::Primary) args.Accept();
        } catch (...) {
            const auto failure = currentException();
            if (!SetEvent(cancelEvent.get())) message(L"Pair cancellation event could not be signalled");
            message(failure); reportError(failure);
        }
        try { deferral.Complete(); }
        catch (...) { message(currentException()); reportError(currentException()); }
    }

    fire_and_forget run() {
        auto lifetime = shared_from_this();
        const auto ticket = generation;
        apartment_context foreground;
        std::wstring failure;
        bool bindingChanged = false, windowsPaired = false;
        try {
            check_bool(ResetEvent(cancelEvent.get()));
            check(ticket);
            co_await resume_background(); original = enrollment::readBinding(); co_await foreground;
            check(ticket);
            if (remove) {
                dialog = ContentDialog{}; dialog.XamlRoot(dialogRoot()); dialog.Title(box_value(L"Remove iPhone?"));
                dialog.Content(box_value(L"Remove this iPhone pairing from the app? Windows Bluetooth pairing and the saved password will remain."));
                dialog.PrimaryButtonText(L"Remove"); dialog.CloseButtonText(L"Cancel");
                dialog.DefaultButton(ContentDialogButton::Close);
                if (co_await dialog.ShowAsync() == ContentDialogResult::Primary) {
                    dialog = nullptr; check(ticket);
                    SensitiveBytes bytes;
                    if (!encodeBindingRemoval({original, eventName}, bytes)) throw hresult_error(E_INVALIDARG);
                    co_await resume_background(); enrollment::manageBinding(Operation::removeBinding, bytes); co_await foreground;
                    bindingChanged = true;
                    message(L"iPhone removed from this app. Windows pairing is unchanged.");
                }
            } else {
                if (original.state == system_ble::BindingState::bound)
                    throw hresult_error(E_FAIL, L"Remove the current iPhone from the app before pairing another device");
                if (!canPair()) throw hresult_error(E_FAIL, L"Select a paired or connectable BLE device first");
                const auto key = selectedKey;
                const auto choice = choices.at(key);
                dialog = ContentDialog{}; dialog.XamlRoot(dialogRoot());
                dialog.Title(box_value(L"Pair selected iPhone?"));
                dialog.Content(box_value(hstring((choice.name.empty() ? L"Name unavailable" : choice.name) +
                    std::wstring(L"\nWindows will pair this BLE device if needed. After UAC, the app will verify and save it."))));
                dialog.PrimaryButtonText(L"Pair"); dialog.CloseButtonText(L"Cancel");
                dialog.DefaultButton(ContentDialogButton::Close);
                if (co_await dialog.ShowAsync() == ContentDialogResult::Primary) {
                    dialog = nullptr; check(ticket);
                    BluetoothLEDevice device{nullptr};
                    DeviceInformation selected{nullptr};
                    message(L"Opening selected BLE device…");
                    if (!choice.endpointId.empty()) device = co_await BluetoothLEDevice::FromIdAsync(choice.endpointId);
                    else device = co_await BluetoothLEDevice::FromBluetoothAddressAsync(choice.address, choice.addressType);
                    check(ticket);
                    if (!device) throw hresult_error(E_FAIL, L"The selected BLE device could not be opened. Scan again.");
                    selected = device.DeviceInformation();
                    if (auto entry = advertisements.find(key); entry != advertisements.end())
                        entry->second.endpointId = std::wstring(selected.Id());
                    if (!selected.Pairing().IsPaired()) {
                        if (!selected.Pairing().CanPair()) throw hresult_error(E_FAIL, L"Windows reports that this BLE device cannot pair.");
                        message(L"Pairing in Windows. Complete any confirmation on both devices…");
                        // Basic PairAsync depends on UWP UI and is unsupported in desktop apps.
                        const auto custom = selected.Pairing().Custom();
                        const auto weak = weak_from_this();
                        const auto requested = custom.PairingRequested(auto_revoke,
                            [weak, ticket, foreground](const auto&, const DevicePairingRequestedEventArgs& args) {
                                if (auto self = weak.lock()) self->confirmPairing(args, ticket, foreground);
                            });
                        pairingOperation = custom.PairAsync(DevicePairingKinds::ConfirmPinMatch,
                            DevicePairingProtectionLevel::EncryptionAndAuthentication);
                        pairingMonitor = dispatcher.CreateTimer();
                        pairingMonitor.Interval(std::chrono::milliseconds(250));
                        pairingMonitor.Tick([weak, ticket](const auto&, const auto&) {
                            if (auto self = weak.lock()) {
                                try { self->check(ticket); }
                                catch (...) {
                                    self->pairingMonitor.Stop();
                                    const auto failure = currentException();
                                    if (!SetEvent(self->cancelEvent.get())) self->message(L"Pair cancellation event could not be signalled");
                                    if (self->dialog) self->dialog.Hide();
                                    try { if (self->pairingOperation) self->pairingOperation.Cancel(); }
                                    catch (...) { self->message(currentException()); }
                                    self->message(failure);
                                }
                            }
                        });
                        pairingMonitor.Start();
                        const auto result = co_await pairingOperation;
                        pairingMonitor.Stop(); pairingMonitor = nullptr; pairingOperation = nullptr;
                        windowsPaired = result.Status() == DevicePairingResultStatus::Paired ||
                            result.Status() == DevicePairingResultStatus::AlreadyPaired;
                        check(ticket);
                        if (!windowsPaired)
                            throw hresult_error(E_FAIL, L"Windows BLE pairing failed; status=" +
                                std::to_wstring(static_cast<int>(result.Status())));
                    }
                    check(ticket);
                    const auto paired = co_await system_ble::pairedEndpoints();
                    check(ticket);
                    const auto bleItem = system_ble::findUniqueEndpoint(paired, selected.Id());
                    if (!bleItem || !bleItem.Pairing().IsPaired())
                        throw hresult_error(E_FAIL, L"Windows did not return the selected device as a paired BLE endpoint. Scan again.");
                    BindingChange change{original, {target.sid, {}, std::wstring(bleItem.Id()),
                        {}, std::wstring(bleItem.Name()), system_ble::kDefaultThreshold}, eventName};
                    SensitiveBytes bytes;
                    if (!encodeBindingChange(change, bytes)) throw hresult_error(E_INVALIDARG, L"Invalid app pairing request");
                    message(L"Waiting for UAC and independent service verification…");
                    co_await resume_background(); enrollment::manageBinding(Operation::beginBinding, bytes); co_await foreground;
                    for (;;) {
                        check(ticket); co_await resume_background();
                        Packet response;
                        if (!call(Operation::bindingTaskStatus, SensitiveBytes{}, response)) throw std::runtime_error("App pairing task status unavailable");
                        AuthenticationStatus progress;
                        if (response.result != Result::success || !decodeAuthenticationStatus(response.payload.value.data(), response.payload.value.size(), progress))
                            throw std::runtime_error("App pairing status rejected or malformed");
                        co_await foreground;
                        if (progress.stage == AuthenticationStage::failed) throw hresult_error(E_FAIL, authenticationStatusText(progress));
                        if (progress.stage == AuthenticationStage::completed) { message(L"iPhone paired with this app. Lock this PC and click Unlock to try it."); break; }
                        if (progress.stage != AuthenticationStage::verifying) throw hresult_error(E_FAIL, L"No active app pairing task");
                        co_await resume_after(std::chrono::milliseconds(100)); co_await foreground;
                    }
                    bindingChanged = true;
                }
            }
            co_await resume_background(); original = enrollment::readBinding(); co_await foreground;
        } catch (...) { failure = currentException(); }
        co_await foreground;
        if (pairingMonitor) { pairingMonitor.Stop(); pairingMonitor = nullptr; }
        pairingOperation = nullptr;
        if (!failure.empty() && windowsPaired)
            failure += L"\nWindows BLE pairing is retained.";
        if (!failure.empty()) { message(failure); reportError(failure); }
        busy = false; dialog = nullptr;
        bind.IsEnabled(canPair() && !stopping); devices.IsEnabled(true); scanButton.IsEnabled(visible && !stopping);
        if (stopping && !scanning) finish(); else if (!stopping) scan();
        if (bindingChanged && failure.empty() && !stopping) {
            try { changed(original); }
            catch (...) { failure = currentException(); message(failure); reportError(failure); }
        }
    }

    void stop() {
        if (stopping) return;
        stopping = true; ++generation;
        stopAdvertisements();
        if (pairingOperation) {
            try { pairingOperation.Cancel(); } catch (...) { message(currentException()); }
        }
        if (cancelEvent && !SetEvent(cancelEvent.get())) message(L"Pair cancellation event could not be signalled");
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
            throw hresult_error(E_ACCESSDENIED, L"Pair from the ordinary target user's unlocked physical console");
        cancelEvent = enrollment::createCancellation(target.sid, eventName);
        root = StackPanel{}; devices = ListView{};
        status = TextBlock{}; empty = TextBlock{};
        bind = Button{}; settings = Button{}; scanButton = Button{};
        root.Spacing(12);
        auto card = Markup::XamlReader::Load(LR"(<Border
            xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
            Background="{ThemeResource CardBackgroundFillColorDefaultBrush}"
            BorderBrush="{ThemeResource CardStrokeColorDefaultBrush}"
            BorderThickness="1" CornerRadius="8" Padding="20,18"/>)").as<Border>();
        StackPanel guidance; guidance.Spacing(12);
        guidance.Children().Append(text(L"Select your iPhone and choose Pair", 16));
        guidance.Children().Append(text(L"Discover nearby BLE devices or select an existing Windows BLE pairing. Confirm any pairing numbers on both devices."));
        settings.Content(box_value(L"Open Bluetooth settings"));
        guidance.Children().Append(settings); card.Child(guidance); root.Children().Append(card);
        root.Children().Append(text(L"Nearby and paired BLE devices", 16));
        devices.SelectionMode(ListViewSelectionMode::Single);
        ScrollViewer::SetVerticalScrollBarVisibility(devices, ScrollBarVisibility::Disabled);
        ScrollViewer::SetHorizontalScrollBarVisibility(devices, ScrollBarVisibility::Disabled);
        devices.HorizontalContentAlignment(HorizontalAlignment::Stretch);
        Automation::AutomationProperties::SetName(devices, L"Nearby and paired BLE devices");
        root.Children().Append(devices);
        empty.Text(L"No BLE devices found. Keep your iPhone nearby and discoverable, then choose Scan again.");
        empty.TextWrapping(TextWrapping::Wrap); root.Children().Append(empty);
        bind.Content(box_value(L"Pair")); bind.IsEnabled(false);
        bind.Style(Application::Current().Resources().Lookup(box_value(L"AccentButtonStyle")).as<Style>());
        bind.HorizontalAlignment(HorizontalAlignment::Right);
        StackPanel actions; actions.Orientation(Orientation::Horizontal); actions.Spacing(12);
        scanButton.Content(box_value(L"Scan again"));
        actions.Children().Append(scanButton); actions.Children().Append(bind);
        root.Children().Append(actions);
        status.TextWrapping(TextWrapping::Wrap); root.Children().Append(status);
        const auto weak = weak_from_this();
        devices.SelectionChanged([weak](const auto&, const auto&) {
            if (auto self = weak.lock(); self && !self->rendering) {
                if (auto choice = self->devices.SelectedItem().try_as<ListViewItem>()) self->selectedKey = std::wstring(unbox_value<hstring>(choice.Tag()));
                else self->selectedKey.clear();
                self->bind.IsEnabled(self->canPair() && !self->busy && !self->stopping);
            }
        });
        bind.Click([weak](const auto&, const auto&) { if (auto self = weak.lock()) self->start(); });
        settings.Click([weak](const auto&, const auto&) { openSettings(weak); });
        scanButton.Click([weak](const auto&, const auto&) {
            if (auto self = weak.lock()) {
                try { self->scan(); self->scanAdvertisements(); } catch (...) { self->message(currentException()); }
            }
        });
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
        [panel] { panel->start(true); }, [panel] { return panel->busy; }, [panel](bool visible) { panel->setVisible(visible); }};
}
}
