// Created by Rui MA on 09 Oct 2026

#include "StatusPage.xaml.h"
#include "StatusPage.g.cpp"
#include "PageControls.h"
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <winrt/Microsoft.UI.Xaml.Data.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <winrt/Windows.UI.Xaml.Interop.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Input.h>
#include <winrt/Windows.System.h>
#include "../../../Enrollment/BindingClient.h"

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;

namespace {
struct DistanceToolTip : implements<DistanceToolTip, Microsoft::UI::Xaml::Data::IValueConverter> {
    Windows::Foundation::IInspectable Convert(const Windows::Foundation::IInspectable& value,
        const Windows::UI::Xaml::Interop::TypeName&, const Windows::Foundation::IInspectable&, const hstring&) {
        const auto threshold = nearestDistanceThreshold(-unbox_value<double>(value));
        return box_value(hstring(distanceLabel(threshold)));
    }
    Windows::Foundation::IInspectable ConvertBack(const Windows::Foundation::IInspectable&,
        const Windows::UI::Xaml::Interop::TypeName&, const Windows::Foundation::IInspectable&, const hstring&) {
        throw hresult_not_implemented();
    }
};

bool distanceKey(Windows::System::VirtualKey key) {
    using Windows::System::VirtualKey;
    return key == VirtualKey::Left || key == VirtualKey::Right || key == VirtualKey::Up ||
        key == VirtualKey::Down || key == VirtualKey::Home || key == VirtualKey::End ||
        key == VirtualKey::PageUp || key == VirtualKey::PageDown;
}
}

void StatusPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    visible_ = true;
    if (statusPanel_) return;
    statusPanel_ = StackPanel{};
    statusPanel_.Spacing(kCardSpacing);
    success_ = InfoBar{};
    success_.Severity(InfoBarSeverity::Success);
    success_.IsClosable(true);
    success_.IsOpen(false);
    success_.Visibility(Visibility::Collapsed);
    success_.Margin({0, 0, 0, 20});
    success_.Closed([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) page->success_.Visibility(Visibility::Collapsed);
    });
    success_.Title(L"iPhone bound successfully");
    success_.Message(L"Lock this PC and click Unlock on the Windows sign-in screen to try it.");
    statusPanel_.Children().Append(success_);
    auto phone = icon(L"\xE8EA", 100, true);
    phone.HorizontalAlignment(HorizontalAlignment::Center);
    Automation::AutomationProperties::SetName(phone, L"iPhone");
    statusPanel_.Children().Append(phone);
    name_ = text(L"iPhone", 24);
    name_.TextAlignment(TextAlignment::Center);
    statusPanel_.Children().Append(name_);
    lastUnlockText_ = text(L"\u2014");
    lastUnlockText_.TextWrapping(TextWrapping::NoWrap);
    lastUnlockText_.TextAlignment(TextAlignment::Right);
    lastUnlockCard_ = settingsCard(L"Last Unlock", lastUnlockText_, L"\xE823", false);
    statusPanel_.Children().Append(lastUnlockCard_);
    threshold_ = Slider{};
    threshold_.Minimum(-kNearThreshold);
    threshold_.Maximum(-kFarThreshold);
    threshold_.StepFrequency(kDistanceStep);
    threshold_.TickFrequency(kDistanceStep);
    threshold_.SnapsTo(Microsoft::UI::Xaml::Controls::Primitives::SliderSnapsTo::Ticks);
    threshold_.TickPlacement(Microsoft::UI::Xaml::Controls::Primitives::TickPlacement::Outside);
    threshold_.ThumbToolTipValueConverter(make<DistanceToolTip>());
    threshold_.Value(-unlock_windows::system_ble::kDefaultThreshold);
    Automation::AutomationProperties::SetName(threshold_, L"Unlock range: Near, Medium, Far");
    threshold_.ValueChanged([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && !page->updating_) {
            page->dirty_ = page->binding_ && nearestDistanceThreshold(-page->threshold_.Value()) !=
                nearestDistanceThreshold(page->binding_->record.threshold);
            // Input handlers run after Slider's class handling. Defer automation saves until they have run.
            page->QueueThresholdAction();
        }
    });
    using namespace Microsoft::UI::Xaml::Input;
    threshold_.AddHandler(UIElement::PointerPressedEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const PointerRoutedEventArgs& args) {
            if (auto page = weak.get(); page && args.GetCurrentPoint(page->threshold_).Properties().IsLeftButtonPressed()) {
                if (!page->thresholdPointerActive_) ++page->thresholdInteraction_;
                page->thresholdPointerActive_ = true;
            }
        }}), true);
    threshold_.AddHandler(UIElement::PointerReleasedEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const auto&) {
            if (auto page = weak.get(); page && page->thresholdPointerActive_) {
                page->thresholdPointerActive_ = false;
                page->QueueThresholdAction();
            }
        }}), true);
    threshold_.AddHandler(UIElement::PointerCaptureLostEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const auto&) {
            if (auto page = weak.get()) page->QueueThresholdAction(true);
        }}), true);
    threshold_.AddHandler(UIElement::PointerCanceledEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const auto&) {
            if (auto page = weak.get()) page->ResetThresholdPreview();
        }}), true);
    threshold_.AddHandler(UIElement::KeyDownEvent(), box_value(KeyEventHandler{
        [weak = get_weak()](const auto&, const KeyRoutedEventArgs& args) {
            if (auto page = weak.get()) {
                if (distanceKey(args.Key())) {
                    if (!page->thresholdKeyActive_) ++page->thresholdInteraction_;
                    page->thresholdKeyActive_ = true;
                }
                else if (args.Key() == Windows::System::VirtualKey::Escape) page->ResetThresholdPreview();
            }
        }}), true);
    threshold_.AddHandler(UIElement::KeyUpEvent(), box_value(KeyEventHandler{
        [weak = get_weak()](const auto&, const KeyRoutedEventArgs& args) {
            if (auto page = weak.get(); page && distanceKey(args.Key()) && page->thresholdKeyActive_) {
                page->thresholdKeyActive_ = false;
                page->QueueThresholdAction();
            }
        }}), true);
    threshold_.LostFocus([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && !page->saving_ &&
            (page->dirty_ || page->thresholdPointerActive_ || page->thresholdKeyActive_))
            page->ResetThresholdPreview();
    });
    thresholdCard_ = signalThresholdCard(L"Unlock range", threshold_);
    statusPanel_.Children().Append(thresholdCard_);

    remove_ = Button{};
    remove_.Content(box_value(L"Remove"));
    remove_.HorizontalAlignment(HorizontalAlignment::Right);
    removalFlyout_ = Flyout{};
    removalFlyout_.Placement(Microsoft::UI::Xaml::Controls::Primitives::FlyoutPlacementMode::TopEdgeAlignedRight);
    StackPanel confirmation; confirmation.Spacing(12); confirmation.MaxWidth(320);
    confirmation.Children().Append(text(L"Remove this iPhone binding?", 16));
    confirmation.Children().Append(text(L"Your iPhone will remain paired in Windows Bluetooth settings."));
    Button confirmRemoval;
    confirmRemoval.Content(box_value(L"Remove binding"));
    confirmRemoval.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) {
            page->removalFlyout_.Hide();
            page->Remove();
        }
    });
    confirmation.Children().Append(confirmRemoval);
    removalFlyout_.Content(confirmation);
    remove_.Flyout(removalFlyout_);
    const auto removeGlyph = std::wstring(1, static_cast<wchar_t>(Symbol::Delete));
    removalCard_ = settingsCard(L"Remove bound iPhone", remove_, removeGlyph.c_str());
    statusPanel_.Children().Append(removalCard_);

    error_ = InfoBar{};
    error_.Severity(InfoBarSeverity::Error);
    error_.IsClosable(false);
    statusPanel_.Children().Append(error_);

    BodyHost().Content(statusPanel_);
}

void StatusPage::OnNavigatedFrom(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    visible_ = false;
    ResetThresholdPreview();
    DismissBindingSuccess();
}

void StatusPage::ResetThresholdPreview() {
    ++thresholdInteraction_;
    thresholdPointerActive_ = thresholdKeyActive_ = dirty_ = false;
    if (!threshold_ || saving_) return;
    updating_ = true;
    threshold_.Value(-nearestDistanceThreshold(binding_ ? binding_->record.threshold :
        unlock_windows::system_ble::kDefaultThreshold));
    updating_ = false;
}

void StatusPage::FinishThresholdInteraction() {
    if (!visible_ || stopped_ || hostBusy_ || Busy()) { ResetThresholdPreview(); return; }
    updating_ = true;
    threshold_.Value(-nearestDistanceThreshold(-threshold_.Value()));
    updating_ = false;
    if (dirty_) save(get_weak());
}

void StatusPage::QueueThresholdAction(bool cancel) {
    const auto interaction = thresholdInteraction_;
    if (!DispatcherQueue().TryEnqueue([weak = get_weak(), interaction, cancel] {
        if (auto page = weak.get(); page && interaction == page->thresholdInteraction_) {
            if (cancel) {
                if (page->thresholdPointerActive_) page->ResetThresholdPreview();
            } else if (!page->thresholdPointerActive_ && !page->thresholdKeyActive_) {
                page->FinishThresholdInteraction();
            }
        }
    })) {
        ResetThresholdPreview();
        saveError_ = L"Unable to schedule the unlock range change.";
        error_.Message(saveError_); error_.IsOpen(true);
    }
}

void StatusPage::DismissBindingSuccess() {
    if (success_) success_.IsOpen(false);
}

void StatusPage::Update(unlock_windows::desktop_app::DashboardSnapshot const& snapshot) {
    hostBusy_ = snapshot.busy;
    const bool known = snapshot.binding.has_value();
    const bool bound = snapshot.binding && snapshot.binding->state == unlock_windows::system_ble::BindingState::bound;
    if (known && !bound && binding_ && binding_->state == unlock_windows::system_ble::BindingState::bound)
        DismissBindingSuccess();
    if (!bound || snapshot.busy || Busy() || stopped_) removalFlyout_.Hide();
    lastUnlockCard_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    lastUnlockText_.Text(unlock_windows::desktop_app::lastUnlockText(snapshot.lastUnlock, GetTickCount64()));
    name_.Text(!known ? L"Binding status unavailable" : bound ?
        (snapshot.binding->record.displayName.empty() ? L"Name unavailable" : snapshot.binding->record.displayName) : L"No iPhone bound");
    error_.Title(L"Status needs attention");
    const bool resetView = resetBindingView_ && known && !bound && !Busy();
    if ((bound || resetView) && bindingView_ && !bindingView_->busy()) {
        bindingView_->stop();
        std::uint32_t index = 0;
        if (statusPanel_.Children().IndexOf(bindingView_->content, index)) statusPanel_.Children().RemoveAt(index);
        bindingView_.reset();
    }
    if (resetView) {
        saveError_.clear();
        resetBindingView_ = false;
    }
    if (known && !bound && !snapshot.busy && !bindingView_ && !stopped_) {
        try {
            EnsureBindingView();
        } catch (...) { saveError_ = currentException(); }
    }
    if (bindingView_) {
        bindingView_->content.Visibility(known && !bound ? Visibility::Visible : Visibility::Collapsed);
        bindingView_->content.IsEnabled(known && !snapshot.busy && !saving_ && !stopped_);
    }
    if (!saving_) {
        const bool changed = binding_ != snapshot.binding;
        binding_ = snapshot.binding;
        if (changed || snapshot.busy || stopped_) ResetThresholdPreview();
        else if (!dirty_ && !thresholdPointerActive_ && !thresholdKeyActive_) ResetThresholdPreview();
    }
    thresholdCard_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    threshold_.IsEnabled(bound && !hostBusy_ && !Busy() && !stopped_);
    removalCard_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    remove_.IsEnabled(bound && !snapshot.busy && !Busy() && !stopped_);
    error_.Message(saveError_.empty() ? snapshot.error : saveError_);
    error_.IsOpen(!saveError_.empty() || !snapshot.error.empty());
}

fire_and_forget StatusPage::save(weak_ref<StatusPage> weak) {
    using namespace unlock_windows::saved_credential;
    auto page = weak.get();
    if (!page || !page->visible_ || page->stopped_ || page->hostBusy_ || page->Busy() || !page->binding_ ||
        page->binding_->state != unlock_windows::system_ble::BindingState::bound || !page->dirty_) co_return;
    ++page->thresholdInteraction_;
    page->saving_ = true; page->threshold_.IsEnabled(false);
    page->remove_.IsEnabled(false);
    BindingChange change{*page->binding_, page->binding_->record, {}};
    change.candidate.threshold = -static_cast<int>(page->threshold_.Value());
    try { page->cancellation_ = unlock_windows::enrollment::createCancellation(change.candidate.accountSid, change.cancelEvent); }
    catch (...) {
        page->saving_ = false; page->saveError_ = currentException();
        page->updating_ = true;
        page->threshold_.Value(-nearestDistanceThreshold(page->binding_->record.threshold)); page->dirty_ = false;
        page->updating_ = false;
        page->threshold_.IsEnabled(!page->hostBusy_);
        page->remove_.IsEnabled(!page->hostBusy_);
        page->error_.Message(page->saveError_); page->error_.IsOpen(true); co_return;
    }
    apartment_context foreground;
    page = nullptr;
    std::wstring failure;
    std::optional<BindingSummary> saved;
    co_await resume_background();
    try {
        SensitiveBytes bytes;
        if (!encodeBindingChange(change, bytes)) throw std::invalid_argument("Invalid threshold request");
        unlock_windows::enrollment::manageBinding(Operation::saveThreshold, bytes);
        saved = unlock_windows::enrollment::readBinding();
    } catch (...) {
        failure = currentException();
        try { saved = unlock_windows::enrollment::readBinding(); }
        catch (...) { failure += L"\n" + currentException(); }
    }
    co_await foreground;
    if (page = weak.get(); page && !page->stopped_) {
        page->saving_ = false; page->dirty_ = false; page->saveError_ = failure;
        if (saved) page->binding_ = saved;
        page->updating_ = true;
        const bool bound = page->binding_ && page->binding_->state == unlock_windows::system_ble::BindingState::bound;
        page->threshold_.Value(-nearestDistanceThreshold(bound ? page->binding_->record.threshold : unlock_windows::system_ble::kDefaultThreshold));
        page->updating_ = false;
        page->threshold_.IsEnabled(bound && !page->hostBusy_ && !page->Busy());
        page->remove_.IsEnabled(bound && !page->hostBusy_ && !page->Busy());
        page->error_.Message(failure); page->error_.IsOpen(!failure.empty());
    }
}

void StatusPage::EnsureBindingView() {
    if (bindingView_) return;
    bindingView_ = unlock_windows::desktop_app::createBindingView([weak = get_weak()](std::wstring failure) {
        if (auto page = weak.get(); page && !page->stopped_) {
            page->saveError_ = std::move(failure);
            page->error_.Message(page->saveError_); page->error_.IsOpen(!page->saveError_.empty());
        }
    }, [weak = get_weak()](const unlock_windows::saved_credential::BindingSummary& binding) {
        if (auto page = weak.get(); page && !page->stopped_) {
            page->resetBindingView_ = binding.state != unlock_windows::system_ble::BindingState::bound;
            page->saveError_.clear();
            if (page->resetBindingView_) page->DismissBindingSuccess();
            else {
                page->success_.Visibility(Visibility::Visible);
                page->success_.IsOpen(true);
            }
            page->refreshSnapshot_(true);
        }
    });
    statusPanel_.Children().InsertAt(statusPanel_.Children().Size() - 1, bindingView_->content);
}

void StatusPage::SetHost(std::function<void(bool)> refresh) {
    refreshSnapshot_ = std::move(refresh);
}

void StatusPage::Refresh() {
    if (bindingView_ && !stopped_) bindingView_->refresh();
}

bool StatusPage::Busy() const {
    return saving_ || (bindingView_ && bindingView_->busy());
}

void StatusPage::Remove() {
    if (stopped_ || hostBusy_ || Busy() || !binding_ || binding_->state != unlock_windows::system_ble::BindingState::bound) return;
    try {
        EnsureBindingView();
        bindingView_->content.Visibility(Visibility::Collapsed);
        bindingView_->remove();
        remove_.IsEnabled(false);
        threshold_.IsEnabled(false);
    } catch (...) {
        saveError_ = currentException(); error_.Message(saveError_); error_.IsOpen(true);
    }
}
void StatusPage::Stop() {
    stopped_ = true;
    ResetThresholdPreview();
    if (removalFlyout_) removalFlyout_.Hide();
    if (bindingView_) bindingView_->stop();
    if (cancellation_ && !SetEvent(cancellation_.get())) OutputDebugStringW(L"Binding management cancellation failed\n");
}
}
