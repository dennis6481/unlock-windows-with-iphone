// Created by Rui MA on 09 Oct 2026

#include "StatusPage.xaml.h"
#include "StatusPage.g.cpp"
#include "PageControls.h"
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include "../../../Enrollment/BindingClient.h"

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;

void StatusPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (statusPanel_) return;
    statusPanel_ = StackPanel{};
    statusPanel_.Spacing(12);
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
    thresholdText_ = text(L"");
    threshold_ = Slider{};
    threshold_.Minimum(unlock_windows::system_ble::kMinimumThreshold);
    threshold_.Maximum(unlock_windows::system_ble::kMaximumThreshold);
    threshold_.StepFrequency(unlock_windows::system_ble::kThresholdStep);
    threshold_.Value(unlock_windows::system_ble::kDefaultThreshold);
    Automation::AutomationProperties::SetName(threshold_, L"Signal threshold in dBm");
    threshold_.ValueChanged([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && !page->updating_) {
            page->dirty_ = page->binding_ && static_cast<int>(page->threshold_.Value()) != page->binding_->record.threshold;
            page->thresholdText_.Text(to_hstring(static_cast<int>(page->threshold_.Value())) + L" dBm");
            page->save_.IsEnabled(page->dirty_ && !page->hostBusy_ && !page->Busy() && !page->stopped_);
        }
    });
    save_ = Button{};
    save_.Content(box_value(L"Save"));
    save_.Click([weak = get_weak()](const auto&, const auto&) { save(weak); });
    thresholdCard_ = signalThresholdCard(L"Signal threshold", thresholdText_, threshold_, save_);
    statusPanel_.Children().Append(thresholdCard_);

    remove_ = Button{};
    remove_.Content(box_value(L"Remove"));
    remove_.HorizontalAlignment(HorizontalAlignment::Right);
    remove_.Click([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) page->Remove();
    });
    const auto removeGlyph = std::wstring(1, static_cast<wchar_t>(Symbol::Delete));
    removalCard_ = settingsCard(L"Remove paired iPhone", remove_, removeGlyph.c_str());
    statusPanel_.Children().Append(removalCard_);

    error_ = InfoBar{};
    error_.Severity(InfoBarSeverity::Error);
    error_.IsClosable(false);
    statusPanel_.Children().Append(error_);

    BodyHost().Content(statusPanel_);
}

void StatusPage::Update(unlock_windows::desktop_app::DashboardSnapshot const& snapshot) {
    hostBusy_ = snapshot.busy;
    const bool known = snapshot.binding.has_value();
    const bool bound = snapshot.binding && snapshot.binding->state == unlock_windows::system_ble::BindingState::bound;
    lastUnlockCard_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    lastUnlockText_.Text(unlock_windows::desktop_app::lastUnlockText(snapshot.lastUnlock, GetTickCount64()));
    name_.Text(!known ? L"App pairing status unavailable" : bound ?
        (snapshot.binding->record.displayName.empty() ? L"Name unavailable" : snapshot.binding->record.displayName) : L"No iPhone paired with this app");
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
        if (binding_ != snapshot.binding) dirty_ = false;
        binding_ = snapshot.binding;
        if (!dirty_) {
            updating_ = true;
            threshold_.Value(bound ? binding_->record.threshold : unlock_windows::system_ble::kDefaultThreshold);
            updating_ = false;
        }
    }
    if (bindingView_) bindingView_->setVisible(visible_ && known && !bound && !stopped_);
    thresholdText_.Text(to_hstring(static_cast<int>(threshold_.Value())) + L" dBm");
    thresholdCard_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    threshold_.IsEnabled(bound && !hostBusy_ && !Busy() && !stopped_);
    save_.IsEnabled(bound && dirty_ && !hostBusy_ && !Busy() && !stopped_);
    removalCard_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    remove_.IsEnabled(bound && !snapshot.busy && !Busy() && !stopped_);
    error_.Message(saveError_.empty() ? snapshot.error : saveError_);
    error_.IsOpen(!saveError_.empty() || !snapshot.error.empty());
}

fire_and_forget StatusPage::save(weak_ref<StatusPage> weak) {
    using namespace unlock_windows::saved_credential;
    auto page = weak.get();
    if (!page || page->stopped_ || page->hostBusy_ || page->Busy() || !page->binding_ ||
        page->binding_->state != unlock_windows::system_ble::BindingState::bound || !page->dirty_) co_return;
    page->saving_ = true; page->threshold_.IsEnabled(false); page->save_.IsEnabled(false);
    page->remove_.IsEnabled(false);
    BindingChange change{*page->binding_, page->binding_->record, {}};
    change.candidate.threshold = static_cast<int>(page->threshold_.Value());
    try { page->cancellation_ = unlock_windows::enrollment::createCancellation(change.candidate.accountSid, change.cancelEvent); }
    catch (...) {
        page->saving_ = false; page->saveError_ = currentException();
        page->updating_ = true;
        page->threshold_.Value(page->binding_->record.threshold); page->dirty_ = false;
        page->updating_ = false;
        page->thresholdText_.Text(to_hstring(page->binding_->record.threshold) + L" dBm");
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
        page->threshold_.Value(bound ? page->binding_->record.threshold : unlock_windows::system_ble::kDefaultThreshold);
        page->updating_ = false;
        page->thresholdText_.Text(to_hstring(static_cast<int>(page->threshold_.Value())) + L" dBm");
        page->threshold_.IsEnabled(bound && !page->hostBusy_ && !page->Busy());
        page->remove_.IsEnabled(bound && !page->hostBusy_ && !page->Busy());
        page->save_.IsEnabled(false);
        page->error_.Message(failure); page->error_.IsOpen(!failure.empty());
    }
}

void StatusPage::EnsureBindingView() {
    if (bindingView_) return;
    bindingView_ = unlock_windows::desktop_app::createBindingView([weak = get_weak()] {
        const auto page = weak.get();
        if (!page || page->stopped_) throw hresult_error(RO_E_CLOSED);
        return page->XamlRoot();
    }, [weak = get_weak()](std::wstring failure) {
        if (auto page = weak.get(); page && !page->stopped_) {
            page->saveError_ = std::move(failure);
            page->error_.Message(page->saveError_); page->error_.IsOpen(!page->saveError_.empty());
        }
    }, [weak = get_weak()](const unlock_windows::saved_credential::BindingSummary& binding) {
        if (auto page = weak.get(); page && !page->stopped_) {
            page->resetBindingView_ = binding.state != unlock_windows::system_ble::BindingState::bound;
            page->saveError_.clear();
            page->refreshSnapshot_(page->resetBindingView_);
        }
    });
    statusPanel_.Children().InsertAt(statusPanel_.Children().Size() - 1, bindingView_->content);
}

void StatusPage::SetHost(std::function<void(bool)> refresh) {
    refreshSnapshot_ = std::move(refresh);
}

void StatusPage::SetVisible(bool visible) {
    visible_ = visible;
    if (bindingView_) bindingView_->setVisible(!stopped_ && visible && (!binding_ || binding_->state != unlock_windows::system_ble::BindingState::bound));
}

void StatusPage::Refresh() {
    if (bindingView_ && !stopped_) bindingView_->refresh();
}

bool StatusPage::Busy() const {
    return saving_ || (bindingView_ && bindingView_->busy());
}

void StatusPage::Remove() {
    if (stopped_ || Busy() || !binding_ || binding_->state != unlock_windows::system_ble::BindingState::bound) return;
    try {
        EnsureBindingView();
        bindingView_->content.Visibility(Visibility::Collapsed);
        bindingView_->remove();
        remove_.IsEnabled(false);
        threshold_.IsEnabled(false);
        save_.IsEnabled(false);
    } catch (...) {
        saveError_ = currentException(); error_.Message(saveError_); error_.IsOpen(true);
    }
}
void StatusPage::Stop() {
    stopped_ = true;
    if (bindingView_) bindingView_->stop();
    if (cancellation_ && !SetEvent(cancellation_.get())) OutputDebugStringW(L"Binding management cancellation failed\n");
}
}
