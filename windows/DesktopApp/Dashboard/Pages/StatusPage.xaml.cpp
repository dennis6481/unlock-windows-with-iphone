// Created by Rui MA on 09 Oct 2026

#include "StatusPage.xaml.h"
#include "StatusPage.g.cpp"
#include "PageControls.h"
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include "../../../Enrollment/BindingClient.h"

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
using namespace Microsoft::UI::Xaml::Markup;

void StatusPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    if (statusPanel_) return;
    statusPanel_ = StackPanel{};
    statusPanel_.Spacing(12);
    auto phone = icon(L"\xE8EA", 100);
    phone.HorizontalAlignment(HorizontalAlignment::Center);
    Automation::AutomationProperties::SetName(phone, L"iPhone");
    statusPanel_.Children().Append(phone);
    name_ = text(L"iPhone", 24);
    name_.TextAlignment(TextAlignment::Center);
    statusPanel_.Children().Append(name_);
    statusText_ = text(L"");
    statusText_.TextAlignment(TextAlignment::Center);
    statusPanel_.Children().Append(statusText_);
    connection_ = text(L"");
    connection_.TextAlignment(TextAlignment::Center);
    statusPanel_.Children().Append(connection_);

    auto card = XamlReader::Load(LR"(<Border
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Background="{ThemeResource CardBackgroundFillColorDefaultBrush}"
        BorderBrush="{ThemeResource CardStrokeColorDefaultBrush}"
        BorderThickness="1" CornerRadius="8" Padding="20,18" Margin="0,16,0,0"/>)").as<Border>();
    Grid approval;
    ColumnDefinition labelColumn;
    labelColumn.Width(star());
    approval.ColumnDefinitions().Append(labelColumn);
    ColumnDefinition valueColumn;
    valueColumn.Width(automatic());
    approval.ColumnDefinitions().Append(valueColumn);
    approval.Children().Append(text(L"Last approval"));
    auto value = text(L"N/A");
    Grid::SetColumn(value, 1);
    approval.Children().Append(value);
    card.Child(approval);
    approvalCard_ = card;
    statusPanel_.Children().Append(card);

    thresholdText_ = text(L"RSSI threshold");
    threshold_ = Slider{};
    threshold_.Minimum(unlock_windows::system_ble::kMinimumThreshold);
    threshold_.Maximum(unlock_windows::system_ble::kMaximumThreshold);
    threshold_.StepFrequency(unlock_windows::system_ble::kThresholdStep);
    threshold_.Value(unlock_windows::system_ble::kDefaultThreshold);
    Automation::AutomationProperties::SetName(threshold_, L"Saved RSSI threshold in dBm");
    threshold_.ValueChanged([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && !page->updating_) {
            page->dirty_ = page->binding_ && static_cast<int>(page->threshold_.Value()) != page->binding_->record.threshold;
            page->thresholdText_.Text(L"RSSI threshold: " + to_hstring(static_cast<int>(page->threshold_.Value())) + L" dBm");
            page->save_.IsEnabled(page->dirty_ && !page->saving_ && !page->stopped_);
        }
    });
    save_ = Button{};
    save_.Content(box_value(L"Save"));
    save_.Click([weak = get_weak()](const auto&, const auto&) { save(weak); });
    statusPanel_.Children().Append(thresholdText_);
    statusPanel_.Children().Append(threshold_);
    StackPanel actions;
    actions.Orientation(Orientation::Horizontal); actions.Spacing(12);
    actions.Children().Append(save_);
    statusPanel_.Children().Append(actions);

    error_ = InfoBar{};
    error_.Severity(InfoBarSeverity::Error);
    error_.IsClosable(false);
    statusPanel_.Children().Append(error_);

    BodyHost().Content(statusPanel_);
}

void StatusPage::Update(unlock_windows::desktop_app::DashboardSnapshot const& snapshot) {
    const bool known = snapshot.paired.has_value();
    const bool paired = snapshot.paired.value_or(false);
    const bool bound = snapshot.binding && snapshot.binding->state == unlock_windows::system_ble::BindingState::bound;
    name_.Text(!known ? L"Binding status unavailable" : bound ?
        (snapshot.binding->record.displayName.empty() ? L"Name unavailable" : snapshot.binding->record.displayName) : L"Bind an iPhone");
    statusText_.Text(!known || paired || snapshot.busy ? snapshot.status :
        L"No iPhone is bound. Pair it in Windows Bluetooth settings, then select it below.");
    connection_.Text(bound ? snapshot.connection : L"");
    approvalCard_.Visibility(known && paired ? Visibility::Visible : Visibility::Collapsed);
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
    thresholdText_.Text(L"RSSI threshold: " + to_hstring(static_cast<int>(threshold_.Value())) + L" dBm");
    thresholdText_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    threshold_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    threshold_.IsEnabled(bound && !Busy() && !stopped_);
    save_.Visibility(bound ? Visibility::Visible : Visibility::Collapsed);
    save_.IsEnabled(bound && dirty_ && !Busy() && !stopped_);
    error_.Message(saveError_.empty() ? snapshot.error : saveError_);
    error_.IsOpen(!saveError_.empty() || !snapshot.error.empty());
}

fire_and_forget StatusPage::save(weak_ref<StatusPage> weak) {
    using namespace unlock_windows::saved_credential;
    auto page = weak.get();
    if (!page || page->stopped_ || page->Busy() || !page->binding_ || !page->dirty_) co_return;
    page->saving_ = true; page->threshold_.IsEnabled(false); page->save_.IsEnabled(false);
    BindingChange change{*page->binding_, page->binding_->record, {}};
    change.candidate.threshold = static_cast<int>(page->threshold_.Value());
    try { page->cancellation_ = unlock_windows::enrollment::createCancellation(change.candidate.accountSid, change.cancelEvent); }
    catch (...) {
        page->saving_ = false; page->saveError_ = currentException();
        page->threshold_.Value(page->binding_->record.threshold); page->dirty_ = false;
        page->threshold_.IsEnabled(true);
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
        saved = BindingSummary{unlock_windows::system_ble::BindingState::bound, change.candidate};
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
        page->threshold_.Value(page->binding_ ? page->binding_->record.threshold : unlock_windows::system_ble::kDefaultThreshold);
        page->updating_ = false;
        page->thresholdText_.Text(L"RSSI threshold: " + to_hstring(static_cast<int>(page->threshold_.Value())) + L" dBm");
        page->threshold_.IsEnabled(true);
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
