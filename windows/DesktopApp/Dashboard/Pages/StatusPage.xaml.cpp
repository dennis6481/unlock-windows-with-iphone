// Created by Rui MA on 09 Oct 2026

#include "StatusPage.xaml.h"
#include "StatusPage.g.cpp"
#include "PageControls.h"
#include "../UnlockRange.h"
#include <winrt/Microsoft.UI.Xaml.Data.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <winrt/Windows.UI.Xaml.Interop.h>
#include <winrt/Microsoft.UI.Input.h>
#include <winrt/Windows.System.h>

namespace winrt::UnlockDesktop::implementation {
using namespace unlock_windows::desktop_app::dashboard_ui;
namespace {
struct DistanceToolTip : implements<DistanceToolTip, Microsoft::UI::Xaml::Data::IValueConverter> {
    /// Convert the positive slider value into its existing range label.
    Windows::Foundation::IInspectable Convert(const Windows::Foundation::IInspectable& value,
        const Windows::UI::Xaml::Interop::TypeName&, const Windows::Foundation::IInspectable&, const hstring&) {
        return box_value(hstring(distanceLabel(nearestDistanceThreshold(-unbox_value<double>(value)))));
    }
    /// Reject reverse conversion because the tooltip is display-only.
    Windows::Foundation::IInspectable ConvertBack(const Windows::Foundation::IInspectable&,
        const Windows::UI::Xaml::Interop::TypeName&, const Windows::Foundation::IInspectable&, const hstring&) {
        throw hresult_not_implemented();
    }
};
/// Identify keys whose release commits a range gesture.
bool distanceKey(Windows::System::VirtualKey key) {
    using Windows::System::VirtualKey;
    return key == VirtualKey::Left || key == VirtualKey::Right || key == VirtualKey::Up ||
        key == VirtualKey::Down || key == VirtualKey::Home || key == VirtualKey::End ||
        key == VirtualKey::PageUp || key == VirtualKey::PageDown;
}
}
StatusPage::StatusPage() {
    viewModel_ = make<StatusViewModel>();
    InitializeComponent();
    DataContext(viewModel_);
    const auto threshold = Threshold();
    threshold.Minimum(-kNearThreshold); threshold.Maximum(-kFarThreshold);
    threshold.StepFrequency(kDistanceStep); threshold.TickFrequency(kDistanceStep);
    threshold.ThumbToolTipValueConverter(make<DistanceToolTip>());
    NearLabel().Text(distanceLabel(kNearThreshold)); FarLabel().Text(distanceLabel(kFarThreshold));
    RangeIcon().Glyph(std::wstring(1, static_cast<wchar_t>(Symbol::FourBars)));
    RemovalIcon().Glyph(std::wstring(1, static_cast<wchar_t>(Symbol::Delete)));
    threshold.ValueChanged([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get(); page && !page->updating_) {
            get_self<StatusViewModel>(page->viewModel_)->PreviewRange(page->Threshold().Value());
            // Slider input handlers run after its class handling, including automation changes.
            page->QueueThresholdAction();
        }
    });
    using namespace Microsoft::UI::Xaml::Input;
    threshold.AddHandler(UIElement::PointerPressedEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const PointerRoutedEventArgs& args) {
            if (auto page = weak.get(); page && args.GetCurrentPoint(page->Threshold()).Properties().IsLeftButtonPressed()) {
                if (!page->thresholdPointerActive_) ++page->thresholdInteraction_;
                page->thresholdPointerActive_ = true;
            }
        }}), true);
    threshold.AddHandler(UIElement::PointerReleasedEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const auto&) {
            if (auto page = weak.get(); page && page->thresholdPointerActive_) {
                page->thresholdPointerActive_ = false; page->QueueThresholdAction();
            }
        }}), true);
    threshold.AddHandler(UIElement::PointerCaptureLostEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const auto&) { if (auto page = weak.get()) page->QueueThresholdAction(true); }}), true);
    threshold.AddHandler(UIElement::PointerCanceledEvent(), box_value(PointerEventHandler{
        [weak = get_weak()](const auto&, const auto&) { if (auto page = weak.get()) page->ResetThresholdPreview(); }}), true);
    threshold.AddHandler(UIElement::KeyDownEvent(), box_value(KeyEventHandler{
        [weak = get_weak()](const auto&, const KeyRoutedEventArgs& args) {
            if (auto page = weak.get()) {
                if (distanceKey(args.Key())) {
                    if (!page->thresholdKeyActive_) ++page->thresholdInteraction_;
                    page->thresholdKeyActive_ = true;
                } else if (args.Key() == Windows::System::VirtualKey::Escape) page->ResetThresholdPreview();
            }
        }}), true);
    threshold.AddHandler(UIElement::KeyUpEvent(), box_value(KeyEventHandler{
        [weak = get_weak()](const auto&, const KeyRoutedEventArgs& args) {
            if (auto page = weak.get(); page && distanceKey(args.Key()) && page->thresholdKeyActive_) {
                page->thresholdKeyActive_ = false; page->QueueThresholdAction();
            }
        }}), true);
    threshold.LostFocus([weak = get_weak()](const auto&, const auto&) {
        if (auto page = weak.get()) {
            auto* model = get_self<StatusViewModel>(page->viewModel_);
            if (!model->Saving() && (model->RangeDirty() || page->thresholdPointerActive_ || page->thresholdKeyActive_))
                page->ResetThresholdPreview();
        }
    });
    viewModel_.PropertyChanged([weak = get_weak()](const auto&, const auto& args) {
        if (auto page = weak.get(); page && args.PropertyName() == L"ManagementEnabled" && !page->viewModel_.ManagementEnabled())
            page->RemovalFlyout().Hide();
    });
}
void StatusPage::OnNavigatedTo(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) { get_self<StatusViewModel>(viewModel_)->Visible(true); }
void StatusPage::OnNavigatedFrom(Microsoft::UI::Xaml::Navigation::NavigationEventArgs const&) {
    get_self<StatusViewModel>(viewModel_)->Visible(false); ResetThresholdPreview(); DismissBindingSuccess();
}
void StatusPage::ResetThresholdPreview() {
    ++thresholdInteraction_; thresholdPointerActive_ = thresholdKeyActive_ = false;
    updating_ = true;
    get_self<StatusViewModel>(viewModel_)->ResetRange();
    updating_ = false;
}
void StatusPage::FinishThresholdInteraction() {
    auto* model = get_self<StatusViewModel>(viewModel_);
    if (!model->CanFinishRange()) { ResetThresholdPreview(); return; }
    updating_ = true;
    Threshold().Value(-nearestDistanceThreshold(-Threshold().Value()));
    model->PreviewRange(Threshold().Value());
    updating_ = false;
    if (model->RangeDirty()) { ++thresholdInteraction_; viewModel_.SaveRangeCommand().Execute(nullptr); }
}
void StatusPage::QueueThresholdAction(bool cancel) {
    const auto interaction = thresholdInteraction_;
    if (!DispatcherQueue().TryEnqueue([weak = get_weak(), interaction, cancel] {
        if (auto page = weak.get(); page && interaction == page->thresholdInteraction_) {
            if (cancel) {
                if (page->thresholdPointerActive_) page->ResetThresholdPreview();
            } else if (!page->thresholdPointerActive_ && !page->thresholdKeyActive_) page->FinishThresholdInteraction();
        }
    })) {
        ResetThresholdPreview(); get_self<StatusViewModel>(viewModel_)->RangeSchedulingFailed();
    }
}
void StatusPage::DismissBindingSuccess() { viewModel_.SuccessOpen(false); }
void StatusPage::Update(unlock_windows::desktop_app::DashboardSnapshot const& snapshot) {
    auto* model = get_self<StatusViewModel>(viewModel_);
    const auto reset = model->Update(snapshot);
    if (reset || (!model->RangeDirty() && !thresholdPointerActive_ && !thresholdKeyActive_)) ResetThresholdPreview();
}
void StatusPage::SetHost(std::function<void(bool)> refresh, unlock_windows::desktop_app::Dashboard::ReportError reportError) {
    get_self<StatusViewModel>(viewModel_)->SetHost(std::move(refresh), std::move(reportError));
}
void StatusPage::Refresh() { get_self<StatusViewModel>(viewModel_)->Refresh(); }
void StatusPage::Stop() {
    get_self<StatusViewModel>(viewModel_)->Stop(); ResetThresholdPreview(); RemovalFlyout().Hide();
}
void StatusPage::ThresholdCardSizeChanged(const Windows::Foundation::IInspectable&, const SizeChangedEventArgs& args) {
    resizeCard(ThresholdLayout(), ThresholdHeading(), ThresholdControls(), args.NewSize().Width);
}
void StatusPage::RemovalCardSizeChanged(const Windows::Foundation::IInspectable&, const SizeChangedEventArgs& args) {
    resizeCard(RemovalLayout(), RemovalHeading(), RemoveButton(), args.NewSize().Width);
}
void StatusPage::ConfirmRemovalClick(const Windows::Foundation::IInspectable&, const RoutedEventArgs&) {
    RemovalFlyout().Hide(); viewModel_.RemoveCommand().Execute(nullptr);
}
void StatusPage::BindButtonLoaded(const Windows::Foundation::IInspectable&, const RoutedEventArgs&) {
    Data::Binding foreground;
    foreground.Source(Media::VisualTreeHelper::GetChild(BindButton(), 0).as<ContentPresenter>());
    foreground.Path(PropertyPath(L"Foreground")); foreground.Mode(Data::BindingMode::OneWay);
    BindText().SetBinding(TextBlock::ForegroundProperty(), foreground);
}
void StatusPage::SuccessClosed(const Windows::Foundation::IInspectable&, const InfoBarClosedEventArgs&) { get_self<StatusViewModel>(viewModel_)->SuccessClosed(); }
}
