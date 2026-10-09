// Created by Rui MA on 09 Oct 2026

#include "StatusPage.xaml.h"
#include "StatusPage.g.cpp"
#include "PageControls.h"
#include <winrt/Microsoft.UI.Xaml.Automation.h>

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

    error_ = InfoBar{};
    error_.Severity(InfoBarSeverity::Error);
    error_.IsClosable(false);
    statusPanel_.Children().Append(error_);

    BodyHost().Content(statusPanel_);
}

void StatusPage::Update(unlock_windows::desktop_app::DashboardSnapshot const& snapshot) {
    const bool known = snapshot.paired.has_value();
    const bool paired = snapshot.paired.value_or(false);
    name_.Text(!known ? L"Pairing status unavailable" : paired ? L"iPhone" : L"Pair an iPhone");
    statusText_.Text(!known || paired || snapshot.busy ? snapshot.status :
        L"Open Unlock PC on your iPhone, then choose Add a Windows PC.");
    connection_.Text(snapshot.connection);
    approvalCard_.Visibility(known && paired ? Visibility::Visible : Visibility::Collapsed);
    error_.Title(L"Status needs attention");
    error_.Message(snapshot.error);
    error_.IsOpen(!snapshot.error.empty());
}
}
