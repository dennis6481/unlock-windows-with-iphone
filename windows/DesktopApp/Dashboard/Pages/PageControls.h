// Created by Rui MA on 09 Oct 2026
// Non-clickable card layout follows CommunityToolkit SettingsCard (MIT):
// https://github.com/CommunityToolkit/Windows/blob/main/components/SettingsControls/src/SettingsCard/SettingsCard.xaml

#pragma once

#include "../../DesktopNotifications.h"
#include "../../../Bluetooth/SystemBleContract.h"
#include <Windows.h>
#undef GetCurrentTime
#include <string>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Controls.Primitives.h>
#include <winrt/Microsoft.UI.Xaml.Markup.h>
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <exception>

namespace unlock_windows::desktop_app::dashboard_ui {
using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Controls;

inline constexpr double kCardSpacing = 6;

inline InfoBarSeverity infoBarSeverity(NoticeSeverity severity) {
    switch (severity) {
    case NoticeSeverity::information: return InfoBarSeverity::Informational;
    case NoticeSeverity::warning: return InfoBarSeverity::Warning;
    case NoticeSeverity::error: return InfoBarSeverity::Error;
    }
    throw hresult_invalid_argument(L"Unknown desktop notice severity.");
}

inline TextBlock text(const wchar_t* value, double size = 14) {
    TextBlock block;
    block.Text(value);
    block.FontSize(size);
    block.TextWrapping(TextWrapping::Wrap);
    return block;
}

inline FontIcon icon(const wchar_t* glyph, double size = 20, bool accent = false) {
    auto result = accent ? Markup::XamlReader::Load(LR"(<FontIcon
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        FontFamily="Segoe Fluent Icons, Segoe MDL2 Assets"
        Foreground="{ThemeResource AccentFillColorDefaultBrush}"/>)").as<FontIcon>() : FontIcon{};
    result.FontFamily(Media::FontFamily(L"Segoe Fluent Icons, Segoe MDL2 Assets"));
    result.Glyph(glyph);
    result.FontSize(size);
    return result;
}

inline GridLength star() { return {1, GridUnitType::Star}; }
inline GridLength automatic() { return {0, GridUnitType::Auto}; }

inline Border settingsCard(const wchar_t* title, const FrameworkElement& content, const wchar_t* glyph,
                           bool stackWhenNarrow = true, const wchar_t* description = nullptr) {
    auto card = Markup::XamlReader::Load(LR"(<Border
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Background="{ThemeResource CardBackgroundFillColorDefaultBrush}"
        BorderBrush="{ThemeResource CardStrokeColorDefaultBrush}"
        BorderThickness="1" CornerRadius="{ThemeResource ControlCornerRadius}"
        MinHeight="68" Padding="16"/>)").as<Border>();
    Grid layout;
    ColumnDefinition iconColumn, headerColumn, contentColumn;
    iconColumn.Width(automatic());
    headerColumn.Width(star()); contentColumn.Width(automatic());
    layout.ColumnDefinitions().Append(iconColumn);
    layout.ColumnDefinitions().Append(headerColumn);
    layout.ColumnDefinitions().Append(contentColumn);
    for (int index = 0; index < 2; ++index) {
        RowDefinition row;
        row.Height(index == 0 ? star() : automatic());
        layout.RowDefinitions().Append(row);
    }
    FrameworkElement header = text(title);
    if (description) {
        StackPanel heading;
        heading.Spacing(4);
        heading.Children().Append(header);
        auto subtitle = Markup::XamlReader::Load(LR"(<TextBlock
            xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
            FontSize="12" TextWrapping="Wrap"
            Foreground="{ThemeResource TextFillColorSecondaryBrush}"/>)").as<TextBlock>();
        subtitle.Text(description);
        heading.Children().Append(subtitle);
        header = heading;
    }
    auto headerIcon = icon(glyph);
    headerIcon.VerticalAlignment(VerticalAlignment::Center);
    headerIcon.Margin({0,0,20,0});
    header.VerticalAlignment(VerticalAlignment::Center);
    header.Margin({0,0,16,0});
    content.VerticalAlignment(VerticalAlignment::Center);
    Grid::SetColumn(header, 1);
    Grid::SetColumn(content, 2);
    layout.Children().Append(headerIcon);
    layout.Children().Append(header);
    layout.Children().Append(content);
    card.Child(layout);
    card.SizeChanged([weakLayout = make_weak(layout), weakHeader = make_weak(header),
                       weakContent = make_weak(content), stackWhenNarrow](const auto&, const SizeChangedEventArgs& args) {
        auto grid = weakLayout.get();
        auto header = weakHeader.get();
        auto content = weakContent.get();
        if (!grid || !header || !content) return;
        const bool narrow = stackWhenNarrow && args.NewSize().Width < 640;
        grid.ColumnDefinitions().GetAt(2).Width(narrow ? GridLength{0, GridUnitType::Pixel} : automatic());
        Grid::SetColumnSpan(header, narrow ? 2 : 1);
        header.Margin(narrow ? Thickness{0,0,0,8} : Thickness{0,0,16,0});
        Grid::SetRow(content, narrow ? 1 : 0);
        Grid::SetColumn(content, narrow ? 1 : 2);
        Grid::SetColumnSpan(content, narrow ? 2 : 1);
    });
    return card;
}

inline constexpr int kDistanceStep = 30;
inline constexpr int kNearThreshold = system_ble::kDefaultThreshold + kDistanceStep;
inline constexpr int kFarThreshold = system_ble::kDefaultThreshold - kDistanceStep;

inline int nearestDistanceThreshold(double value) {
    if (value >= (kNearThreshold + system_ble::kDefaultThreshold) / 2.0) return kNearThreshold;
    if (value >= (kFarThreshold + system_ble::kDefaultThreshold) / 2.0) return system_ble::kDefaultThreshold;
    return kFarThreshold;
}

inline const wchar_t* distanceLabel(int threshold) {
    return threshold == kNearThreshold ? L"Near" : threshold == kFarThreshold ? L"Far" : L"Medium";
}

inline Border signalThresholdCard(const wchar_t* title, const Slider& slider) {
    Grid controls;
    for (auto width : {automatic(), star(), automatic()}) {
        ColumnDefinition column;
        column.Width(width);
        controls.ColumnDefinitions().Append(column);
    }
    auto nearLabel = text(distanceLabel(kNearThreshold));
    auto farLabel = text(distanceLabel(kFarThreshold));
    nearLabel.VerticalAlignment(VerticalAlignment::Center);
    farLabel.VerticalAlignment(VerticalAlignment::Center);
    nearLabel.Margin({0,0,12,0});
    farLabel.Margin({12,0,0,0});
    slider.Width(240);
    slider.HorizontalAlignment(HorizontalAlignment::Stretch);
    slider.VerticalAlignment(VerticalAlignment::Center);
    Grid::SetColumn(slider, 1);
    Grid::SetColumn(farLabel, 2);
    controls.Children().Append(nearLabel);
    controls.Children().Append(slider);
    controls.Children().Append(farLabel);
    const auto glyph = std::wstring(1, static_cast<wchar_t>(Symbol::FourBars));
    return settingsCard(title, controls, glyph.c_str(), true,
        L"RSSI-based range does not indicate an exact distance.");
}

inline void rethrowNonlocalUiError(const hresult_error& error) {
    const auto code = error.code();
    if (code == E_OUTOFMEMORY || code == RPC_E_WRONG_THREAD || code == E_UNEXPECTED ||
        code == E_POINTER || code == E_INVALIDARG) throw;
}

inline std::wstring currentException() {
    try { throw; }
    catch (const hresult_error& error) {
        return std::wstring(error.message()) + L" (HRESULT=" +
            std::to_wstring(static_cast<unsigned long>(error.code().value)) + L")";
    }
    catch (const std::exception& error) { return std::wstring(to_hstring(error.what())); }
    catch (...) { return L"Unknown desktop error."; }
}
}
