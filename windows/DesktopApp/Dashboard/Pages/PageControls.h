// Created by Rui MA on 09 Oct 2026
// Non-clickable card layout follows CommunityToolkit SettingsCard (MIT):
// https://github.com/CommunityToolkit/Windows/blob/main/components/SettingsControls/src/SettingsCard/SettingsCard.xaml

#pragma once

#include "../../DesktopNotifications.h"
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

inline Border settingsCard(const wchar_t* title, const FrameworkElement& content, const wchar_t* glyph) {
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
    auto header = text(title);
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
                      weakContent = make_weak(content)](const auto&, const SizeChangedEventArgs& args) {
        auto grid = weakLayout.get();
        auto header = weakHeader.get();
        auto content = weakContent.get();
        if (!grid || !header || !content) return;
        const bool narrow = args.NewSize().Width < 640;
        grid.ColumnDefinitions().GetAt(2).Width(narrow ? GridLength{0, GridUnitType::Pixel} : automatic());
        Grid::SetColumnSpan(header, narrow ? 2 : 1);
        header.Margin(narrow ? Thickness{0,0,0,8} : Thickness{0,0,16,0});
        Grid::SetRow(content, narrow ? 1 : 0);
        Grid::SetColumn(content, narrow ? 1 : 2);
        Grid::SetColumnSpan(content, narrow ? 2 : 1);
    });
    return card;
}

inline Border signalThresholdCard(const wchar_t* title, const TextBlock& value,
                                 const Slider& slider, const Button& action = nullptr) {
    Grid row;
    for (auto width : {automatic(), star(), automatic()}) {
        ColumnDefinition column;
        column.Width(width);
        row.ColumnDefinitions().Append(column);
    }
    value.VerticalAlignment(VerticalAlignment::Center);
    value.Margin({0,0,12,0});
    slider.VerticalAlignment(VerticalAlignment::Center);
    slider.MaxWidth(240);
    slider.Width(240);
    slider.HorizontalAlignment(HorizontalAlignment::Stretch);
    Grid::SetColumn(slider, 1);
    row.Children().Append(value);
    row.Children().Append(slider);
    if (action) {
        action.VerticalAlignment(VerticalAlignment::Center);
        action.Margin({12,0,0,0});
        Grid::SetColumn(action, 2);
        row.Children().Append(action);
    }
    const auto glyph = std::wstring(1, static_cast<wchar_t>(Symbol::FourBars));
    return settingsCard(title, row, glyph.c_str());
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
