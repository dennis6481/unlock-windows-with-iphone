// Created by Rui MA on 09 Oct 2026
// Non-clickable card layout follows CommunityToolkit SettingsCard (MIT):
// https://github.com/CommunityToolkit/Windows/blob/main/components/SettingsControls/src/SettingsCard/SettingsCard.xaml

#pragma once

#include "../../DesktopNotifications.h"
#include "../../DesktopErrors.h"
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


/// Translate the existing desktop notice severity for a WinUI InfoBar.
inline InfoBarSeverity infoBarSeverity(NoticeSeverity severity) {
    switch (severity) {
    case NoticeSeverity::information: return InfoBarSeverity::Informational;
    case NoticeSeverity::warning: return InfoBarSeverity::Warning;
    case NoticeSeverity::error: return InfoBarSeverity::Error;
    }
    throw hresult_invalid_argument(L"Unknown desktop notice severity.");
}

/// Create wrapping text for the Dashboard shell and independent password window.
inline TextBlock text(const wchar_t* value, double size = 14) {
    TextBlock block;
    block.Text(value);
    block.FontSize(size);
    block.TextWrapping(TextWrapping::Wrap);
    return block;
}

/// Create the shell's existing theme-aware Fluent icon.
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

/// Return a shared proportional shell layout size.
inline GridLength star() { return {1, GridUnitType::Star}; }
/// Return a shared content-sized shell layout size.
inline GridLength automatic() { return {0, GridUnitType::Auto}; }

/// Preserve the existing card layout switch below 640 device-independent pixels.
inline void resizeCard(const Grid& grid, const FrameworkElement& header, const FrameworkElement& content, double width) {
    const bool narrow = width < 640;
    grid.ColumnDefinitions().GetAt(2).Width(narrow ? GridLength{0, GridUnitType::Pixel} : automatic());
    Grid::SetColumnSpan(header, narrow ? 2 : 1);
    header.Margin(narrow ? Thickness{0,0,0,8} : Thickness{0,0,16,0});
    Grid::SetRow(content, narrow ? 1 : 0);
    Grid::SetColumn(content, narrow ? 1 : 2);
    Grid::SetColumnSpan(content, narrow ? 2 : 1);
}
}
