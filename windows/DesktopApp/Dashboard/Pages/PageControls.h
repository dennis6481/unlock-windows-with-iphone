// Created by Rui MA on 09 Oct 2026

#pragma once

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

inline TextBlock text(const wchar_t* value, double size = 14) {
    TextBlock block;
    block.Text(value);
    block.FontSize(size);
    block.TextWrapping(TextWrapping::Wrap);
    return block;
}

inline FontIcon icon(const wchar_t* glyph, double size = 20) {
    FontIcon result;
    result.FontFamily(Media::FontFamily(L"Segoe Fluent Icons, Segoe MDL2 Assets"));
    result.Glyph(glyph);
    result.FontSize(size);
    return result;
}

inline GridLength star() { return {1, GridUnitType::Star}; }
inline GridLength automatic() { return {0, GridUnitType::Auto}; }

inline std::wstring currentException() {
    try { throw; }
    catch (const hresult_error& error) {
        return std::wstring(error.message()) + L" (HRESULT=" +
            std::to_wstring(static_cast<unsigned long>(error.code().value)) + L")";
    }
    catch (const std::exception& error) { return std::wstring(to_hstring(error.what())); }
    catch (...) { return L"Unknown Dashboard error."; }
}
}
