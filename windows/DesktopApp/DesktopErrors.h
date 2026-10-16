// Created by Rui MA on 16 Oct 2026

#pragma once

#include <Windows.h>
#undef GetCurrentTime
#include <winrt/base.h>
#include <exception>
#include <string>

namespace unlock_windows::desktop_app::dashboard_ui {
/// Propagate process-wide failures instead of treating them as local UI errors.
inline void rethrowNonlocalUiError(const winrt::hresult_error& error) {
    const auto code = error.code();
    if (code == E_OUTOFMEMORY || code == RPC_E_WRONG_THREAD || code == E_UNEXPECTED ||
        code == E_POINTER || code == E_INVALIDARG) throw;
}

/// Format the active exception for the existing desktop diagnostics and feedback.
inline std::wstring currentException() {
    try { throw; }
    catch (const winrt::hresult_error& error) {
        return std::wstring(error.message()) + L" (hresult=" +
            std::to_wstring(static_cast<unsigned long>(error.code().value)) + L")";
    }
    catch (const std::exception& error) { return std::wstring(winrt::to_hstring(error.what())); }
    catch (...) { return L"Unknown desktop error."; }
}
}
