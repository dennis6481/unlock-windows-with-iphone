// Created by Rui MA on 16 Oct 2026

#pragma once

#include <Windows.h>
#undef GetCurrentTime
#include <winrt/base.h>
#include <exception>
#include <string>

namespace unlock_windows::desktop_app::ui {
/// Identify failures that must propagate instead of being treated as local UI errors.
inline bool isNonlocalUiError(const winrt::hresult_error& error) {
    const auto code = error.code();
    return code == E_OUTOFMEMORY || code == RPC_E_WRONG_THREAD || code == E_UNEXPECTED ||
        code == E_POINTER || code == E_INVALIDARG;
}

/// Format a captured exception for the existing desktop diagnostics and feedback.
/// @param exception Non-null exception captured by the caller in a catch handler.
inline std::wstring formatException(const std::exception_ptr& exception) {
    try { std::rethrow_exception(exception); }
    catch (const winrt::hresult_error& error) {
        return std::wstring(error.message()) + L" (hresult=" +
            std::to_wstring(static_cast<unsigned long>(error.code().value)) + L")";
    }
    catch (const std::exception& error) { return std::wstring(winrt::to_hstring(error.what())); }
    catch (...) { return L"Unknown desktop error."; }
}
}
