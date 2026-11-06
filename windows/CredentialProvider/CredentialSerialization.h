// Created on 6 Nov 2026

#pragma once

#include <Windows.h>
#include <credentialprovider.h>
#include <span>
#include <string>
#include <vector>

namespace unlock_windows::credential_provider {

/// Store password characters and clear them when the buffer leaves scope.
struct PasswordBuffer final {
    std::vector<wchar_t> value;
    ~PasswordBuffer() {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    }
};

/// Pack a saved plaintext password buffer including its NUL terminator in LogonUI.
/// On success the caller transfers the CoTaskMem buffer to Windows.
[[nodiscard]] HRESULT serializePassword(const std::wstring& qualifiedName, const GUID& providerId,
    std::span<wchar_t> password, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, BYTE** buffer, DWORD* bytes) noexcept;

} // namespace unlock_windows::credential_provider
