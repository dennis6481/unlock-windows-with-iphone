// Created on 6 Nov 2026

#pragma once

#include <Windows.h>
#include <credentialprovider.h>
#include <string>

namespace unlock_windows::credential_provider {

/// Pack a saved plaintext password in LogonUI. On success the caller transfers the CoTaskMem buffer to Windows.
[[nodiscard]] HRESULT serializePassword(const std::wstring& qualifiedName, const GUID& providerId,
    PWSTR password, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, BYTE** buffer, DWORD* bytes) noexcept;

} // namespace unlock_windows::credential_provider
