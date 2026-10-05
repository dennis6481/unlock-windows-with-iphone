// Created by Rui MA on 05 Oct 2026

#pragma once

#include "SetupContract.h"
#include <Windows.h>
#include <sddl.h>
#include <vector>

namespace unlock::components {
inline HRESULT readSetupTargetSid(std::wstring& target) {
    target.clear();
    HKEY key = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(),
        0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (status == ERROR_FILE_NOT_FOUND)
        status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath.c_str(),
            0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);
    struct Key final { HKEY value; ~Key() { RegCloseKey(value); } } owner{key};
    DWORD bytes = 0;
    status = RegGetValueW(key, nullptr, kTargetSidValueName, RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);
    if (bytes < 2 * sizeof(wchar_t) || bytes > 1024 || bytes % sizeof(wchar_t))
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    std::vector<wchar_t> value(bytes / sizeof(wchar_t));
    status = RegGetValueW(key, nullptr, kTargetSidValueName, RRF_RT_REG_SZ, nullptr, value.data(), &bytes);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);
    if (bytes < 2 * sizeof(wchar_t) || bytes % sizeof(wchar_t) || bytes > value.size() * sizeof(wchar_t) ||
        value[bytes / sizeof(wchar_t) - 1] != L'\0') return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    const std::wstring text(value.data(), bytes / sizeof(wchar_t) - 1);
    if (text.find(L'\0') != std::wstring::npos) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(text.c_str(), &sid)) return HRESULT_FROM_WIN32(GetLastError());
    LPWSTR normalized = nullptr;
    const BOOL converted = ConvertSidToStringSidW(sid, &normalized);
    const DWORD error = converted ? ERROR_SUCCESS : GetLastError();
    LocalFree(sid);
    if (!converted) return HRESULT_FROM_WIN32(error);
    struct Text final { LPWSTR value; ~Text() { LocalFree(value); } } ownedText{normalized};
    target = normalized;
    return S_OK;
}
}
