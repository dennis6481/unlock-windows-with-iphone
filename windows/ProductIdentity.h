// Shared machine identity. Installation transactions are never an identity source.
#pragma once
#include <Windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <sddl.h>
#include <filesystem>
#include <string>
#include <string_view>

namespace unlock::components {
inline constexpr wchar_t kProductRegistryPath[] = L"SOFTWARE\\UnlockWindowsWithIPhone";
inline constexpr wchar_t kInstalledProductRegistryPath[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\InstalledProduct";
inline constexpr wchar_t kTargetSidValueName[] = L"TargetSid";
inline constexpr wchar_t kInstalledVersionValueName[] = L"InstalledVersion";
inline constexpr wchar_t kDeploymentKindValueName[] = L"DeploymentKind";
inline constexpr wchar_t kMsiProductCodeValueName[] = L"MsiProductCode";
inline constexpr wchar_t kDesktopDirectoryName[] = L"Unlock Windows with iPhone";
inline constexpr wchar_t kStartupRegistryPath[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
inline constexpr wchar_t kSetupPromptValueName[] = L"SetupPromptPending";
inline HRESULT readProductDirectory(std::filesystem::path& directory) {
    directory.clear();
    PWSTR raw = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, nullptr, &raw);
    if (FAILED(result)) return result;
    const std::filesystem::path root(raw);
    CoTaskMemFree(raw);
    directory = root / kDesktopDirectoryName;
    return S_OK;
}
inline HRESULT readSetupTargetSid(std::wstring& target) {
    target.clear();
    wchar_t value[256]{};
    DWORD bytes = sizeof(value);
    const auto status = RegGetValueW(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath,
        kTargetSidValueName, RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, value, &bytes);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);
    if (bytes < 2 * sizeof(wchar_t) || bytes > sizeof(value) || bytes % sizeof(wchar_t))
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    const std::wstring_view text(value, bytes / sizeof(wchar_t));
    if (text.back() != L'\0' || text.find(L'\0') != text.size() - 1)
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(value, &sid)) return HRESULT_FROM_WIN32(GetLastError());
    LPWSTR normalized = nullptr;
    const BOOL converted = ConvertSidToStringSidW(sid, &normalized);
    const DWORD error = converted ? ERROR_SUCCESS : GetLastError();
    LocalFree(sid);
    if (!converted) return HRESULT_FROM_WIN32(error);
    target = normalized;
    LocalFree(normalized);
    if (target == L"S-1-5-18" || target == L"S-1-5-19" || target == L"S-1-5-20") {
        target.clear(); return E_INVALIDARG;
    }
    return S_OK;
}
}
