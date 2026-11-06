// Created on 6 Nov 2026
// Portions adapted from Windows-classic-samples, Copyright (c) Microsoft Corporation.
// Distributed under the MIT license; see ../../LICENSE.md.

#include "CredentialSerialization.h"
#include "../SavedCredential/SavedCredentialIpc.h"
#include <wincred.h>
#include <cstring>
#include <cwchar>
#include <limits>
#include <new>
#include <string_view>
#include <vector>

namespace unlock_windows::credential_provider {
namespace {

struct ProtectedPassword final {
    std::vector<wchar_t> value;
    ~ProtectedPassword() {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    }
};

// Adapted from Microsoft's V2 Credential Provider sample, helpers.cpp:
// https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider/cpp
HRESULT packLocalPassword(const std::wstring& qualifiedName, PWSTR password,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, BYTE** buffer, DWORD* bytes) {
    const auto separator = qualifiedName.find(L'\\');
    if (separator == std::wstring::npos || separator == 0 || separator + 1 == qualifiedName.size() ||
        qualifiedName.find(L'\\', separator + 1) != std::wstring::npos) return E_INVALIDARG;
    const std::wstring_view domain(qualifiedName.data(), separator);
    const std::wstring_view user(qualifiedName.data() + separator + 1, qualifiedName.size() - separator - 1);

    DWORD protectedChars = 0;
    if (CredProtectW(FALSE, password, static_cast<DWORD>(std::wcslen(password) + 1),
            nullptr, &protectedChars, nullptr)) return E_UNEXPECTED;
    const DWORD error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER) return HRESULT_FROM_WIN32(error);
    if (protectedChars == 0) return E_UNEXPECTED;
    ProtectedPassword protectedPassword;
    protectedPassword.value.resize(protectedChars);
    if (!CredProtectW(FALSE, password, static_cast<DWORD>(std::wcslen(password) + 1),
            protectedPassword.value.data(), &protectedChars, nullptr)) return HRESULT_FROM_WIN32(GetLastError());

    const std::wstring_view secret(protectedPassword.value.data());
    constexpr auto maxChars = std::numeric_limits<USHORT>::max() / sizeof(wchar_t);
    if (domain.size() > maxChars || user.size() > maxChars || secret.size() > maxChars) return E_INVALIDARG;
    const auto total = static_cast<DWORD>(sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) +
        (domain.size() + user.size() + secret.size()) * sizeof(wchar_t));
    auto* packed = static_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(CoTaskMemAlloc(total));
    if (!packed) return E_OUTOFMEMORY;
    *packed = {};
    packed->Logon.MessageType = scenario == CPUS_UNLOCK_WORKSTATION ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;
    auto* begin = reinterpret_cast<BYTE*>(packed);
    auto* cursor = begin + sizeof(*packed);
    const auto copy = [&](std::wstring_view source, UNICODE_STRING& target) {
        target.Length = static_cast<USHORT>(source.size() * sizeof(wchar_t));
        target.MaximumLength = target.Length;
        std::memcpy(cursor, source.data(), target.Length);
        target.Buffer = reinterpret_cast<PWSTR>(cursor - begin);
        cursor += target.Length;
    };
    copy(domain, packed->Logon.LogonDomainName);
    copy(user, packed->Logon.UserName);
    copy(secret, packed->Logon.Password);
    *buffer = begin;
    *bytes = total;
    return S_OK;
}

} // namespace

HRESULT serializePassword(const std::wstring& qualifiedName, const GUID& providerId,
    PWSTR password, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, BYTE** buffer, DWORD* bytes) noexcept {
    if (!buffer || !bytes) return E_POINTER;
    *buffer = nullptr;
    *bytes = 0;
    if ((scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) || qualifiedName.empty() ||
        qualifiedName.size() > saved_credential::kMaxQualifiedUserNameChars || qualifiedName.find(L'\0') != std::wstring::npos ||
        !password || !*password || std::wcslen(password) > saved_credential::kMaxPasswordChars) return E_INVALIDARG;
    try {
        if (saved_credential::isLocalAccountProvider(providerId))
            return packLocalPassword(qualifiedName, password, scenario, buffer, bytes);

        constexpr DWORD flags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;
        DWORD size = 0;
        if (CredPackAuthenticationBufferW(flags, const_cast<PWSTR>(qualifiedName.c_str()), password, nullptr, &size))
            return E_UNEXPECTED;
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) return HRESULT_FROM_WIN32(error);
        if (size == 0) return E_UNEXPECTED;
        const DWORD allocated = size;
        auto* packed = static_cast<BYTE*>(CoTaskMemAlloc(allocated));
        if (!packed) return E_OUTOFMEMORY;
        if (!CredPackAuthenticationBufferW(flags, const_cast<PWSTR>(qualifiedName.c_str()), password, packed, &size)) {
            const HRESULT result = HRESULT_FROM_WIN32(GetLastError());
            SecureZeroMemory(packed, allocated);
            CoTaskMemFree(packed);
            return result;
        }
        *buffer = packed;
        *bytes = size;
        return S_OK;
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    }
}

} // namespace unlock_windows::credential_provider
