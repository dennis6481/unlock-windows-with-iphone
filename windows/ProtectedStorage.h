// Created by Rui MA on 11 Oct 2026

#pragma once

#include <Windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <filesystem>
#include <stdexcept>
#include <winrt/base.h>

namespace unlock_windows::storage {
inline void verifyProtectedPath(const std::filesystem::path& path, bool directory) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory)
        throw std::runtime_error("Protected storage path is unavailable, has the wrong type or is a reparse point");
    PSECURITY_DESCRIPTOR raw = nullptr; PACL acl = nullptr; PSID owner = nullptr;
    const DWORD result = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &raw);
    if (result != ERROR_SUCCESS) throw winrt::hresult_error(HRESULT_FROM_WIN32(result));
    struct Descriptor final { PSECURITY_DESCRIPTOR value; ~Descriptor() { LocalFree(value); } } descriptor{raw};
    BYTE system[SECURITY_MAX_SID_SIZE]{}, administrators[SECURITY_MAX_SID_SIZE]{};
    DWORD systemSize = sizeof(system), adminSize = sizeof(administrators);
    winrt::check_bool(CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemSize));
    winrt::check_bool(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &adminSize));
    if (!acl || !owner || (!EqualSid(owner, system) && !EqualSid(owner, administrators)))
        throw std::runtime_error("Protected storage is not owned by SYSTEM or Administrators");
    constexpr DWORD writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        LPVOID entry = nullptr; winrt::check_bool(GetAce(acl, index, &entry));
        const auto header = static_cast<ACE_HEADER*>(entry);
        if (header->AceFlags & INHERIT_ONLY_ACE || header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) throw std::runtime_error("Unsupported protected storage ACL entry");
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
        if ((ace->Mask & writes) && !EqualSid(&ace->SidStart, system) && !EqualSid(&ace->SidStart, administrators))
            throw std::runtime_error("Protected storage is writable by another identity");
    }
}

inline void ensureProtectedDirectory(const std::filesystem::path& path, bool create) {
    if (create) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        winrt::check_bool(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1, &descriptor, nullptr));
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        const BOOL made = CreateDirectoryW(path.c_str(), &attributes);
        const DWORD error = GetLastError(); LocalFree(descriptor);
        if (!made && error != ERROR_ALREADY_EXISTS) throw winrt::hresult_error(HRESULT_FROM_WIN32(error));
    }
    verifyProtectedPath(path, true);
}
}
