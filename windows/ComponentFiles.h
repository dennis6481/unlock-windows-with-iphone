// Created by Rui MA on 02 Oct 2026

#pragma once

#include <array>
#include <cstdint>

namespace unlock::components {
inline constexpr std::uint32_t kMinimumWindowsBuild = 19041;
inline constexpr wchar_t kCredentialProviderFile[] = L"unlock_credential_provider.dll";
inline constexpr wchar_t kSavedCredentialServiceFile[] = L"unlock_saved_credential_service.exe";
inline constexpr wchar_t kMainAppFile[] = L"UnlockWithIPhone.exe";

inline constexpr std::array<const wchar_t*, 3> kComponentFiles{{
    kCredentialProviderFile,
    kSavedCredentialServiceFile,
    kMainAppFile,
}};
}
