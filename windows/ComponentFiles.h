// Created by Rui MA on 02 Oct 2026

#pragma once

#include <array>

namespace unlock::components {
inline constexpr wchar_t kCredentialProviderFile[] = L"unlock_credential_provider.dll";
inline constexpr wchar_t kSavedCredentialServiceFile[] = L"unlock_saved_credential_service.exe";
inline constexpr wchar_t kGattHostFile[] = L"unlock_gatt_host.exe";
inline constexpr wchar_t kPairingToolFile[] = L"unlock_pairing_tool.exe";
inline constexpr wchar_t kCredentialManagerFile[] = L"unlock_saved_credential_manager.exe";
inline constexpr wchar_t kInstallerFile[] = L"setup.exe";

struct ComponentFile final {
    const wchar_t* name;
    bool desktopTool;
};

inline constexpr std::array<ComponentFile, 6> kComponentFiles{{
    {kCredentialProviderFile, false},
    {kSavedCredentialServiceFile, false},
    {kGattHostFile, true},
    {kPairingToolFile, true},
    {kCredentialManagerFile, true},
    {kInstallerFile, true},
}};
}
