// Created by Rui MA on 02 Oct 2026

#pragma once

#include <array>

namespace unlock::components {
inline constexpr wchar_t kCredentialProviderFile[] = L"unlock_credential_provider.dll";
inline constexpr wchar_t kSavedCredentialServiceFile[] = L"unlock_saved_credential_service.exe";
inline constexpr wchar_t kGattHostFile[] = L"unlock_gatt_host.exe";
inline constexpr wchar_t kPairingToolFile[] = L"unlock_pairing_tool.exe";
inline constexpr wchar_t kCredentialManagerFile[] = L"unlock_saved_credential_manager.exe";
inline constexpr wchar_t kInstallerFile[] = L"unlock_windows_components_wizard.exe";
inline constexpr wchar_t kInstallerBuildFile[] = L"setup.exe";

struct ComponentFile final {
    const wchar_t* name;
    const wchar_t* buildName;
    bool desktopTool;
};

inline constexpr std::array<ComponentFile, 6> kComponentFiles{{
    {kCredentialProviderFile, kCredentialProviderFile, false},
    {kSavedCredentialServiceFile, kSavedCredentialServiceFile, false},
    {kGattHostFile, kGattHostFile, true},
    {kPairingToolFile, kPairingToolFile, true},
    {kCredentialManagerFile, kCredentialManagerFile, true},
    {kInstallerFile, kInstallerBuildFile, true},
}};
}
