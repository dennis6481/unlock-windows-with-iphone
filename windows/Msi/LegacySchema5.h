#pragma once
#include "Platform.h"
#include "LegacyManifest.h"
#include <vector>
namespace unlock::components::msi {
inline constexpr DWORD kLegacySchema = 5;
inline constexpr wchar_t kLegacySchemaValueName[] = L"SchemaVersion";
inline constexpr wchar_t kLegacyWizardPathValueName[] = L"WizardPath";
inline constexpr wchar_t kLegacyLastOperationIdValueName[] = L"LastOperationId";
inline constexpr wchar_t kLegacyOperationMutex[] = L"Global\\UnlockWindowsWithIPhone-ComponentOperation";
inline constexpr wchar_t kLegacyTransaction[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\ComponentsWizard";
inline constexpr wchar_t kLegacyUninstall[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\UnlockWindowsWithIPhone";
inline constexpr wchar_t kLegacyResult[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\ComponentResult";
inline std::optional<ProductVersion> supportedLegacyVersion(DWORD schema, std::wstring_view text) {
    if (schema != kLegacySchema) return {};
    const auto version = parseProductVersion(text);
    return version && version->text() == text ? version : std::nullopt;
}
struct LegacyInstallation {
    std::wstring sid;
    ProductVersion version;
    std::vector<PackageFile> files;
};
std::wstring providerClsid();
std::vector<std::wstring> deploymentRegistryKeys();
ProductVersion binaryVersion(const std::filesystem::path& path);
WORD binaryMachine(const std::filesystem::path& path);
std::optional<LegacyInstallation> readLegacyInstallation();
std::filesystem::path legacyTarget(const PackageFile& file);
}
