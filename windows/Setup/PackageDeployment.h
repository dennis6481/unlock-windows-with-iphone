// Created by Rui MA on 09 Oct 2026
// Embedded package verification, transaction staging and manifest-owned file deployment.

#pragma once
#include "WindowsAdapter.h"
#include "PackageManifest.h"

namespace unlock::components {
class PackageDeployment final {
public:
    static void requireEmbeddedComponents(const std::filesystem::path& path);
    explicit PackageDeployment(WindowsAdapter& adapter) : adapter_(adapter) {}
    [[nodiscard]] ProductVersion validatePackage(const SetupTransactionState& state) const;
    void validateInstalledFiles(const std::wstring& installedVersion) const;
    [[nodiscard]] std::vector<PackageFile> installedPackageFiles() const;
    [[nodiscard]] std::filesystem::path transactionDirectory(const SetupTransactionState& state) const;
    void stagePackage(SetupTransactionState& state) const;
    void stageContinuation(SetupTransactionState& state) const;
    void applyStagedPackage(const SetupTransactionState& state) const;
    [[nodiscard]] bool desktopPackagePresent() const;
    [[nodiscard]] bool desktopArtifactsPresent() const;
    void removeDesktopPackage() const;
    void validatePackageFile(const PackageFile& entry, const std::filesystem::path& path, ProductVersion version) const;
private:
    void preparePackageParent(const std::filesystem::path& root, const std::filesystem::path& relative) const;
    void copyNativeExecutable(const std::filesystem::path& source, const std::filesystem::path& target) const;
    WindowsAdapter& adapter_;
};
}
