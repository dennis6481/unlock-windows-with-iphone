// Created by Rui MA on 28 Sep 2026
// Windows mechanisms only: native components, identity, paths and desktop integration.

#pragma once
#include "ComponentState.h"
#include "../ComponentFiles.h"
#include <Windows.h>
#include <exception>
#include <filesystem>
#include <functional>

namespace unlock::components {
class ComponentError final : public std::exception {
public:
    explicit ComponentError(std::wstring message);
    [[nodiscard]] const wchar_t* wideWhat() const noexcept;
    [[nodiscard]] const char* what() const noexcept override;
private:
    std::wstring message_;
    std::string narrow_;
};
struct EnvironmentStatus final {
    bool elevated = false;
    Architecture nativeArchitecture = Architecture::unknown;
    Architecture wizardArchitecture = Architecture::unknown;
};
[[nodiscard]] const wchar_t* architectureName(Architecture architecture) noexcept;
class WindowsAdapter final {
public:
    explicit WindowsAdapter(std::filesystem::path wizardPath);
    [[nodiscard]] const std::filesystem::path& wizardPath() const noexcept;
    [[nodiscard]] std::filesystem::path credentialProviderTarget() const;
    [[nodiscard]] std::filesystem::path savedCredentialServiceTarget() const;
    [[nodiscard]] std::filesystem::path componentTarget(const ComponentFile& component) const;
    [[nodiscard]] ProductVersion binaryVersion(const std::filesystem::path& file) const;
    [[nodiscard]] Architecture executableArchitecture(const std::filesystem::path& file) const;
    void ensureProtectedDirectory(const std::filesystem::path& path, bool create) const;
    void ensureDeploymentDirectories() const;
    [[nodiscard]] EnvironmentStatus environment() const;
    void assertSupportedAdministratorEnvironment() const;
    void setOperationLog(std::function<void(const std::wstring&)> listener);
    void logOperation(const std::wstring& message) const;
    [[nodiscard]] ComponentSnapshot inspectSystemComponents() const;
    void configureSavedCredentialServiceForUpdate(bool suspend) const;
    void deleteFileIfPresent(const std::filesystem::path& target) const;
    void createCredentialProviderRegistration(const std::filesystem::path& target) const;
    void removeCredentialProviderRegistration() const;
    void createSavedCredentialService() const;
    void removeSavedCredentialService() const;
    void clearSavedCredential() const;
    [[nodiscard]] std::wstring consoleUserSid() const;
    [[nodiscard]] std::wstring currentUserSid() const;
    [[nodiscard]] bool isSystem() const;
    void registerUserStartup(const std::wstring& targetSid) const;
    void stopTray(const std::wstring& targetSid) const;
    void removeDesktopIntegration(const std::wstring& targetSid) const;
    void installDesktopIntegration(const std::wstring& targetSid, const std::wstring& version) const;
    void registerApplicationUninstall(const std::filesystem::path& executable, const std::wstring& version) const;
    [[nodiscard]] bool userStartupPresent(const std::wstring& targetSid) const;
    [[nodiscard]] bool trayRunning(const std::wstring& targetSid) const;
    void startTray(const std::wstring& targetSid, bool setup) const;
    void removeProductData(const std::wstring& targetSid) const;
    void restartWindows() const;
private:
    void withUserHive(const std::wstring& sid, const std::function<void(HKEY)>& operation) const;
    void removeUserStartup(const std::wstring& sid) const;
    std::filesystem::path wizardPath_;
    std::function<void(const std::wstring&)> operationLog_;
};
}
