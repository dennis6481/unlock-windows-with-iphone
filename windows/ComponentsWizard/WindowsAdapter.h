// Created by Rui MA on 28 Sep 2026

#pragma once

#include "ComponentState.h"
#include "../ComponentFiles.h"

#include <exception>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

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

enum class Architecture {
    x64,
    arm64,
    unknown,
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
    [[nodiscard]] ProductVersion validatePackage(const WizardState& state) const;
    void validateInstalledVersions(const WizardState& state) const;
    void ensureDeploymentDirectories() const;
    void removeProductData(const WizardState& state) const;
    void startFinalization(const WizardState& state) const;
    void registerResultTask(const WizardState& state) const;
    [[nodiscard]] bool finalizationTaskExists() const;
    void retryFinalization(const WizardState& state) const;
    void runContinuation(const WizardState& state) const;
    void registerFinalizationUninstall(const WizardState& state) const;

    [[nodiscard]] EnvironmentStatus environment() const;
    void assertSupportedAdministratorEnvironment() const;
    void setOperationLog(std::function<void(const std::wstring&)> listener);
    void logOperation(const std::wstring& message) const;

    [[nodiscard]] ComponentSnapshot inspect() const;
    [[nodiscard]] std::optional<WizardState> readState() const;
    void writeState(const WizardState& state) const;

    void copyNativeBinary(const std::filesystem::path& source, const std::filesystem::path& target,
        bool replace = false) const;
    [[nodiscard]] std::filesystem::path updateDirectory(const WizardState& state) const;
    void stageUpdate(WizardState& state) const;
    void stageContinuation(WizardState& state) const;
    void applyStagedUpdate(const WizardState& state) const;
    void configureSavedCredentialServiceForUpdate(bool suspend) const;
    [[nodiscard]] bool updateRebootRequired() const;
    void markUpdateRequiresReboot() const;
    void deleteBinaryIfPresent(const std::filesystem::path& target) const;

    void createCredentialProviderRegistration(const std::filesystem::path& target) const;
    void removeCredentialProviderRegistration() const;
    void createSavedCredentialService() const;
    void removeSavedCredentialService() const;
    void clearSavedCredential() const;

    [[nodiscard]] bool continuationTaskExists() const;
    void registerContinuationTask(const WizardState& state) const;

    [[nodiscard]] std::wstring consoleUserSid() const;
    [[nodiscard]] bool isSystem() const;
    void registerUserStartup(const WizardState& state) const;
    void stopTray(const WizardState& state) const;
    void removeDesktopIntegration() const;
    void installDesktopIntegration(const WizardState& state) const;
    void registerApplicationUninstall(const std::filesystem::path& executable) const;
    void removeTools() const;
    [[nodiscard]] bool userStartupPresent() const;
    [[nodiscard]] bool toolsPresent() const;
    [[nodiscard]] bool desktopArtifactsPresent() const;
    [[nodiscard]] bool trayRunning() const;
    void writeCompletion(const CompletionRecord& result) const;
    [[nodiscard]] std::optional<CompletionRecord> readCompletion() const;
    void acknowledgeCompletion(const std::wstring& transactionId) const;
    void startTrayForCompletedOperation(const std::wstring& transactionId) const;

    void restartWindows() const;

private:
    std::filesystem::path wizardPath_;
    std::function<void(const std::wstring&)> operationLog_;
};

} // namespace unlock::components
