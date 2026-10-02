// Created by Rui MA on 28 Sep 2026

#pragma once

#include "ComponentState.h"

#include <exception>
#include <filesystem>
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
    [[nodiscard]] std::filesystem::path credentialProviderSource() const;
    [[nodiscard]] std::filesystem::path savedCredentialServiceSource() const;
    [[nodiscard]] std::filesystem::path credentialProviderTarget() const;
    [[nodiscard]] std::filesystem::path savedCredentialServiceTarget() const;

    [[nodiscard]] EnvironmentStatus environment() const;
    void assertSupportedAdministratorEnvironment() const;

    [[nodiscard]] ComponentSnapshot inspect() const;
    [[nodiscard]] std::optional<WizardState> readState() const;
    void writeState(const WizardState& state) const;
    void clearState() const;

    void copyNativeBinary(const std::filesystem::path& source, const std::filesystem::path& target,
        bool replace = false) const;
    [[nodiscard]] std::filesystem::path updateDirectory(const WizardState& state) const;
    void stageUpdate(WizardState& state) const;
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
    void removeContinuationTask() const;

    void restartWindows() const;

private:
    std::filesystem::path wizardPath_;
};

} // namespace unlock::components
