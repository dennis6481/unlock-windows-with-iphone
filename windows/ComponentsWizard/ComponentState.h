// Created by Rui MA on 28 Sep 2026

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace unlock::components {

enum class WizardPhase : std::uint32_t {
    none = 0,
    installing = 1,
    installed = 2,
    uninstallPendingReboot = 3,
    cleaningUp = 4,
    recoveryRequired = 5,
};

enum class WizardAction {
    install,
    uninstall,
    cleanup,
    recover,
    resetStaleState,
    blocked,
};

struct WizardState final {
    std::uint32_t schemaVersion = 3;
    WizardPhase phase = WizardPhase::none;
    std::wstring transactionId;
    std::wstring wizardPath;
    std::wstring createdAtUtc;
    std::wstring lastError;
    bool credentialCleanupConfirmed = false;
};

struct ComponentSnapshot final {
    bool statePresent = false;
    bool stateValid = false;
    WizardPhase statePhase = WizardPhase::none;
    std::wstring stateError;
    std::wstring stateLastError;

    bool credentialProviderDllPresent = false;
    bool credentialProviderRegistered = false;
    bool credentialProviderClsidRegistered = false;
    bool savedCredentialServiceExePresent = false;
    bool savedCredentialServiceRegistered = false;
    bool savedCredentialServiceMatchesInstallation = false;
    bool savedCredentialServiceRunning = false;
    bool continuationTaskPresent = false;

    bool observationValid = true;
    std::wstring observationError;

    [[nodiscard]] bool hasKnownArtifacts() const noexcept;
    [[nodiscard]] bool hasAnyArtifacts() const noexcept;
    [[nodiscard]] bool isCompleteInstallation() const noexcept;
};

struct RecoveryPlan final {
    WizardAction action = WizardAction::blocked;
    std::wstring title;
    std::wstring explanation;
    bool safeToAutomate = false;
};

[[nodiscard]] RecoveryPlan determineRecoveryPlan(const ComponentSnapshot& snapshot);
[[nodiscard]] const wchar_t* wizardPhaseName(WizardPhase phase) noexcept;
[[nodiscard]] const wchar_t* wizardActionName(WizardAction action) noexcept;

} // namespace unlock::components
