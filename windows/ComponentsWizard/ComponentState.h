// Created by Rui MA on 28 Sep 2026

#pragma once

#include <cstdint>
#include <string>

namespace unlock::components {

inline constexpr std::uint32_t kWizardStateSchemaVersion = 3;

enum class WizardPhase : std::uint32_t {
    none = 0,
    installing = 1,
    installed = 2,
    uninstallPendingReboot = 3,
    cleaningUp = 4,
    recoveryRequired = 5,
    updatePendingReboot = 6,
    updating = 7,
    installPendingReboot = 8,
};

enum class WizardAction {
    install,
    update,
    uninstall,
    blocked,
};

struct WizardState final {
    std::uint32_t schemaVersion = kWizardStateSchemaVersion;
    WizardPhase phase = WizardPhase::none;
    std::wstring transactionId;
    std::wstring wizardPath;
    std::wstring createdAtUtc;
    std::wstring lastError;
    std::wstring targetSid;
    bool credentialCleanupConfirmed = false;
};

struct ComponentSnapshot final {
    bool statePresent = false;
    bool stateValid = false;
    std::wstring stateError;

    bool credentialProviderDllPresent = false;
    bool credentialProviderRegistered = false;
    bool credentialProviderClsidRegistered = false;
    bool savedCredentialServiceExePresent = false;
    bool savedCredentialServiceRegistered = false;
    bool savedCredentialServiceMatchesInstallation = false;
    bool savedCredentialServiceRunning = false;
    bool continuationTaskPresent = false;
    bool userStartupPresent = false;
    bool toolsPresent = false;
    bool desktopArtifactsPresent = false;
    bool shortcutsPresent = false;
    bool trayRunning = false;
    std::wstring targetSid;

    bool observationValid = true;
    std::wstring observationError;

    [[nodiscard]] bool hasAnyArtifacts() const noexcept;
    [[nodiscard]] bool isFullInstallation() const noexcept;
};

struct CompletionRecord final {
    std::wstring transactionId;
    std::wstring targetSid;
    std::wstring message;
    std::wstring log;
    bool finished = false;
    bool success = false;
};

enum class MaintenanceAction { install, maintain, restart, resume, blocked };

struct MaintenancePlan final {
    MaintenanceAction action = MaintenanceAction::blocked;
    std::wstring explanation;
    bool pending = false;
    bool attentionRequired = false;
};

[[nodiscard]] MaintenancePlan determineMaintenancePlan(const ComponentSnapshot& snapshot,
    const WizardState* state, const CompletionRecord* completion, bool rebootRequired);

} // namespace unlock::components
