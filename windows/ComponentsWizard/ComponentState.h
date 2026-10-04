// Created by Rui MA on 28 Sep 2026

#pragma once

#include <cstdint>
#include <string>
#include "../ProductVersion.h"
#include "SetupContract.h"

namespace unlock::components {

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
    SetupOperation operation = SetupOperation::install;
    std::wstring sourcePath;
    std::wstring installedVersion;
    std::wstring packageVersion;
    bool payloadReady = false;
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
    bool applicationUninstallPresent = false;
    bool trayRunning = false;
    bool versionsMatch = false;
    std::wstring versionError;
    std::wstring targetSid;

    bool observationValid = true;
    std::wstring observationError;

    [[nodiscard]] bool hasAnyArtifacts() const noexcept;
    [[nodiscard]] bool isFullInstallation() const noexcept;
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
