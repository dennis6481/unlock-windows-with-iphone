// Created by Rui MA on 28 Sep 2026

#include "ComponentState.h"

namespace unlock::components {

bool ComponentSnapshot::hasKnownArtifacts() const noexcept {
    return credentialProviderDllPresent ||
        credentialProviderRegistered ||
        credentialProviderClsidRegistered ||
        savedCredentialServiceExePresent ||
        savedCredentialServiceRegistered ||
        continuationTaskPresent || userStartupPresent || desktopArtifactsPresent;
}

bool ComponentSnapshot::hasAnyArtifacts() const noexcept {
    return hasKnownArtifacts();
}

bool ComponentSnapshot::isCompleteInstallation() const noexcept {
    return credentialProviderDllPresent &&
        credentialProviderRegistered &&
        credentialProviderClsidRegistered &&
        savedCredentialServiceExePresent &&
        savedCredentialServiceRegistered &&
        savedCredentialServiceMatchesInstallation &&
        savedCredentialServiceRunning;
}

bool ComponentSnapshot::isFullInstallation() const noexcept {
    return observationValid && stateValid && isCompleteInstallation() && userStartupPresent && toolsPresent && shortcutsPresent && !targetSid.empty();
}

const wchar_t* wizardPhaseName(const WizardPhase phase) noexcept {
    switch (phase) {
        case WizardPhase::none:
            return L"None";
        case WizardPhase::installing:
            return L"Installing";
        case WizardPhase::installed:
            return L"Installed";
        case WizardPhase::uninstallPendingReboot:
            return L"UninstallPendingReboot";
        case WizardPhase::cleaningUp:
            return L"CleaningUp";
        case WizardPhase::recoveryRequired:
            return L"RecoveryRequired";
        case WizardPhase::updatePendingReboot:
            return L"UpdatePendingReboot";
        case WizardPhase::updating:
            return L"Updating";
        case WizardPhase::installPendingReboot:
            return L"InstallPendingReboot";
        default:
            return L"Unknown";
    }
}

const wchar_t* wizardActionName(const WizardAction action) noexcept {
    switch (action) {
        case WizardAction::install:
            return L"Install";
        case WizardAction::update:
            return L"Update";
        case WizardAction::completeUpdate:
            return L"CompleteUpdate";
        case WizardAction::uninstall:
            return L"Uninstall";
        case WizardAction::cleanup:
            return L"Cleanup";
        case WizardAction::blocked:
            return L"Blocked";
        default:
            return L"Unknown";
    }
}

RecoveryPlan determineRecoveryPlan(const ComponentSnapshot& snapshot) {
    if (!snapshot.observationValid)
        return {WizardAction::blocked, L"Cannot read component status", snapshot.observationError, false};
    if (!snapshot.statePresent)
        return snapshot.hasAnyArtifacts()
            ? RecoveryPlan{WizardAction::blocked, L"Unregistered artifacts", L"No changes will be made automatically.", false}
            : RecoveryPlan{WizardAction::install, L"Install", L"Install phone connectivity and lock-screen unlock.", true};
    if (!snapshot.stateValid)
        return {WizardAction::blocked, L"Invalid transaction", snapshot.stateError, false};
    switch (snapshot.statePhase) {
        case WizardPhase::installed:
            if (snapshot.isCompleteInstallation() && !snapshot.continuationTaskPresent)
                return {WizardAction::update, L"Installed", L"Update preserves credentials and phone registration.", true};
            return {WizardAction::blocked, L"Installation needs attention", L"State preserved; no destructive recovery.", false};
        case WizardPhase::installPendingReboot:
            return {WizardAction::blocked, L"Restart required", L"Restart to verify installation.", false};
        case WizardPhase::updatePendingReboot:
        case WizardPhase::updating:
            return {WizardAction::completeUpdate, L"Pending update",
                snapshot.updateRebootRequired ? L"Restart before replacing files." : L"Continue the registered update.", true};
        case WizardPhase::uninstallPendingReboot:
        case WizardPhase::cleaningUp:
            return {WizardAction::cleanup, L"Pending removal", L"Continue only the registered removal.", true};
        default:
            return {WizardAction::blocked, L"Interrupted operation", L"State preserved for diagnosis. No automatic cleanup.", false};
    }
}

} // namespace unlock::components
