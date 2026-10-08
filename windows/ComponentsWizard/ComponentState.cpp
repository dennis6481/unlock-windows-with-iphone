// Created by Rui MA on 28 Sep 2026

#include "ComponentState.h"

namespace unlock::components {

bool ComponentSnapshot::hasAnyArtifacts() const noexcept {
    return credentialProviderDllPresent || credentialProviderRegistered ||
        credentialProviderClsidRegistered || savedCredentialServiceExePresent ||
        savedCredentialServiceRegistered || continuationTaskPresent ||
        userStartupPresent || desktopArtifactsPresent || applicationUninstallPresent;
}

bool ComponentSnapshot::isFullInstallation() const noexcept {
    return observationValid && stateValid && credentialProviderDllPresent &&
        credentialProviderRegistered && credentialProviderClsidRegistered &&
        savedCredentialServiceExePresent && savedCredentialServiceRegistered &&
        savedCredentialServiceMatchesInstallation && savedCredentialServiceRunning &&
        userStartupPresent && toolsPresent && versionsMatch && !targetSid.empty();
}

MaintenancePlan determineMaintenancePlan(const ComponentSnapshot& snapshot,
    const WizardState* state, const CompletionRecord* completion, bool rebootRequired) {
    if (!snapshot.observationValid)
        return {MaintenanceAction::blocked, snapshot.observationError};
    if (snapshot.statePresent && (!snapshot.stateValid || !state))
        return {MaintenanceAction::blocked, snapshot.stateError.empty()
            ? L"The installation record is invalid." : snapshot.stateError};
    if (!state)
        return snapshot.hasAnyArtifacts()
            ? MaintenancePlan{MaintenanceAction::blocked, L"Unregistered component artifacts exist. No changes were made."}
            : MaintenancePlan{MaintenanceAction::install};
    if (state->schemaVersion != kWizardStateSchemaVersion || state->targetSid.empty() ||
        !isKnownPhase(static_cast<std::uint32_t>(state->phase)) || state->phase == WizardPhase::none)
        return {MaintenanceAction::blocked, L"This installation record is unsupported or has no startup account. Uninstall an older installation with its original installer first. No migration will run."};
    const bool unfinishedHandoff = completion && completion->transactionId == state->transactionId && !completion->finished;
    const bool pending = unfinishedHandoff || state->phase == WizardPhase::installPendingReboot ||
        state->phase == WizardPhase::updatePendingReboot || state->phase == WizardPhase::updating ||
        state->phase == WizardPhase::uninstallPendingReboot || state->phase == WizardPhase::cleaningUp ||
        state->phase == WizardPhase::preparing || state->phase == WizardPhase::finalizing;
    if (pending) {
        if (!rebootRequired && (state->phase == WizardPhase::preparing || state->phase == WizardPhase::finalizing))
            return {MaintenanceAction::resume, state->lastError.empty()
                ? L"Continue the registered preparation or finalization. No new operation may start."
                : state->lastError + L"\r\n\r\nFinalization is incomplete. Continue this transaction.", true, true};
        if (!state->lastError.empty())
            return {rebootRequired ? MaintenanceAction::restart : MaintenanceAction::resume,
                state->lastError + L"\r\n\r\nThe transaction is preserved. No other operation may start.", true, true};
        if (unfinishedHandoff && !rebootRequired && state->phase == WizardPhase::installed)
            return {MaintenanceAction::resume, L"Continue verification of the existing transaction. No new operation may start.", true, true};
        return {MaintenanceAction::restart, L"A component operation is pending. Restart Windows to complete it. No other operation can start.", true};
    }
    if (state->phase != WizardPhase::installed)
        return {MaintenanceAction::blocked, L"An interrupted transaction is preserved for diagnosis. No automatic removal or rollback will be performed.\r\n" + state->lastError};
    if (!snapshot.isFullInstallation() || snapshot.continuationTaskPresent)
        return {MaintenanceAction::blocked, L"The current complete installation could not be verified. Older or incomplete installations are not supported. Uninstall an older installation with its original installer first. No changes were made.\r\n" + snapshot.versionError};
    return {MaintenanceAction::maintain};
}

} // namespace unlock::components
