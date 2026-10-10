// Created by Rui MA on 28 Sep 2026
// Pure maintenance decisions: an active transaction takes precedence over an installation.

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
        userStartupPresent && desktopPackagePresent && versionsMatch && !targetSid.empty();
}
MaintenancePlan determineMaintenancePlan(const ComponentSnapshot& snapshot,
    const InstalledProduct* installed, const SetupTransactionState* transaction,
    const CompletionRecord* completion, bool rebootRequired) {
    if (!snapshot.observationValid)
        return {MaintenanceAction::blocked, snapshot.observationError};
    if (snapshot.statePresent && (!snapshot.stateValid || (!installed && !transaction)))
        return {MaintenanceAction::blocked, snapshot.stateError.empty()
            ? L"The installation record is invalid." : snapshot.stateError};
    if (!installed && !transaction)
        return snapshot.hasAnyArtifacts()
            ? MaintenancePlan{MaintenanceAction::blocked, L"Unregistered component artifacts exist. No changes were made."}
            : MaintenancePlan{MaintenanceAction::install};
    const auto schema = transaction ? transaction->schemaVersion : installed->schemaVersion;
    const auto& sid = transaction ? transaction->targetSid : installed->targetSid;
    if (schema != kWizardStateSchemaVersion || sid.empty() ||
        (transaction && (!isKnownPhase(static_cast<std::uint32_t>(transaction->phase)) ||
            transaction->phase == WizardPhase::none)))
        return {MaintenanceAction::blocked, L"This installation record is unsupported or has no startup account. Uninstall an older installation with its original installer first. No migration will run."};
    const auto& operationId = transaction ? transaction->transactionId : installed->lastOperationId;
    const bool unfinishedHandoff = completion && completion->transactionId == operationId && !completion->finished;
    if (transaction) {
        const auto phase = transaction->phase;
        const bool pending = unfinishedHandoff || phase == WizardPhase::installPendingReboot ||
            phase == WizardPhase::updatePendingReboot || phase == WizardPhase::updating ||
            phase == WizardPhase::uninstallPendingReboot || phase == WizardPhase::cleaningUp ||
            phase == WizardPhase::preparing || phase == WizardPhase::finalizing;
        if (pending) {
            if (!rebootRequired && (phase == WizardPhase::preparing || phase == WizardPhase::finalizing))
                return {MaintenanceAction::resume, transaction->lastError.empty()
                    ? L"Continue the registered preparation or finalization. No new operation may start."
                    : transaction->lastError + L"\r\n\r\nFinalization is incomplete. Continue this transaction.", true, true};
            if (!transaction->lastError.empty())
                return {rebootRequired ? MaintenanceAction::restart : MaintenanceAction::resume,
                    transaction->lastError + L"\r\n\r\nThe transaction is preserved. No other operation may start.", true, true};
            if (unfinishedHandoff && !rebootRequired && phase == WizardPhase::installed)
                return {MaintenanceAction::resume, L"Continue verification of the existing transaction. No new operation may start.", true, true};
            return {MaintenanceAction::restart, L"A component operation is pending. Restart Windows to complete it. No other operation can start.", true};
        }
        if (phase != WizardPhase::installed)
            return {MaintenanceAction::blocked, L"An interrupted transaction is preserved for diagnosis. No automatic removal or rollback will be performed.\r\n" + transaction->lastError};
    } else if (unfinishedHandoff) {
        return {rebootRequired ? MaintenanceAction::restart : MaintenanceAction::resume,
            rebootRequired ? L"A component operation is pending. Restart Windows to complete it. No other operation can start."
                : L"Continue verification of the existing transaction. No new operation may start.", true, !rebootRequired};
    }
    if (!snapshot.isFullInstallation() || snapshot.continuationTaskPresent)
        return {MaintenanceAction::blocked, L"The current complete installation could not be verified. Older or incomplete installations are not supported. Uninstall an older installation with its original installer first. No changes were made.\r\n" + snapshot.versionError};
    return {MaintenanceAction::maintain};
}
}
