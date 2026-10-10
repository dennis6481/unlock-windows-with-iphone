// Created by Rui MA on 28 Sep 2026
// Owns maintenance inspection, operation sequencing and continuation/result publication.

#include "SetupTransaction.h"
#include "SetupPlatform.h"
#include <Windows.h>
#include <utility>

namespace unlock::components {
ComponentSnapshot SetupTransaction::inspect() const {
    auto snapshot = adapter_.inspectSystemComponents();
    std::optional<SetupTransactionState> transaction;
    std::optional<InstalledProduct> installed;
    try {
        transaction = store_.readTransaction();
        if (!transaction) installed = store_.readInstalledProduct();
        snapshot.statePresent = transaction.has_value() || installed.has_value();
        snapshot.stateValid = snapshot.statePresent;
        if (transaction) snapshot.targetSid = transaction->targetSid;
        else if (installed) snapshot.targetSid = installed->targetSid;
    } catch (const ComponentError& error) {
        snapshot.statePresent = true;
        snapshot.stateValid = false;
        snapshot.stateError = error.wideWhat();
    }
    try {
        snapshot.continuationTaskPresent = finalization_.continuationTaskExists();
        snapshot.userStartupPresent = adapter_.userStartupPresent(snapshot.targetSid);
        snapshot.desktopPackagePresent = package_.desktopPackagePresent();
        snapshot.desktopArtifactsPresent = package_.desktopArtifactsPresent();
        snapshot.trayRunning = adapter_.trayRunning(snapshot.targetSid);
        const auto version = transaction ? transaction->installedVersion
            : installed ? installed->installedVersion : std::wstring{};
        if (!version.empty() && snapshot.desktopPackagePresent &&
            snapshot.credentialProviderDllPresent && snapshot.savedCredentialServiceExePresent) {
            try {
                package_.validateInstalledFiles(version);
                snapshot.versionsMatch = true;
            } catch (const ComponentError& error) {
                snapshot.versionError = error.wideWhat();
            }
        }
        snapshot.continuationTaskPresent = snapshot.continuationTaskPresent || finalization_.finalizationTaskExists();
    } catch (const ComponentError& error) {
        snapshot.observationValid = false;
        snapshot.observationError = error.wideWhat();
    }
    return snapshot;
}
MaintenancePlan SetupTransaction::maintenancePlan() const {
    const auto snapshot = inspect();
    const auto transaction = store_.readTransaction();
    const auto installed = transaction ? std::nullopt : store_.readInstalledProduct();
    const auto completion = store_.readCompletion();
    return determineMaintenancePlan(snapshot, installed ? &*installed : nullptr,
        transaction ? &*transaction : nullptr, completion ? &*completion : nullptr,
        store_.transactionRebootRequired());
}
int SetupTransaction::completeSystemOperation(const SetupTransactionState& state) {
    CompletionRecord record{state.transactionId, state.targetSid, L"Completing operation after restart...", L"", false, false};
    const auto previous = store_.readCompletion();
    if (previous && previous->transactionId == state.transactionId) record.log = previous->log;
    store_.writeCompletion(record);
    try {
        const auto result = continueOperation([&](int, const std::wstring& message) {
            record.log += message + L"\r\n"; store_.writeCompletion(record);
        });
        adapter_.setOperationLog({});
        record.message = result.message;
        record.success = result.success && !result.rebootRequired && !result.finalizationPending;
        if (result.finalizationPending) {
            record.finished = false; store_.writeCompletion(record);
            const auto current = store_.readTransaction();
            if (!current) throw ComponentError(L"Finalization transaction disappeared.");
            finalization_.startFinalization(*current);
            return 0;
        }
        record.finished = true;
        store_.writeCompletion(record);
        return record.success ? 0 : ERROR_INSTALL_FAILURE;
    } catch (const std::exception& error) {
        adapter_.setOperationLog({});
        record.message = setupErrorText(error); record.finished = true; record.success = false;
        store_.writeCompletion(record); return ERROR_INSTALL_FAILURE;
    }
}
OperationResult SetupTransaction::continueOperation(const ProgressCallback& progress) {
    const auto state = store_.readTransaction();
    if (!state) {
        if (store_.readInstalledProduct() && inspect().isFullInstallation())
            return {true, false, L"Completed installation verified after interrupted result handoff."};
        return failure(L"No registered transaction is pending.");
    }
    switch (state->phase) {
        case WizardPhase::installed:
            if (inspect().isFullInstallation())
                return {true, false, L"Completed installation verified after interrupted result handoff."};
            return failure(L"Installed component verification failed.");
        case WizardPhase::installPendingReboot: return completeInstall(progress);
        case WizardPhase::updatePendingReboot:
        case WizardPhase::updating: return completeUpdate(progress);
        case WizardPhase::uninstallPendingReboot:
        case WizardPhase::cleaningUp: return completeUninstall(progress);
        case WizardPhase::preparing: return continuePreparation(progress);
        case WizardPhase::finalizing: return {true, false, L"Finalization is pending.", true};
        default: return failure(L"This transaction is not eligible for reboot continuation.");
    }
}
SetupTransactionState SetupTransaction::newState(WizardPhase phase, std::wstring targetSid) const {
    SetupTransactionState state;
    state.phase = phase;
    state.transactionId = std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(GetCurrentProcessId());
    state.sourcePath = adapter_.wizardPath().wstring();
    state.wizardPath = (package_.transactionDirectory(state) / kInstallerFile).wstring();
    state.packageVersion = adapter_.binaryVersion(adapter_.wizardPath()).text();
    FILETIME time{}; GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER value{}; value.LowPart = time.dwLowDateTime; value.HighPart = time.dwHighDateTime;
    state.createdAtUtc = std::to_wstring(value.QuadPart);
    state.targetSid = std::move(targetSid);
    return state;
}
OperationResult SetupTransaction::failure(const std::wstring& message) const {
    return {false, false, message};
}
void SetupTransaction::report(const ProgressCallback& progress, int percent, const std::wstring& message) const {
    if (progress) progress(percent, message);
}
OperationResult SetupTransaction::prepare(SetupTransactionState& state, const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    bool continuationReady = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (!state.payloadReady) {
            report(progress, 10, L"Stage this transaction in protected ProgramData.");
            if (state.operation == SetupOperation::uninstall) package_.stageContinuation(state);
            else package_.stagePackage(state);
            state.payloadReady = true; store_.writeTransaction(state);
        }
        adapter_.registerApplicationUninstall(state.wizardPath, state.installedVersion.empty() ? state.packageVersion : state.installedVersion);
        if (state.operation == SetupOperation::uninstall && !state.credentialCleanupConfirmed) {
            adapter_.clearSavedCredential(); state.credentialCleanupConfirmed = true; store_.writeTransaction(state);
        }
        // A volatile guard is released only by a real reboot, never by a successful API call.
        store_.markTransactionRequiresReboot();
        if (state.operation == SetupOperation::install) {
            report(progress, 35, L"Deploy system components to System32 and desktop tools to Program Files.");
            if (inspect().savedCredentialServiceRegistered) adapter_.configureSavedCredentialServiceForUpdate(true);
            package_.applyStagedPackage(state);
            if (inspect().savedCredentialServiceRegistered) adapter_.configureSavedCredentialServiceForUpdate(false);
            else adapter_.createSavedCredentialService();
            adapter_.createCredentialProviderRegistration(adapter_.credentialProviderTarget());
            state.phase = WizardPhase::installPendingReboot;
        } else {
            report(progress, 50, L"Remove Run startup and wait for normal main application and operation exit.");
            adapter_.stopTray(state.targetSid); adapter_.removeCredentialProviderRegistration();
            if (state.operation == SetupOperation::uninstall) {
                adapter_.removeDesktopIntegration(state.targetSid); adapter_.removeSavedCredentialService();
                state.phase = WizardPhase::uninstallPendingReboot;
            } else {
                adapter_.configureSavedCredentialServiceForUpdate(true);
                state.phase = WizardPhase::updatePendingReboot;
            }
        }
        state.lastError.clear();
        store_.writeCompletion({state.transactionId, state.targetSid, L"Waiting for restart.", L"", false, false});
        finalization_.registerContinuationTask(state);
        continuationReady = true;
        store_.writeTransaction(state);
        report(progress, 100, L"Preparation complete. Restart to continue and verify finalization.");
        return {true, true, state.operation == SetupOperation::uninstall
            ? L"Saved password deletion confirmed. Restart to remove programs, phone enrollment and computer identity."
            : L"Restart to finish. Updates and reinstalls preserve credentials and phone enrollment."};
    } catch (const std::exception& error) {
        // Keep ownership and diagnostics on failure; only this transaction may continue.
        if (!continuationReady) state.phase = WizardPhase::preparing;
        std::wstring message = setupErrorText(error); state.lastError = message;
        try { store_.writeTransaction(state); }
        catch (const std::exception& more) { message += L"\r\nState write failed: " + setupErrorText(more); }
        return failure(message);
    }
}
OperationResult SetupTransaction::install(const ProgressCallback& progress) {
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto plan = maintenancePlan();
        if (plan.action != MaintenanceAction::install)
            return failure(L"Installation requires empty, readable component state.");
        auto state = newState(WizardPhase::preparing, adapter_.consoleUserSid());
        static_cast<void>(package_.validatePackage(state)); store_.writeTransaction(state);
        return prepare(state, progress);
    } catch (const std::exception& error) { return failure(setupErrorText(error)); }
}
OperationResult SetupTransaction::beginUpdate(const ProgressCallback& progress) {
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto plan = maintenancePlan();
        const auto old = plan.action == MaintenanceAction::maintain ? store_.readInstalledProduct() : std::nullopt;
        if (!old || plan.action != MaintenanceAction::maintain)
            return failure(L"Update requires a verified installation without a pending transaction.");
        package_.validateInstalledFiles(old->installedVersion);
        auto state = newState(WizardPhase::preparing, old->targetSid);
        state.operation = SetupOperation::update; state.installedVersion = old->installedVersion;
        const auto incoming = package_.validatePackage(state);
        if (packageAction(incoming, *parseProductVersion(old->installedVersion)) == PackageAction::rejectDowngrade)
            return failure(L"Downgrades are not supported. No changes were made.");
        store_.writeTransaction(state);
        return prepare(state, progress);
    } catch (const std::exception& error) { return failure(setupErrorText(error)); }
}
OperationResult SetupTransaction::beginUninstall(const ProgressCallback& progress) {
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto plan = maintenancePlan();
        const auto old = plan.action == MaintenanceAction::maintain ? store_.readInstalledProduct() : std::nullopt;
        if (!old || plan.action != MaintenanceAction::maintain)
            return failure(L"Uninstall requires a verified installation without a pending transaction.");
        auto state = newState(WizardPhase::preparing, old->targetSid);
        state.operation = SetupOperation::uninstall; state.installedVersion = old->installedVersion;
        state.sourcePath = old->wizardPath;
        state.packageVersion = old->installedVersion;
        store_.writeTransaction(state);
        return prepare(state, progress);
    } catch (const std::exception& error) { return failure(setupErrorText(error)); }
}
OperationResult SetupTransaction::continuePreparation(const ProgressCallback& progress) {
    auto state = store_.readTransaction();
    if (!state || state->phase != WizardPhase::preparing) return failure(L"No preparation is pending.");
    if (store_.transactionRebootRequired()) return {true, true, L"Restart before continuing this transaction."};
    return prepare(*state, progress);
}
void SetupTransaction::finishDeployment(SetupTransactionState& state) const {
    state.installedVersion = state.packageVersion; store_.writeTransaction(state);
    adapter_.installDesktopIntegration(state.targetSid, state.installedVersion); package_.validateInstalledFiles(state.installedVersion);
    if (!inspect().isFullInstallation()) throw ComponentError(L"Full installation verification failed.");
    state.phase = WizardPhase::finalizing; state.lastError.clear(); store_.writeTransaction(state);
}
OperationResult SetupTransaction::completeInstall(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    auto state = store_.readTransaction();
    if (!state || state->phase != WizardPhase::installPendingReboot) return failure(L"No installation is pending.");
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (store_.transactionRebootRequired()) return {true, true, L"Restart is still required."};
        finishDeployment(*state);
        return {true, false, L"Deployment verified; releasing transaction resources.", true};
    } catch (const std::exception& error) {
        state->lastError = setupErrorText(error); store_.writeTransaction(*state); return failure(state->lastError);
    }
}
OperationResult SetupTransaction::completeUpdate(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    auto state = store_.readTransaction();
    if (!state || (state->phase != WizardPhase::updatePendingReboot && state->phase != WizardPhase::updating))
        return failure(L"No update is pending.");
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (store_.transactionRebootRequired()) return {true, true, L"Restart is still required."};
        state->phase = WizardPhase::updating; store_.writeTransaction(*state);
        adapter_.stopTray(state->targetSid); adapter_.removeCredentialProviderRegistration();
        adapter_.configureSavedCredentialServiceForUpdate(true);
        report(progress, 40, L"Replace and verify files from the package dependency manifest.");
        package_.applyStagedPackage(*state); adapter_.configureSavedCredentialServiceForUpdate(false);
        adapter_.createCredentialProviderRegistration(adapter_.credentialProviderTarget());
        finishDeployment(*state);
        return {true, false, L"Update verified; credentials preserved. Releasing transaction resources.", true};
    } catch (const std::exception& error) {
        state->lastError = setupErrorText(error); store_.writeTransaction(*state); return failure(state->lastError);
    }
}
OperationResult SetupTransaction::completeUninstall(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    auto state = store_.readTransaction();
    if (!state || (state->phase != WizardPhase::uninstallPendingReboot && state->phase != WizardPhase::cleaningUp))
        return failure(L"No uninstall is pending.");
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (store_.transactionRebootRequired()) return {true, true, L"Restart is still required."};
        if (!state->credentialCleanupConfirmed) throw ComponentError(L"Saved credential cleanup is not confirmed.");
        state->phase = WizardPhase::cleaningUp; store_.writeTransaction(*state);
        adapter_.stopTray(state->targetSid); adapter_.removeDesktopIntegration(state->targetSid);
        adapter_.removeCredentialProviderRegistration(); adapter_.removeSavedCredentialService();
        package_.removeDesktopPackage();
        adapter_.deleteFileIfPresent(adapter_.credentialProviderTarget());
        adapter_.deleteFileIfPresent(adapter_.savedCredentialServiceTarget());
        adapter_.removeProductData(state->targetSid);
        for (const auto& entry : packageFiles()) {
            if (entry.desktopTool) continue;
            auto temporary = adapter_.componentTarget(entry.component()); temporary += L".update";
            adapter_.deleteFileIfPresent(temporary);
        }
        auto remaining = inspect();
        remaining.continuationTaskPresent = remaining.applicationUninstallPresent = false;
        if (!remaining.observationValid || remaining.hasAnyArtifacts()) throw ComponentError(L"Removal verification found remaining components.");
        state->phase = WizardPhase::finalizing; state->lastError.clear(); store_.writeTransaction(*state);
        return {true, false, L"Components and Windows enrollment removed; finalization remains pending.", true};
    } catch (const std::exception& error) {
        state->lastError = setupErrorText(error); store_.writeTransaction(*state); return failure(state->lastError);
    }
}
}
