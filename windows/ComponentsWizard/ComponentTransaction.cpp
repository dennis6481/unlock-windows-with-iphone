// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE
#include "ComponentTransaction.h"
#include <Windows.h>
#include <utility>

namespace unlock::components {
ComponentTransaction::ComponentTransaction(WindowsAdapter& adapter) : adapter_(adapter) {}
WizardState ComponentTransaction::newState(WizardPhase phase, std::wstring targetSid) const {
    WizardState state;
    state.phase = phase;
    state.transactionId = std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(GetCurrentProcessId());
    state.sourcePath = adapter_.wizardPath().wstring();
    state.wizardPath = (adapter_.updateDirectory(state) / kInstallerFile).wstring();
    state.packageVersion = adapter_.binaryVersion(adapter_.wizardPath()).text();
    FILETIME time{}; GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER value{}; value.LowPart = time.dwLowDateTime; value.HighPart = time.dwHighDateTime;
    state.createdAtUtc = std::to_wstring(value.QuadPart);
    state.targetSid = std::move(targetSid);
    return state;
}
OperationResult ComponentTransaction::failure(const std::wstring& message, bool preserved) const {
    return {false, false, preserved, message};
}
void ComponentTransaction::report(const ProgressCallback& progress, int percent, const std::wstring& message) const {
    if (progress) progress(percent, message);
}
std::wstring ComponentTransaction::errorText(const std::exception& error) const {
    if (auto* component = dynamic_cast<const ComponentError*>(&error)) return component->wideWhat();
    std::string narrow(error.what()); return std::wstring(narrow.begin(), narrow.end());
}
OperationResult ComponentTransaction::prepare(WizardState& state, const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    bool continuationReady = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (!state.payloadReady) {
            report(progress, 10, L"Stage this transaction in protected ProgramData.");
            if (state.operation == SetupOperation::uninstall) adapter_.stageContinuation(state);
            else adapter_.stageUpdate(state);
            state.payloadReady = true; adapter_.writeState(state);
        }
        adapter_.registerApplicationUninstall(state.wizardPath);
        if (state.operation == SetupOperation::uninstall && !state.credentialCleanupConfirmed) {
            adapter_.clearSavedCredential(); state.credentialCleanupConfirmed = true; adapter_.writeState(state);
        }
        adapter_.markUpdateRequiresReboot();
        if (state.operation == SetupOperation::install) {
            report(progress, 35, L"Deploy system components to System32 and desktop tools to Program Files.");
            if (adapter_.inspect().savedCredentialServiceRegistered) adapter_.configureSavedCredentialServiceForUpdate(true);
            adapter_.applyStagedUpdate(state);
            if (adapter_.inspect().savedCredentialServiceRegistered) adapter_.configureSavedCredentialServiceForUpdate(false);
            else adapter_.createSavedCredentialService();
            adapter_.createCredentialProviderRegistration(adapter_.credentialProviderTarget());
            state.phase = WizardPhase::installPendingReboot;
        } else {
            report(progress, 50, L"Remove Run startup and wait for normal tray and pairing-tool exit.");
            adapter_.stopTray(state); adapter_.removeCredentialProviderRegistration();
            if (state.operation == SetupOperation::uninstall) {
                adapter_.removeDesktopIntegration(); adapter_.removeSavedCredentialService();
                state.phase = WizardPhase::uninstallPendingReboot;
            } else {
                adapter_.configureSavedCredentialServiceForUpdate(true);
                state.phase = WizardPhase::updatePendingReboot;
            }
        }
        state.lastError.clear();
        adapter_.writeCompletion({state.transactionId, state.targetSid, L"Waiting for restart.", L"", false, false});
        adapter_.registerContinuationTask(state);
        continuationReady = true;
        adapter_.writeState(state);
        report(progress, 100, L"Preparation complete. Restart to continue and verify finalization.");
        return {true, true, true, state.operation == SetupOperation::uninstall
            ? L"Saved password deletion confirmed. Restart to remove programs, phone enrollment and computer identity."
            : L"Restart to finish. Updates and reinstalls preserve credentials and phone enrollment."};
    } catch (const std::exception& error) {
        if (!continuationReady) state.phase = WizardPhase::preparing;
        std::wstring message = errorText(error); state.lastError = message;
        try { adapter_.writeState(state); }
        catch (const std::exception& more) { message += L"\r\nState write failed: " + errorText(more); }
        return failure(message, true);
    }
}
OperationResult ComponentTransaction::install(const ProgressCallback& progress) {
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto old = adapter_.readState(); const auto result = adapter_.readCompletion();
        if (determineMaintenancePlan(adapter_.inspect(), old ? &*old : nullptr,
                result ? &*result : nullptr, adapter_.updateRebootRequired()).action != MaintenanceAction::install)
            return failure(L"Installation requires empty, readable component state.", old.has_value());
        auto state = newState(WizardPhase::preparing, adapter_.consoleUserSid());
        adapter_.validatePackage(state); adapter_.writeState(state);
        return prepare(state, progress);
    } catch (const std::exception& error) { return failure(errorText(error), true); }
}
OperationResult ComponentTransaction::beginUpdate(const ProgressCallback& progress) {
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto old = adapter_.readState(); const auto result = adapter_.readCompletion();
        if (!old || determineMaintenancePlan(adapter_.inspect(), &*old, result ? &*result : nullptr,
                adapter_.updateRebootRequired()).action != MaintenanceAction::maintain)
            return failure(L"Update requires a verified installation without a pending transaction.", old.has_value());
        adapter_.validateInstalledVersions(*old);
        auto state = newState(WizardPhase::preparing, old->targetSid);
        state.operation = SetupOperation::update; state.installedVersion = old->installedVersion;
        const auto incoming = adapter_.validatePackage(state);
        if (packageAction(incoming, *parseProductVersion(old->installedVersion)) == PackageAction::rejectDowngrade)
            return failure(L"Downgrades are not supported. No changes were made.", true);
        adapter_.writeState(state);
        return prepare(state, progress);
    } catch (const std::exception& error) { return failure(errorText(error), true); }
}
OperationResult ComponentTransaction::beginUninstall(const ProgressCallback& progress) {
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto old = adapter_.readState(); const auto result = adapter_.readCompletion();
        if (!old || determineMaintenancePlan(adapter_.inspect(), &*old, result ? &*result : nullptr,
                adapter_.updateRebootRequired()).action != MaintenanceAction::maintain)
            return failure(L"Uninstall requires a verified installation without a pending transaction.", old.has_value());
        auto state = newState(WizardPhase::preparing, old->targetSid);
        state.operation = SetupOperation::uninstall; state.installedVersion = old->installedVersion;
        adapter_.writeState(state);
        return prepare(state, progress);
    } catch (const std::exception& error) { return failure(errorText(error), true); }
}
OperationResult ComponentTransaction::continuePreparation(const ProgressCallback& progress) {
    auto state = adapter_.readState();
    if (!state || state->phase != WizardPhase::preparing) return failure(L"No preparation is pending.", state.has_value());
    if (adapter_.updateRebootRequired()) return {true, true, true, L"Restart before continuing this transaction."};
    return prepare(*state, progress);
}
void ComponentTransaction::finishDeployment(WizardState& state) const {
    state.installedVersion = state.packageVersion; adapter_.writeState(state);
    adapter_.installDesktopIntegration(state); adapter_.validateInstalledVersions(state);
    if (!adapter_.inspect().isFullInstallation()) throw ComponentError(L"Full installation verification failed.");
    state.phase = WizardPhase::finalizing; state.lastError.clear(); adapter_.writeState(state);
}
OperationResult ComponentTransaction::completeInstall(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    auto state = adapter_.readState();
    if (!state || state->phase != WizardPhase::installPendingReboot) return failure(L"No installation is pending.", state.has_value());
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (adapter_.updateRebootRequired()) return {true, true, true, L"Restart is still required."};
        finishDeployment(*state);
        return {true, false, true, L"Deployment verified; releasing transaction resources.", true};
    } catch (const std::exception& error) {
        state->lastError = errorText(error); adapter_.writeState(*state); return failure(state->lastError, true);
    }
}
OperationResult ComponentTransaction::completeUpdate(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    auto state = adapter_.readState();
    if (!state || (state->phase != WizardPhase::updatePendingReboot && state->phase != WizardPhase::updating))
        return failure(L"No update is pending.", state.has_value());
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (adapter_.updateRebootRequired()) return {true, true, true, L"Restart is still required."};
        state->phase = WizardPhase::updating; adapter_.writeState(*state);
        adapter_.stopTray(*state); adapter_.removeCredentialProviderRegistration();
        adapter_.configureSavedCredentialServiceForUpdate(true);
        report(progress, 40, L"Replace and byte-verify the six fixed component targets.");
        adapter_.applyStagedUpdate(*state); adapter_.configureSavedCredentialServiceForUpdate(false);
        adapter_.createCredentialProviderRegistration(adapter_.credentialProviderTarget());
        finishDeployment(*state);
        return {true, false, true, L"Update verified; credentials preserved. Releasing transaction resources.", true};
    } catch (const std::exception& error) {
        state->lastError = errorText(error); adapter_.writeState(*state); return failure(state->lastError, true);
    }
}
OperationResult ComponentTransaction::completeUninstall(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    auto state = adapter_.readState();
    if (!state || (state->phase != WizardPhase::uninstallPendingReboot && state->phase != WizardPhase::cleaningUp))
        return failure(L"No uninstall is pending.", state.has_value());
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (adapter_.updateRebootRequired()) return {true, true, true, L"Restart is still required."};
        if (!state->credentialCleanupConfirmed) throw ComponentError(L"Saved credential cleanup is not confirmed.");
        state->phase = WizardPhase::cleaningUp; adapter_.writeState(*state);
        adapter_.stopTray(*state); adapter_.removeDesktopIntegration();
        adapter_.removeCredentialProviderRegistration(); adapter_.removeSavedCredentialService();
        adapter_.removeTools();
        adapter_.deleteBinaryIfPresent(adapter_.credentialProviderTarget());
        adapter_.deleteBinaryIfPresent(adapter_.savedCredentialServiceTarget());
        adapter_.removeProductData(*state);
        for (const auto& component : kComponentFiles) {
            auto temporary = adapter_.componentTarget(component); temporary += L".update";
            adapter_.deleteBinaryIfPresent(temporary);
        }
        auto remaining = adapter_.inspect();
        remaining.continuationTaskPresent = remaining.applicationUninstallPresent = false;
        if (!remaining.observationValid || remaining.hasAnyArtifacts()) throw ComponentError(L"Removal verification found remaining components.");
        state->phase = WizardPhase::finalizing; state->lastError.clear(); adapter_.writeState(*state);
        return {true, false, true, L"Components and Windows enrollment removed; finalization remains pending.", true};
    } catch (const std::exception& error) {
        state->lastError = errorText(error); adapter_.writeState(*state); return failure(state->lastError, true);
    }
}
}
