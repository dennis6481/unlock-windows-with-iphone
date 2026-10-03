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
    state.wizardPath = adapter_.wizardPath().wstring();
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
OperationResult ComponentTransaction::install(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    WizardState state; bool written = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto before = adapter_.inspect();
        const auto previous = adapter_.readState();
        const auto completion = adapter_.readCompletion();
        if (determineMaintenancePlan(before, previous ? &*previous : nullptr,
                completion ? &*completion : nullptr, adapter_.updateRebootRequired()).action != MaintenanceAction::install)
            return failure(L"Installation requires empty, readable component state.", before.statePresent);
        state = newState(WizardPhase::installing, adapter_.consoleUserSid());
        report(progress, 10, L"Stage complete installation in a protected System32 directory.");
        adapter_.stageUpdate(state);
        adapter_.writeState(state); written = true;
        report(progress, 35, L"Copy and byte-verify complete staged payload in System32.");
        adapter_.applyStagedUpdate(state);
        report(progress, 60, L"Register automatic LocalSystem service and Credential Provider.");
        adapter_.createSavedCredentialService();
        adapter_.createCredentialProviderRegistration(adapter_.credentialProviderTarget());
        state.phase = WizardPhase::installPendingReboot;
        adapter_.markUpdateRequiresReboot(); adapter_.writeState(state);
        adapter_.writeCompletion({state.transactionId, state.targetSid, L"Waiting for restart.", L"", false, false});
        report(progress, 80, L"Register SYSTEM boot continuation and target-user completion notification.");
        adapter_.registerContinuationTask(state);
        report(progress, 100, L"Installation prepared. Restart to verify and enable login startup.");
        return {true, true, true, L"Restart to finish installation. Use native PIN or password for the first sign-in."};
    } catch (const std::exception& error) {
        std::wstring message = errorText(error);
        if (written) {
            state.lastError = message;
            try { adapter_.writeState(state); } catch (const std::exception& more) { message += L"\r\nState write failed: " + errorText(more); }
        }
        return failure(message, written);
    }
}
OperationResult ComponentTransaction::completeInstall(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    auto state = adapter_.readState();
    if (!state || state->phase != WizardPhase::installPendingReboot) return failure(L"No installation is pending.", state.has_value());
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        if (adapter_.updateRebootRequired()) return {true, true, true, L"Restart is still required."};
        report(progress, 60, L"Register target-user Run startup and Start menu shortcuts.");
        adapter_.installDesktopIntegration(*state);
        if (!adapter_.inspect().isFullInstallation()) throw ComponentError(L"Full installation verification failed.");
        state->phase = WizardPhase::installed; state->lastError.clear();
        adapter_.writeState(*state);
        return {true, false, true, L"Installation verified. Phone unlock applies to an existing locked session, not first sign-in."};
    } catch (const std::exception& error) {
        state->lastError = errorText(error); adapter_.writeState(*state); return failure(state->lastError, true);
    }
}
OperationResult ComponentTransaction::beginUpdate(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    WizardState state; bool written = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto before = adapter_.inspect(); const auto old = adapter_.readState();
        const auto completion = adapter_.readCompletion();
        if (!old || determineMaintenancePlan(before, &*old, completion ? &*completion : nullptr,
                adapter_.updateRebootRequired()).action != MaintenanceAction::maintain)
            return failure(L"Update requires a verified installation without a pending transaction.", old.has_value());
        state = newState(WizardPhase::updatePendingReboot, old->targetSid);
        report(progress, 10, L"Stage all new files; saved credentials and enrollment remain untouched.");
        adapter_.stageUpdate(state); adapter_.markUpdateRequiresReboot(); adapter_.writeState(state); written = true;
        adapter_.writeCompletion({state.transactionId, state.targetSid, L"Waiting for restart.", L"", false, false});
        adapter_.registerContinuationTask(state);
        report(progress, 50, L"Remove Run startup; request verified Bluetooth tray to exit normally (30 second timeout).");
        adapter_.stopTray(state);
        report(progress, 75, L"Unregister Credential Provider; stop and disable credential service.");
        adapter_.removeCredentialProviderRegistration(); adapter_.configureSavedCredentialServiceForUpdate(true);
        report(progress, 100, L"Update prepared. Restart before replacing installed files.");
        return {true, true, true, L"Restart to complete the update. Saved credentials, enrollment and startup account are preserved."};
    } catch (const std::exception& error) {
        std::wstring message = errorText(error);
        if (written) {
            state.lastError = message;
            try { adapter_.writeState(state); } catch (const std::exception& more) { message += L"\r\nState write failed: " + errorText(more); }
        }
        return failure(message, written);
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
        report(progress, 15, L"Remove Run startup and wait for normal tray exit.");
        adapter_.stopTray(*state);
        adapter_.removeCredentialProviderRegistration(); adapter_.configureSavedCredentialServiceForUpdate(true);
        report(progress, 40, L"Replace and byte-verify all six staged files in System32.");
        adapter_.applyStagedUpdate(*state);
        adapter_.markUpdateRequiresReboot();
        report(progress, 70, L"Restore automatic service, Credential Provider, Run startup and shortcuts.");
        adapter_.configureSavedCredentialServiceForUpdate(false);
        adapter_.createCredentialProviderRegistration(adapter_.credentialProviderTarget());
        adapter_.installDesktopIntegration(*state);
        if (!adapter_.inspect().isFullInstallation()) throw ComponentError(L"Full updated installation verification failed.");
        state->phase = WizardPhase::installed; state->lastError.clear();
        adapter_.writeState(*state);
        return {true, false, true, L"Update verified. Credentials and enrollment preserved. Phone unlock still needs functional regression testing."};
    } catch (const std::exception& error) {
        state->lastError = errorText(error); adapter_.writeState(*state); return failure(state->lastError, true);
    }
}
OperationResult ComponentTransaction::beginUninstall(const ProgressCallback& progress) {
    adapter_.setOperationLog([progress](const std::wstring& text) { if (progress) progress(-1, text); });
    WizardState state; bool written = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto old = adapter_.readState();
        const auto before = adapter_.inspect();
        const auto completion = adapter_.readCompletion();
        if (!old || determineMaintenancePlan(before, &*old, completion ? &*completion : nullptr,
                adapter_.updateRebootRequired()).action != MaintenanceAction::maintain)
            return failure(L"Removal requires a verified current installation without a pending transaction.", old.has_value());
        state = newState(WizardPhase::uninstallPendingReboot, old->targetSid);
        report(progress, 10, L"Stage protected maintenance installer for reboot continuation.");
        adapter_.stageContinuation(state);
        report(progress, 20, L"Ask running service to confirm saved credential deletion.");
        adapter_.clearSavedCredential(); state.credentialCleanupConfirmed = true;
        report(progress, 25, L"Service confirmed saved credential deletion; phone public-key registration is retained.");
        adapter_.markUpdateRequiresReboot(); adapter_.writeState(state); written = true;
        adapter_.writeCompletion({state.transactionId, state.targetSid, L"Waiting for restart.", L"", false, false});
        adapter_.registerContinuationTask(state);
        report(progress, 40, L"Remove Run startup; wait for tray and pairing cancellation to exit.");
        adapter_.stopTray(state);
        report(progress, 65, L"Remove desktop startup and shortcuts; disable unlock components.");
        adapter_.removeDesktopIntegration(); adapter_.removeCredentialProviderRegistration(); adapter_.removeSavedCredentialService();
        report(progress, 100, L"Removal prepared. Restart to remove remaining files.");
        return {true, true, true, L"Saved credential deletion confirmed. Restart to finish removal. Phone enrollment is retained."};
    } catch (const std::exception& error) {
        std::wstring message = errorText(error);
        if (written) {
            state.lastError = message;
            try { adapter_.writeState(state); } catch (const std::exception& more) { message += L"\r\nState write failed: " + errorText(more); }
        }
        return failure(message, written);
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
        if (!state->credentialCleanupConfirmed) throw ComponentError(L"Saved credential cleanup is not confirmed. Removal paused.");
        state->phase = WizardPhase::cleaningUp; adapter_.writeState(*state);
        adapter_.stopTray(*state); adapter_.removeDesktopIntegration();
        adapter_.removeCredentialProviderRegistration(); adapter_.removeSavedCredentialService();
        report(progress, 50, L"Delete Bluetooth tray, pairing helper, manager and installed maintenance executable.");
        adapter_.removeTools();
        report(progress, 70, L"Delete: " + adapter_.credentialProviderTarget().wstring());
        adapter_.deleteBinaryIfPresent(adapter_.credentialProviderTarget());
        report(progress, 80, L"Delete: " + adapter_.savedCredentialServiceTarget().wstring());
        adapter_.deleteBinaryIfPresent(adapter_.savedCredentialServiceTarget());
        auto remaining = adapter_.inspect();
        remaining.continuationTaskPresent = false;
        if (!remaining.observationValid || remaining.hasAnyArtifacts()) throw ComponentError(L"Removal verification found remaining artifacts.");
        return {true, false, false, L"Components removed and saved credential deletion confirmed. Phone enrollment retained."};
    } catch (const std::exception& error) {
        state->lastError = errorText(error); adapter_.writeState(*state); return failure(state->lastError, true);
    }
}
}
