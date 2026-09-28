// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE

#include "ComponentTransaction.h"

#include <Windows.h>

#include <sstream>
#include <utility>

namespace unlock::components {
namespace {

std::wstring timestamp() {
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return std::to_wstring(value.QuadPart);
}

std::wstring processTransactionId() {
    return std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(GetCurrentProcessId());
}

std::wstring combineFailure(const std::wstring& primary, const std::vector<std::wstring>& cleanupErrors) {
    if (cleanupErrors.empty()) {
        return primary;
    }
    std::wstring result = primary + L"\r\n\r\nRollback also reported:";
    for (const auto& error : cleanupErrors) {
        result += L"\r\n- " + error;
    }
    return result;
}

} // namespace

ComponentTransaction::ComponentTransaction(WindowsAdapter& adapter) : adapter_(adapter) {}

WizardState ComponentTransaction::newState(
    const WizardPhase phase,
    const std::vector<std::byte>& originalPackages
) const {
    WizardState state;
    state.schemaVersion = 1;
    state.phase = phase;
    state.originalAuthenticationPackages = originalPackages;
    state.transactionId = processTransactionId();
    state.wizardPath = adapter_.wizardPath().wstring();
    state.createdAtUtc = timestamp();
    return state;
}

OperationResult ComponentTransaction::failure(const std::wstring& message, const bool statePreserved) const {
    return OperationResult{false, false, statePreserved, message};
}

void ComponentTransaction::report(
    const ProgressCallback& progress,
    const int percent,
    const std::wstring& message
) const {
    if (progress) {
        progress(percent, message);
    }
}

std::wstring ComponentTransaction::errorText(const std::exception& error) const {
    if (const auto* componentError = dynamic_cast<const ComponentError*>(&error)) {
        return componentError->wideWhat();
    }
    const auto* text = error.what();
    std::wstring result;
    while (*text != '\0') {
        result.push_back(static_cast<unsigned char>(*text));
        ++text;
    }
    return result.empty() ? L"Unknown component operation error." : result;
}

OperationResult ComponentTransaction::install(const ProgressCallback& progress) {
    std::vector<std::byte> originalPackages;
    WizardState state;
    bool stateWritten = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto before = adapter_.inspect();
        if (before.statePresent || before.hasAnyArtifacts()) {
            return failure(
                L"Installation cannot start because the machine already has component state or known artifacts. "
                L"Use the recovery or uninstall action shown by the wizard first.",
                before.statePresent
            );
        }
        originalPackages = adapter_.readAuthenticationPackages();
        state = newState(WizardPhase::installing, originalPackages);
        stateWritten = true;
        adapter_.writeState(state);

        report(progress, 10, L"Preparing the sign-in components...");
        adapter_.copyNativeDll(adapter_.lsaSource(), adapter_.lsaTarget());

        report(progress, 35, L"Applying Windows sign-in settings...");
        adapter_.writeAuthenticationPackages(adapter_.addLsaModule(originalPackages));

        report(progress, 60, L"Installing the sign-in components...");
        adapter_.copyNativeDll(adapter_.credentialProviderSource(), adapter_.credentialProviderTarget());

        report(progress, 80, L"Finishing the installation...");
        adapter_.createCredentialProviderRegistration(adapter_.credentialProviderTarget());

        report(progress, 95, L"Checking the installation...");
        const auto after = adapter_.inspect();
        if (!after.observationValid || !after.isCompleteInstallation()) {
            throw ComponentError(L"The installation verification did not find all expected components.");
        }

        state.phase = WizardPhase::installed;
        state.lastError.clear();
        adapter_.writeState(state);
        report(progress, 100, L"Installation complete.");
        return OperationResult{true, true, true, L"The components were installed successfully."};
    } catch (const std::exception& error) {
        const auto primaryError = errorText(error);
        if (!stateWritten) {
            return failure(primaryError, false);
        }

        std::vector<std::wstring> rollbackErrors;
        try {
            adapter_.removeCredentialProviderRegistration();
        } catch (const std::exception& rollbackError) {
            rollbackErrors.push_back(errorText(rollbackError));
        }
        try {
            adapter_.writeAuthenticationPackages(originalPackages);
        } catch (const std::exception& rollbackError) {
            rollbackErrors.push_back(errorText(rollbackError));
        }
        try {
            adapter_.deleteDllIfPresent(adapter_.credentialProviderTarget());
        } catch (const std::exception& rollbackError) {
            rollbackErrors.push_back(errorText(rollbackError));
        }
        try {
            adapter_.deleteDllIfPresent(adapter_.lsaTarget());
        } catch (const std::exception& rollbackError) {
            rollbackErrors.push_back(errorText(rollbackError));
        }

        if (rollbackErrors.empty()) {
            try {
                adapter_.clearState();
                return failure(primaryError, false);
            } catch (const std::exception& rollbackError) {
                rollbackErrors.push_back(errorText(rollbackError));
            }
        }

        state.phase = WizardPhase::recoveryRequired;
        state.lastError = combineFailure(primaryError, rollbackErrors);
        try {
            adapter_.writeState(state);
        } catch (const std::exception& stateError) {
            rollbackErrors.push_back(errorText(stateError));
        }
        return failure(combineFailure(primaryError, rollbackErrors), true);
    }
}

OperationResult ComponentTransaction::beginUninstall(const ProgressCallback& progress) {
    WizardState state;
    bool stateWritten = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto currentState = adapter_.readState();
        if (!currentState || currentState->phase != WizardPhase::installed) {
            return failure(L"There is no complete installation transaction to uninstall.", currentState.has_value());
        }
        state = *currentState;
        state.phase = WizardPhase::uninstallPendingReboot;
        state.lastError.clear();
        stateWritten = true;
        adapter_.writeState(state);

        report(progress, 20, L"Disabling the components...");
        adapter_.removeCredentialProviderRegistration();

        report(progress, 50, L"Restoring Windows sign-in settings...");
        adapter_.writeAuthenticationPackages(state.originalAuthenticationPackages);

        report(progress, 75, L"Checking the changes...");
        const auto afterRegistration = adapter_.inspect();
        if (!afterRegistration.observationValid ||
            afterRegistration.credentialProviderRegistered ||
            afterRegistration.credentialProviderClsidRegistered ||
            afterRegistration.lsaPackageRegistered) {
            throw ComponentError(L"The component registrations could not be fully removed.");
        }

        report(progress, 90, L"Preparing completion after restart...");
        adapter_.registerContinuationTask(state);
        report(progress, 100, L"Removal is ready for restart.");
        return OperationResult{
            true,
            true,
            true,
            L"The components have been disabled. Windows needs to restart to complete removal.",
        };
    } catch (const std::exception& error) {
        const auto message = errorText(error);
        if (!stateWritten) {
            return failure(message, false);
        }
        state.phase = WizardPhase::recoveryRequired;
        state.lastError = message;
        try {
            adapter_.writeState(state);
        } catch (const std::exception& stateError) {
            return failure(message + L"\r\nCould not preserve recovery state: " + errorText(stateError), true);
        }
        return failure(message, true);
    }
}

OperationResult ComponentTransaction::completeUninstall(const ProgressCallback& progress) {
    WizardState state;
    bool stateWritten = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto currentState = adapter_.readState();
        if (!currentState ||
            (currentState->phase != WizardPhase::uninstallPendingReboot && currentState->phase != WizardPhase::cleaningUp)) {
            return failure(L"There is no pending uninstall cleanup to complete.", currentState.has_value());
        }
        state = *currentState;
        state.phase = WizardPhase::cleaningUp;
        state.lastError.clear();
        stateWritten = true;
        adapter_.writeState(state);

        report(progress, 30, L"Removing the remaining component files...");
        adapter_.deleteDllIfPresent(adapter_.credentialProviderTarget());
        report(progress, 60, L"Finishing the removal...");
        adapter_.deleteDllIfPresent(adapter_.lsaTarget());

        report(progress, 80, L"Checking the removal...");
        const auto after = adapter_.inspect();
        if (!after.observationValid ||
            after.credentialProviderDllPresent ||
            after.lsaDllPresent ||
            after.credentialProviderRegistered ||
            after.credentialProviderClsidRegistered ||
            after.lsaPackageRegistered) {
            throw ComponentError(L"Uninstall verification found remaining component files or registrations.");
        }

        report(progress, 90, L"Finishing...");
        adapter_.removeContinuationTask();
        const auto afterTask = adapter_.inspect();
        if (!afterTask.observationValid || afterTask.continuationTaskPresent) {
            throw ComponentError(L"The cleanup task could not be removed.");
        }
        adapter_.clearState();
        report(progress, 100, L"Removal complete.");
        return OperationResult{true, false, false, L"The components have been completely removed from Windows."};
    } catch (const std::exception& error) {
        const auto message = errorText(error);
        if (stateWritten) {
            state.phase = WizardPhase::cleaningUp;
            state.lastError = message;
            try {
                adapter_.writeState(state);
            } catch (...) {
                // The original failure is still more useful than replacing it with a state-write failure.
            }
        }
        return failure(message, stateWritten);
    }
}

OperationResult ComponentTransaction::recover(const ProgressCallback& progress) {
    WizardState state;
    bool stateWritten = false;
    try {
        adapter_.assertSupportedAdministratorEnvironment();
        const auto currentState = adapter_.readState();
        if (!currentState || currentState->phase == WizardPhase::none) {
            return failure(L"No safe transaction record is available for recovery.", currentState.has_value());
        }
        if (currentState->phase == WizardPhase::uninstallPendingReboot || currentState->phase == WizardPhase::cleaningUp) {
            return completeUninstall(progress);
        }

        state = *currentState;
        state.phase = WizardPhase::recoveryRequired;
        state.lastError.clear();
        stateWritten = true;
        adapter_.writeState(state);

        report(progress, 20, L"Restoring Windows sign-in settings...");
        adapter_.removeCredentialProviderRegistration();
        report(progress, 45, L"Removing incomplete components...");
        adapter_.writeAuthenticationPackages(state.originalAuthenticationPackages);
        report(progress, 70, L"Cleaning up the interrupted operation...");
        adapter_.deleteDllIfPresent(adapter_.credentialProviderTarget());
        adapter_.deleteDllIfPresent(adapter_.lsaTarget());
        adapter_.removeContinuationTask();

        const auto after = adapter_.inspect();
        if (!after.observationValid || after.hasAnyArtifacts()) {
            throw ComponentError(L"Recovery verification found remaining component artifacts.");
        }
        adapter_.clearState();
        report(progress, 100, L"Repair complete.");
        return OperationResult{true, false, false, L"The previous operation was repaired successfully."};
    } catch (const std::exception& error) {
        const auto message = errorText(error);
        if (stateWritten) {
            state.phase = WizardPhase::recoveryRequired;
            state.lastError = message;
            try {
                adapter_.writeState(state);
            } catch (...) {
            }
        }
        return failure(message, stateWritten);
    }
}

OperationResult ComponentTransaction::resetStaleState() {
    try {
        const auto snapshot = adapter_.inspect();
        if (snapshot.hasAnyArtifacts()) {
            return failure(L"The transaction state cannot be reset while known artifacts exist.", true);
        }
        adapter_.clearState();
        return OperationResult{true, false, false, L"The previous operation information was removed."};
    } catch (const std::exception& error) {
        return failure(errorText(error), true);
    }
}

} // namespace unlock::components
