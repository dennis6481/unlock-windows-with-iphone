// Created by Rui MA on 28 Sep 2026

#include "ComponentState.h"

namespace unlock::components {

bool ComponentSnapshot::hasKnownArtifacts() const noexcept {
    return credentialProviderDllPresent ||
        lsaDllPresent ||
        credentialProviderRegistered ||
        credentialProviderClsidRegistered ||
        savedCredentialServiceExePresent ||
        savedCredentialServiceRegistered ||
        lsaPackageRegistered ||
        continuationTaskPresent;
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
        savedCredentialServiceRunning &&
        !lsaDllPresent &&
        !lsaPackageRegistered;
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
        case WizardPhase::removedUnconfirmed:
            return L"RemovedUnconfirmed";
        default:
            return L"Unknown";
    }
}

const wchar_t* wizardActionName(const WizardAction action) noexcept {
    switch (action) {
        case WizardAction::install:
            return L"Install";
        case WizardAction::uninstall:
            return L"Uninstall";
        case WizardAction::cleanup:
            return L"Cleanup";
        case WizardAction::recover:
            return L"Recover";
        case WizardAction::resetStaleState:
            return L"ResetStaleState";
        case WizardAction::blocked:
            return L"Blocked";
        default:
            return L"Unknown";
    }
}

RecoveryPlan determineRecoveryPlan(const ComponentSnapshot& snapshot) {
    if (!snapshot.observationValid) {
        return {
            WizardAction::blocked,
            L"Component status cannot be read",
            snapshot.observationError.empty()
                ? L"Windows did not return a complete component status. No changes will be made."
                : snapshot.observationError,
            false,
        };
    }

    if (snapshot.lsaDllPresent || snapshot.lsaPackageRegistered) {
        return {
            WizardAction::blocked,
            L"A diagnostic LSA package is installed",
            L"This Credential Provider-only wizard cannot change an existing LSA installation. Restore the disposable VM snapshot before this probe.",
            false,
        };
    }

    if (!snapshot.statePresent) {
        if (!snapshot.hasAnyArtifacts()) {
            return {
                WizardAction::install,
                L"Install components",
                L"The components are not installed. You can install them now. Windows will need to restart before they can be used.",
                true,
            };
        }
        return {
            WizardAction::blocked,
            L"Unable to continue",
            L"Windows contains files or settings from an earlier attempt. No changes were made automatically.",
            false,
        };
    }

    if (!snapshot.stateValid) {
        return {
            WizardAction::blocked,
            L"Unable to continue",
            snapshot.stateError.empty()
                ? L"The saved recovery information cannot be read. No changes were made."
                : snapshot.stateError,
            false,
        };
    }

    switch (snapshot.statePhase) {
        case WizardPhase::installed:
            if (snapshot.isCompleteInstallation() && !snapshot.continuationTaskPresent) {
                return {
                    WizardAction::uninstall,
                    L"Uninstall components",
                    L"The components are installed. You can disable them now, then restart Windows to complete removal.",
                    true,
                };
            }
            if (!snapshot.hasAnyArtifacts()) {
                return {
                    WizardAction::resetStaleState,
                    L"Repair previous operation",
                    L"The previous operation left no components behind. The saved recovery information can be removed safely.",
                    true,
                };
            }
            return {
                WizardAction::recover,
                L"Repair installation",
                L"The previous installation did not finish. The wizard can safely restore Windows before you try again.",
                true,
            };

        case WizardPhase::installing:
            if (!snapshot.hasAnyArtifacts()) {
                return {
                    WizardAction::resetStaleState,
                    L"Repair previous operation",
                    L"The previous operation left no components behind. The saved recovery information can be removed safely.",
                    true,
                };
            }
            return {
                WizardAction::recover,
                L"Repair installation",
                L"The previous installation did not finish. The wizard can safely restore Windows before you try again.",
                true,
            };

        case WizardPhase::uninstallPendingReboot:
        case WizardPhase::cleaningUp:
            return {
                WizardAction::cleanup,
                L"Complete removal",
                L"The components have been disabled. Continue to remove the remaining files.",
                true,
            };

        case WizardPhase::recoveryRequired:
            return {
                WizardAction::recover,
                L"Repair previous operation",
                L"The previous operation did not finish. The wizard will keep the recovery information and try to restore Windows safely.",
                true,
            };

        case WizardPhase::removedUnconfirmed:
            return {
                WizardAction::blocked,
                L"Components removed; credential cleanup unconfirmed",
                L"Emergency removal removed the components, but deletion of the saved credential was not confirmed. The recovery record remains for diagnosis. Restore the VM snapshot before reinstalling.",
                false,
            };

        case WizardPhase::none:
        default:
            return {
                WizardAction::blocked,
                L"Unable to continue",
                L"The transaction record has an unsupported phase. No changes will be made.",
                false,
            };
    }
}

} // namespace unlock::components
