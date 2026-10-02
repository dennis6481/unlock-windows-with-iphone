// Created by Rui MA on 28 Sep 2026

#include "../ComponentsWizard/ComponentState.h"

#include <cstdlib>
#include <iostream>

using unlock::components::ComponentSnapshot;
using unlock::components::WizardAction;
using unlock::components::WizardPhase;
using unlock::components::determineRecoveryPlan;

namespace {

void expect(const bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

ComponentSnapshot baseState(const WizardPhase phase) {
    ComponentSnapshot snapshot;
    snapshot.statePresent = true;
    snapshot.stateValid = true;
    snapshot.statePhase = phase;
    return snapshot;
}

void testEmptyMachineRequestsInstall() {
    ComponentSnapshot snapshot;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::install, "empty machine should request install");
}

void testCompleteInstallationRequestsUpdate() {
    auto snapshot = baseState(WizardPhase::installed);
    snapshot.credentialProviderDllPresent = true;
    snapshot.credentialProviderRegistered = true;
    snapshot.credentialProviderClsidRegistered = true;
    snapshot.savedCredentialServiceExePresent = true;
    snapshot.savedCredentialServiceRegistered = true;
    snapshot.savedCredentialServiceMatchesInstallation = true;
    snapshot.savedCredentialServiceRunning = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::update, "complete installation should offer credential-preserving update");
}

void testInterruptedUpdateNeverRequestsDestructiveRecovery() {
    for (const auto phase : {WizardPhase::updatePendingReboot, WizardPhase::updating}) {
        auto snapshot = baseState(phase);
        snapshot.savedCredentialServiceRegistered = true;
        snapshot.credentialProviderDllPresent = true;
        for (const bool needsRestart : {false, true}) {
            snapshot.updateRebootRequired = needsRestart;
            const auto plan = determineRecoveryPlan(snapshot);
            expect(plan.action == WizardAction::completeUpdate,
                "an interrupted update must resume update, not credential-clearing recovery");
            expect(plan.explanation.find(needsRestart ? L"Restart" : L"Continue") != std::wstring::npos,
                "update plan must explain its reboot boundary");
        }
    }
}

void testOrphanedInstalledStateResets() {
    const auto plan = determineRecoveryPlan(baseState(WizardPhase::installed));
    expect(plan.action == WizardAction::resetStaleState, "orphaned Installed state should reset");
}

void testPartialInstallationRequestsRecovery() {
    auto snapshot = baseState(WizardPhase::installed);
    snapshot.credentialProviderDllPresent = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::recover, "partial installation should request recovery");
}

void testPendingRebootRequestsCleanup() {
    auto snapshot = baseState(WizardPhase::uninstallPendingReboot);
    snapshot.credentialProviderDllPresent = true;
    snapshot.continuationTaskPresent = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::cleanup, "pending uninstall should request cleanup");
}

void testInstalledStateWithCleanupTaskRequestsRecovery() {
    auto snapshot = baseState(WizardPhase::installed);
    snapshot.credentialProviderDllPresent = true;
    snapshot.credentialProviderRegistered = true;
    snapshot.credentialProviderClsidRegistered = true;
    snapshot.savedCredentialServiceExePresent = true;
    snapshot.savedCredentialServiceRegistered = true;
    snapshot.savedCredentialServiceMatchesInstallation = true;
    snapshot.savedCredentialServiceRunning = true;
    snapshot.continuationTaskPresent = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::recover, "an unexpected task must not make installation look complete");
}

void testCleaningStateRequestsCleanup() {
    const auto plan = determineRecoveryPlan(baseState(WizardPhase::cleaningUp));
    expect(plan.action == WizardAction::cleanup, "cleaning state should request cleanup");
}

void testRecoveryRequiredRequestsRecovery() {
    const auto plan = determineRecoveryPlan(baseState(WizardPhase::recoveryRequired));
    expect(plan.action == WizardAction::recover, "recovery-required state should request recovery");
}

void testUnknownArtifactsAreBlocked() {
    ComponentSnapshot snapshot;
    snapshot.credentialProviderDllPresent = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::blocked, "unknown artifacts must be blocked");
    expect(!plan.safeToAutomate, "unknown artifacts must not be safe to automate");
}

void testServiceMismatchRequestsRecovery() {
    auto snapshot = baseState(WizardPhase::installed);
    snapshot.credentialProviderDllPresent = true;
    snapshot.credentialProviderRegistered = true;
    snapshot.credentialProviderClsidRegistered = true;
    snapshot.savedCredentialServiceExePresent = true;
    snapshot.savedCredentialServiceRegistered = true;
    snapshot.savedCredentialServiceRunning = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::recover,
        "wrong saved credential service configuration must not look installed");
}

void testInvalidStateIsBlocked() {
    ComponentSnapshot snapshot;
    snapshot.statePresent = true;
    snapshot.stateValid = false;
    snapshot.stateError = L"invalid test state";
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::blocked, "invalid state must be blocked");
}

void testOrphanedSavedCredentialServiceIsBlocked() {
    ComponentSnapshot snapshot;
    snapshot.savedCredentialServiceRegistered = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::blocked,
        "unowned saved credential service must not be removed automatically");
}

} // namespace

int main() {
    testEmptyMachineRequestsInstall();
    testCompleteInstallationRequestsUpdate();
    testInterruptedUpdateNeverRequestsDestructiveRecovery();
    testOrphanedInstalledStateResets();
    testPartialInstallationRequestsRecovery();
    testServiceMismatchRequestsRecovery();
    testPendingRebootRequestsCleanup();
    testInstalledStateWithCleanupTaskRequestsRecovery();
    testCleaningStateRequestsCleanup();
    testRecoveryRequiredRequestsRecovery();
    testUnknownArtifactsAreBlocked();
    testInvalidStateIsBlocked();
    testOrphanedSavedCredentialServiceIsBlocked();
    std::cout << "ComponentsWizard state tests passed.\n";
    return EXIT_SUCCESS;
}
