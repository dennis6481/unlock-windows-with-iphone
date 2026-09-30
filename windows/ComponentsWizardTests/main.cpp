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

void testCompleteInstallationRequestsUninstall() {
    auto snapshot = baseState(WizardPhase::installed);
    snapshot.credentialProviderDllPresent = true;
    snapshot.credentialProviderRegistered = true;
    snapshot.credentialProviderClsidRegistered = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::uninstall, "complete installation should request uninstall");
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

void testPreviousLsaInstallationIsNotMistakenForProbe() {
    auto snapshot = baseState(WizardPhase::installed);
    snapshot.credentialProviderDllPresent = true;
    snapshot.credentialProviderRegistered = true;
    snapshot.credentialProviderClsidRegistered = true;
    snapshot.lsaDllPresent = true;
    snapshot.lsaPackageRegistered = true;
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::blocked,
        "an old LSA installation must not be treated as the CP-only probe");
}

void testInvalidStateIsBlocked() {
    ComponentSnapshot snapshot;
    snapshot.statePresent = true;
    snapshot.stateValid = false;
    snapshot.stateError = L"invalid test state";
    const auto plan = determineRecoveryPlan(snapshot);
    expect(plan.action == WizardAction::blocked, "invalid state must be blocked");
}

} // namespace

int main() {
    testEmptyMachineRequestsInstall();
    testCompleteInstallationRequestsUninstall();
    testOrphanedInstalledStateResets();
    testPartialInstallationRequestsRecovery();
    testPendingRebootRequestsCleanup();
    testInstalledStateWithCleanupTaskRequestsRecovery();
    testCleaningStateRequestsCleanup();
    testRecoveryRequiredRequestsRecovery();
    testUnknownArtifactsAreBlocked();
    testPreviousLsaInstallationIsNotMistakenForProbe();
    testInvalidStateIsBlocked();
    std::cout << "ComponentsWizard state tests passed.\n";
    return EXIT_SUCCESS;
}
