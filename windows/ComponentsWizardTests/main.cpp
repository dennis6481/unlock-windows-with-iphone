// Created by Rui MA on 28 Sep 2026

#include "../ComponentsWizard/ComponentState.h"
#include "../ComponentsWizard/ComponentFiles.h"
#include <cwchar>
#include <cstdlib>
#include <iostream>
using namespace unlock::components;
void expect(bool condition, const char* message) {
    if (!condition) { std::cerr << "FAILED: " << message << '\n'; std::exit(EXIT_FAILURE); }
}
ComponentSnapshot installedCore() {
    ComponentSnapshot state;
    state.statePresent = state.stateValid = true; state.statePhase = WizardPhase::installed;
    state.credentialProviderDllPresent = state.credentialProviderRegistered = state.credentialProviderClsidRegistered = true;
    state.savedCredentialServiceExePresent = state.savedCredentialServiceRegistered = true;
    state.savedCredentialServiceMatchesInstallation = state.savedCredentialServiceRunning = true;
    return state;
}
int main() {
    size_t desktopTools = 0;
    for (size_t i = 0; i < kComponentFiles.size(); ++i) {
        expect(kComponentFiles[i].name && kComponentFiles[i].name[0], "component manifest has a filename");
        if (kComponentFiles[i].desktopTool) ++desktopTools;
        for (size_t j = i + 1; j < kComponentFiles.size(); ++j)
            expect(wcscmp(kComponentFiles[i].name, kComponentFiles[j].name) != 0, "component manifest has no duplicate files");
    }
    expect(kComponentFiles.size() == 6 && desktopTools == 4, "manifest describes six components including four desktop tools");
    expect(determineRecoveryPlan({}).action == WizardAction::install, "empty machine offers Install");
    auto state = installedCore();
    expect(determineRecoveryPlan(state).action == WizardAction::update, "existing core-only installation offers Update without clearing credential");
    expect(!state.isFullInstallation(), "core-only install is not a verified expanded payload");
    state.toolsPresent = state.userStartupPresent = state.shortcutsPresent = state.desktopArtifactsPresent = true;
    state.targetSid = L"S-1-5-21-1-2-3-1001";
    expect(state.isFullInstallation(), "expanded verification requires tools, user Run startup, shortcuts and target");
    state.userStartupPresent = false;
    expect(!state.isFullInstallation(), "missing user Run startup cannot be reported as a full installation");
    state.userStartupPresent = true;
    state.trayRunning = false;
    expect(state.isFullInstallation(), "installed state is independent of tray currently running");
    state.shortcutsPresent = false;
    expect(!state.isFullInstallation(), "missing shortcuts cannot report full installation");
    state = installedCore(); state.continuationTaskPresent = true;
    expect(determineRecoveryPlan(state).action == WizardAction::blocked, "unexpected continuation cannot start another mutation");
    for (auto phase : {WizardPhase::updatePendingReboot, WizardPhase::updating}) {
        state.statePhase = phase;
        for (bool restart : {false, true}) {
            state.updateRebootRequired = restart;
            auto plan = determineRecoveryPlan(state);
            expect(plan.action == WizardAction::completeUpdate, "pending update never requests destructive removal");
            expect(plan.explanation.find(restart ? L"Restart" : L"Continue") != std::wstring::npos, "reboot boundary is explicit");
        }
    }
    state.statePhase = WizardPhase::installPendingReboot;
    expect(determineRecoveryPlan(state).action == WizardAction::blocked, "pending install cannot start a second operation");
    for (auto phase : {WizardPhase::uninstallPendingReboot, WizardPhase::cleaningUp}) {
        state.statePhase = phase;
        expect(determineRecoveryPlan(state).action == WizardAction::cleanup, "only registered removal can continue");
    }
    for (auto phase : {WizardPhase::installing, WizardPhase::recoveryRequired, WizardPhase::none}) {
        state.statePhase = phase;
        expect(!determineRecoveryPlan(state).safeToAutomate, "incomplete state never silently clears credentials");
    }
    state = {}; state.desktopArtifactsPresent = true;
    expect(determineRecoveryPlan(state).action == WizardAction::blocked, "partial tool or shortcut artifacts block clean install");
    state = installedCore(); state.stateValid = false;
    expect(determineRecoveryPlan(state).action == WizardAction::blocked, "invalid transaction fails closed");
    state = installedCore(); state.observationValid = false;
    expect(determineRecoveryPlan(state).action == WizardAction::blocked, "unreadable status fails closed");
    std::cout << "Component state checks passed.\n";
    return EXIT_SUCCESS;
}
