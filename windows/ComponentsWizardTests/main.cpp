// Created by Rui MA on 28 Sep 2026

#include "../ComponentsWizard/ComponentState.h"
#include "../ComponentFiles.h"
#include <cwchar>
#include <cstdlib>
#include <iostream>
using namespace unlock::components;
void expect(bool condition, const char* message) {
    if (!condition) { std::cerr << "FAILED: " << message << '\n'; std::exit(EXIT_FAILURE); }
}
ComponentSnapshot completeInstallation() {
    ComponentSnapshot snapshot;
    snapshot.statePresent = snapshot.stateValid = true;
    snapshot.credentialProviderDllPresent = snapshot.credentialProviderRegistered = snapshot.credentialProviderClsidRegistered = true;
    snapshot.savedCredentialServiceExePresent = snapshot.savedCredentialServiceRegistered = true;
    snapshot.savedCredentialServiceMatchesInstallation = snapshot.savedCredentialServiceRunning = true;
    snapshot.toolsPresent = snapshot.userStartupPresent = snapshot.shortcutsPresent = snapshot.desktopArtifactsPresent = true;
    snapshot.targetSid = L"S-1-5-21-1-2-3-1001";
    return snapshot;
}
int main() {
    size_t desktopTools = 0;
    for (size_t i = 0; i < kComponentFiles.size(); ++i) {
        expect(kComponentFiles[i].name && kComponentFiles[i].name[0] &&
            kComponentFiles[i].buildName && kComponentFiles[i].buildName[0], "manifest has installed and build filenames");
        if (kComponentFiles[i].desktopTool) ++desktopTools;
        for (size_t j = i + 1; j < kComponentFiles.size(); ++j) {
            expect(wcscmp(kComponentFiles[i].name, kComponentFiles[j].name) != 0, "no duplicate installed files");
            expect(wcscmp(kComponentFiles[i].buildName, kComponentFiles[j].buildName) != 0, "no duplicate build files");
        }
    }
    expect(kComponentFiles.size() == 6 && desktopTools == 4, "manifest describes the current six components");
    expect(wcscmp(kComponentFiles.back().name, kInstallerFile) == 0 &&
        wcscmp(kComponentFiles.back().buildName, kInstallerBuildFile) == 0, "setup maps to the installed maintenance executable");
    expect(determineMaintenancePlan({}, nullptr, nullptr, false).action == MaintenanceAction::install, "empty machine offers Install");
    auto snapshot = completeInstallation();
    WizardState state;
    state.phase = WizardPhase::installed;
    state.targetSid = snapshot.targetSid;
    state.transactionId = L"123-456";
    auto plan = [&] (bool reboot = false, const CompletionRecord* completion = nullptr) {
        return determineMaintenancePlan(snapshot, &state, completion, reboot);
    };
    expect(plan().action == MaintenanceAction::maintain, "current full installation offers maintenance");
    snapshot.trayRunning = false;
    expect(plan().action == MaintenanceAction::maintain, "tray not running is not an incomplete installation");
    snapshot.toolsPresent = snapshot.userStartupPresent = snapshot.shortcutsPresent = false;
    expect(plan().action == MaintenanceAction::blocked, "old core-only installation is unsupported");
    snapshot = completeInstallation();
    snapshot.targetSid.clear(); state.targetSid.clear();
    expect(plan().action == MaintenanceAction::blocked, "missing recorded target cannot be rebound");
    snapshot = completeInstallation(); state.targetSid = snapshot.targetSid;
    state.schemaVersion = 2;
    expect(plan().action == MaintenanceAction::blocked, "old schema is unsupported");
    state.schemaVersion = kWizardStateSchemaVersion;
    snapshot.continuationTaskPresent = true;
    expect(plan().action == MaintenanceAction::blocked, "unexpected continuation blocks new maintenance");
    for (auto phase : {WizardPhase::installPendingReboot, WizardPhase::updatePendingReboot,
            WizardPhase::updating, WizardPhase::uninstallPendingReboot, WizardPhase::cleaningUp}) {
        state.phase = phase;
        snapshot.toolsPresent = snapshot.userStartupPresent = snapshot.shortcutsPresent = false;
        snapshot.savedCredentialServiceRunning = false;
        expect(plan(true).action == MaintenanceAction::restart && plan(true).pending,
            "current pending transaction survives intentionally disabled components");
        state.lastError = L"Operation failed";
        expect(plan().action == MaintenanceAction::resume && plan().attentionRequired && plan().pending,
            "failed current transaction offers only continuation");
        expect(plan(true).action == MaintenanceAction::restart && plan(true).attentionRequired,
            "failed pending transaction respects reboot boundary");
        state.lastError.clear();
    }
    snapshot = completeInstallation(); state.phase = WizardPhase::installed;
    CompletionRecord completion{state.transactionId, state.targetSid, L"", L"", false, false};
    expect(plan(false, &completion).action == MaintenanceAction::resume, "unfinished result handoff resumes verification");
    completion.finished = true;
    expect(plan(false, &completion).action == MaintenanceAction::maintain, "finished result allows maintenance");
    for (auto phase : {WizardPhase::installing, WizardPhase::recoveryRequired, WizardPhase::none}) {
        state.phase = phase;
        expect(plan().action == MaintenanceAction::blocked, "interrupted initial state never triggers cleanup");
    }
    snapshot = {}; snapshot.desktopArtifactsPresent = true;
    expect(determineMaintenancePlan(snapshot, nullptr, nullptr, false).action == MaintenanceAction::blocked,
        "unregistered artifacts block installation");
    snapshot = completeInstallation(); state.phase = WizardPhase::installed;
    snapshot.stateValid = false;
    expect(plan().action == MaintenanceAction::blocked, "invalid transaction fails closed");
    snapshot.stateValid = true; snapshot.observationValid = false;
    expect(plan().action == MaintenanceAction::blocked, "unreadable status fails closed");
    std::cout << "Component maintenance checks passed.\n";
    return EXIT_SUCCESS;
}
