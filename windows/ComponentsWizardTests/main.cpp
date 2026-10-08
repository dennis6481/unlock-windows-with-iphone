// Created by Rui MA on 28 Sep 2026

#include "../ComponentsWizard/ComponentState.h"
#include "../ComponentFiles.h"
#include "../DesktopApp/DesktopApp.h"
#include <cwchar>
#include <cstdlib>
#include <iostream>
#include <initializer_list>
#include <vector>
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
    snapshot.toolsPresent = snapshot.userStartupPresent = snapshot.applicationUninstallPresent = snapshot.desktopArtifactsPresent = snapshot.versionsMatch = true;
    snapshot.targetSid = L"S-1-5-21-1-2-3-1001";
    return snapshot;
}
int main() {
    using unlock_windows::desktop_app::Role;
    const auto launch = [](std::initializer_list<const wchar_t*> values) {
        std::vector<wchar_t*> arguments;
        for (const auto* value : values) arguments.push_back(const_cast<wchar_t*>(value));
        return unlock_windows::desktop_app::parseLaunch(static_cast<int>(arguments.size()), arguments.data());
    };
    expect(launch({L"app"}).role == Role::tray, "ordinary startup selects only the tray role");
    expect(launch({L"app", L"--saved-password"}).role == Role::savedPassword,
        "password management does not select the tray role");
    expect(launch({L"app", L"--bluetooth", L"channel", L"pair", L"1", L"sid", L"deadline", L"event", L"pid"}).role == Role::bluetoothEnrollment,
        "Bluetooth enrollment dispatch leaves identity validation to enrollment");
    expect(launch({L"app", L"--key-clipboard", L"--replace"}).replace, "manual replacement option remains supported");
    expect(launch({L"app", L"--clear"}).clear, "manual removal remains explicit");
    for (const auto arguments : {
            std::initializer_list<const wchar_t*>{L"app", L"--saved-password", L"--clear"},
            {L"app", L"--key-hex"}, {L"app", L"--key-clipboard", L"--saved-password"},
            {L"app", L"--clear", L"--replace"}, {L"app", L"--bluetooth"}, {L"app", L"--unknown"}}) {
        bool rejected = false;
        try { launch(arguments); } catch (const std::invalid_argument&) { rejected = true; }
        expect(rejected, "unknown, incomplete or conflicting roles are rejected before dispatch");
    }
    expect(parseProductVersion(kProductVersion.text()) == kProductVersion, "configured product version round trip");
    expect(packageAction({0, 10, 0}, {0, 9, 9}) == PackageAction::update, "numeric minor version comparison");
    expect(packageAction({1, 0, 0}, {0, 65535, 65535}) == PackageAction::update, "major version takes precedence");
    expect(packageAction(kProductVersion, kProductVersion) == PackageAction::reinstall, "same version requires explicit reinstall");
    expect(packageAction({0, 1, 0}, {0, 1, 1}) == PackageAction::rejectDowngrade, "reject downgrade");
    for (const auto* invalid : {L"", L"0.1", L"0.1.0.0", L"01.1.0", L"1.-1.0", L"65536.0.0", L"0.1.0junk"})
        expect(!parseProductVersion(invalid), "malformed product versions fail closed");
    size_t desktopTools = 0;
    for (size_t i = 0; i < kComponentFiles.size(); ++i) {
        expect(kComponentFiles[i].name && kComponentFiles[i].name[0], "manifest has fixed component filenames");
        if (kComponentFiles[i].desktopTool) ++desktopTools;
        for (size_t j = i + 1; j < kComponentFiles.size(); ++j) {
            expect(wcscmp(kComponentFiles[i].name, kComponentFiles[j].name) != 0, "no duplicate installed files");
        }
    }
    expect(kComponentFiles.size() == 4 && desktopTools == 2, "manifest describes the current four components");
    expect(wcscmp(kComponentFiles.back().name, L"setup.exe") == 0, "setup keeps its fixed name in staging and installation");
    expect(determineMaintenancePlan({}, nullptr, nullptr, false).action == MaintenanceAction::install, "empty machine offers Install");
    auto snapshot = completeInstallation();
    WizardState state;
    state.phase = WizardPhase::installed;
    state.targetSid = snapshot.targetSid;
    state.transactionId = L"123-456";
    state.installedVersion = state.packageVersion = kProductVersion.text();
    expect(isKnownPhase(static_cast<std::uint32_t>(state.phase)), "installed phase is defined");
    auto plan = [&] (bool reboot = false, const CompletionRecord* completion = nullptr) {
        return determineMaintenancePlan(snapshot, &state, completion, reboot);
    };
    expect(plan().action == MaintenanceAction::maintain, "current full installation offers maintenance");
    snapshot.versionsMatch = false;
    snapshot.versionError = L"Installed component version mismatch";
    expect(plan().action == MaintenanceAction::blocked, "mixed installed versions block new maintenance");
    expect(plan().explanation.find(snapshot.versionError) != std::wstring::npos, "version mismatch preserves its diagnostic");
    state.phase = WizardPhase::updating;
    state.lastError = L"File replacement failed";
    expect(plan().action == MaintenanceAction::resume, "mixed versions in an interrupted update retain continuation");
    state.phase = WizardPhase::installed; state.lastError.clear(); snapshot.versionError.clear();
    snapshot.versionsMatch = true;
    snapshot.trayRunning = false;
    expect(plan().action == MaintenanceAction::maintain, "tray not running is not an incomplete installation");
    snapshot.applicationUninstallPresent = false;
    expect(plan().action == MaintenanceAction::maintain,
        "application listing is not a prerequisite for maintaining intact installed components");
    snapshot.toolsPresent = snapshot.userStartupPresent = false;
    expect(plan().action == MaintenanceAction::blocked, "old core-only installation is unsupported");
    snapshot = completeInstallation();
    snapshot.targetSid.clear(); state.targetSid.clear();
    expect(plan().action == MaintenanceAction::blocked, "missing recorded target cannot be rebound");
    snapshot = completeInstallation(); state.targetSid = snapshot.targetSid;
    state.schemaVersion = 4;
    expect(plan().action == MaintenanceAction::blocked, "old schema is unsupported");
    state.phase = WizardPhase::finalizing;
    expect(plan().action == MaintenanceAction::blocked, "old six-component transaction cannot resume with the new installer");
    state.phase = WizardPhase::installed;
    state.schemaVersion = kWizardStateSchemaVersion;
    snapshot.continuationTaskPresent = true;
    expect(plan().action == MaintenanceAction::blocked, "unexpected continuation blocks new maintenance");
    for (auto phase : {WizardPhase::installPendingReboot, WizardPhase::updatePendingReboot,
            WizardPhase::updating, WizardPhase::uninstallPendingReboot, WizardPhase::cleaningUp}) {
        state.phase = phase;
        expect(isKnownPhase(static_cast<std::uint32_t>(phase)), "pending phase is defined");
        snapshot.toolsPresent = snapshot.userStartupPresent = false;
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
    for (const auto phase : {WizardPhase::preparing, WizardPhase::finalizing}) {
        state.phase = phase; snapshot.toolsPresent = false;
        expect(isKnownPhase(static_cast<std::uint32_t>(phase)), "owned preparation/finalization phase is defined");
        expect(plan().action == MaintenanceAction::resume && plan().pending,
            "preparation and finalization own their resources until verified cleanup");
        expect(plan(true).action == MaintenanceAction::restart && plan(true).pending,
            "pending resource ownership respects restart boundary");
    }
    for (const auto phase : {1U, 5U, 11U, UINT32_MAX}) {
        expect(!isKnownPhase(phase), "undefined phase values are rejected");
        state.phase = static_cast<WizardPhase>(phase);
        expect(plan().action == MaintenanceAction::blocked, "interrupted initial state never triggers cleanup");
        completion.finished = false;
        expect(plan(false, &completion).action == MaintenanceAction::blocked,
            "unfinished result cannot authorize an undefined phase");
    }
    state.phase = WizardPhase::none;
    expect(plan().action == MaintenanceAction::blocked, "empty phase cannot represent an installation");
    snapshot = {}; snapshot.desktopArtifactsPresent = true;
    expect(determineMaintenancePlan(snapshot, nullptr, nullptr, false).action == MaintenanceAction::blocked,
        "unregistered artifacts block installation");
    snapshot = {}; snapshot.applicationUninstallPresent = true;
    expect(snapshot.hasAnyArtifacts() &&
        determineMaintenancePlan(snapshot, nullptr, nullptr, false).action == MaintenanceAction::blocked,
        "an orphan Installed apps entry is still a registered artifact, not an empty installation");
    snapshot = completeInstallation(); state.phase = WizardPhase::installed;
    snapshot.stateValid = false;
    expect(plan().action == MaintenanceAction::blocked, "invalid transaction fails closed");
    snapshot.stateValid = true; snapshot.observationValid = false;
    expect(plan().action == MaintenanceAction::blocked, "unreadable status fails closed");
    std::cout << "Component maintenance checks passed.\n";
    return EXIT_SUCCESS;
}
