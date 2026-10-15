// Created by Rui MA on 28 Sep 2026

#include "../Setup/ComponentState.h"
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
    snapshot.desktopPackagePresent = snapshot.userStartupPresent = snapshot.applicationUninstallPresent = snapshot.desktopArtifactsPresent = snapshot.versionsMatch = true;
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
    expect(launch({L"app", L"--binding-helper", L"21", L"00"}).role == Role::bindingHelper, "UAC helper dispatch remains separate");
    for (const auto arguments : {
            std::initializer_list<const wchar_t*>{L"app", L"--saved-password", L"--clear"},
            {L"app", L"--bind"}, {L"app", L"--bind", L"--remove"}, {L"app", L"--key-hex"}, {L"app", L"--key-clipboard", L"--saved-password"},
            {L"app", L"--clear", L"--replace"}, {L"app", L"--bluetooth"}, {L"app", L"--unknown"}}) {
        bool rejected = false;
        try { launch(arguments); } catch (const std::invalid_argument&) { rejected = true; }
        expect(rejected, "unknown, incomplete or conflicting roles are rejected before dispatch");
    }
    expect(parseProductVersion(kProductVersion.text()) == kProductVersion, "configured product version round trip");
    expect(parseProductVersion(L"1.2.3") == ProductVersion{1, 2, 3, 0}, "three-part versions default build to zero");
    expect(parseProductVersion(L"1.2.3.42") == ProductVersion{1, 2, 3, 42}, "four-part product version round trip");
    expect(parseProductVersion(L"65535.65535.65535.65535") == ProductVersion{65535, 65535, 65535, 65535}, "all version parts support the resource limit");
    expect(packageAction({0, 10, 0, 0}, {0, 9, 9, 65535}) == PackageAction::update, "numeric minor version comparison");
    expect(packageAction({1, 0, 0, 0}, {0, 65535, 65535, 65535}) == PackageAction::update, "major version takes precedence");
    expect(packageAction({1, 2, 3, 10}, {1, 2, 3, 9}) == PackageAction::update, "build comparison is numeric");
    expect(packageAction({1, 2, 4, 0}, {1, 2, 3, 65535}) == PackageAction::update, "patch takes precedence over build");
    expect(packageAction({1, 2, 3, 9}, {1, 2, 3, 10}) == PackageAction::rejectDowngrade, "lower builds are rejected");
    expect(packageAction(*parseProductVersion(L"1.2.3.0"), *parseProductVersion(L"1.2.3")) == PackageAction::reinstall,
        "legacy three-part versions are equivalent to build zero");
    expect(ProductVersion{1, 2, 3, 42}.release() == ProductVersion{1, 2, 3, 0}.release(), "public releases ignore build differences");
    expect(ProductVersion{1, 2, 4, 0}.release() > ProductVersion{1, 2, 3, 65535}.release(), "public updates compare release versions");
    expect(packageAction(kProductVersion, kProductVersion) == PackageAction::reinstall, "same version requires explicit reinstall");
    expect(packageAction({0, 1, 0, 0}, {0, 1, 1, 0}) == PackageAction::rejectDowngrade, "reject downgrade");
    for (const auto* invalid : {L"", L"0.1", L"0.1.0.", L"1.2.3.4.5", L"01.1.0", L"1.2.3.04", L"1.-1.0",
            L"65536.0.0", L"1.2.3.65536", L"999999999999999999999.0.0", L"0.1.0junk", L"1.2.3.4junk"})
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
    expect(determineMaintenancePlan({}, nullptr, nullptr, nullptr, false).action == MaintenanceAction::install,
        "empty machine offers Install");
    expect(isKnownPhase(static_cast<std::uint32_t>(WizardPhase::installed)), "installed phase remains in the persisted contract");
    auto snapshot = completeInstallation();
    InstalledProduct installed;
    installed.targetSid = snapshot.targetSid;
    installed.lastOperationId = L"123-456";
    installed.installedVersion = kProductVersion.text();
    SetupTransactionState transaction;
    transaction.targetSid = installed.targetSid;
    transaction.transactionId = installed.lastOperationId;
    transaction.installedVersion = transaction.packageVersion = installed.installedVersion;
    bool activeTransaction = false;
    auto plan = [&] (bool reboot = false, const CompletionRecord* completion = nullptr) {
        return determineMaintenancePlan(snapshot, &installed,
            activeTransaction ? &transaction : nullptr, completion, reboot);
    };
    expect(plan().action == MaintenanceAction::maintain, "formal installation offers maintenance without a transaction");
    for (const auto* version : {L"0.3.1", L"0.65535.65535"}) {
        installed.installedVersion = version;
        const auto blocked = plan();
        expect(blocked.action == MaintenanceAction::blocked && blocked.explanation.find(version) != std::wstring::npos &&
            blocked.explanation.find(L"Windows Settings > Apps") != std::wstring::npos,
            "pre-1.0.0 installations must require manual system uninstall with the actual version");
    }
    for (const auto* version : {L"", L"1.0", L"1.0.0junk"}) {
        installed.installedVersion = version;
        expect(plan().action == MaintenanceAction::blocked, "missing or malformed installed versions must block maintenance");
    }
    for (const auto* version : {L"1.0.0", L"1.0.1", L"2.0.0", L"1.0.0.0", L"1.0.0.42"}) {
        installed.installedVersion = version;
        expect(plan().action == MaintenanceAction::maintain, "maintenance floor is fixed independently of the current package version");
    }
    installed.installedVersion = kProductVersion.text();
    activeTransaction = true;
    transaction.phase = WizardPhase::updating;
    transaction.operation = SetupOperation::update;
    transaction.installedVersion = L"0.3.1";
    expect(plan().action == MaintenanceAction::blocked, "a new package must not resume maintenance of a pre-1.0.0 installation");
    transaction.installedVersion = installed.installedVersion;
    transaction.packageVersion = L"0.3.1";
    expect(plan().action == MaintenanceAction::blocked, "old-package transactions cannot be resumed");
    transaction.operation = SetupOperation::install;
    transaction.installedVersion.clear();
    transaction.packageVersion = kProductVersion.text();
    transaction.phase = WizardPhase::preparing;
    expect(plan().action == MaintenanceAction::resume, "a supported fresh-install transaction needs no previous installed version");
    transaction.operation = SetupOperation::update;
    expect(plan().action == MaintenanceAction::blocked, "maintenance transactions require an installed version");
    transaction.installedVersion = installed.installedVersion;
    transaction.operation = SetupOperation::install;
    transaction.phase = WizardPhase::none;
    activeTransaction = false;
    snapshot.versionsMatch = false;
    snapshot.versionError = L"Installed component version mismatch";
    expect(plan().action == MaintenanceAction::blocked, "mixed installed versions block new maintenance");
    expect(plan().explanation.find(snapshot.versionError) != std::wstring::npos, "version mismatch preserves its diagnostic");
    activeTransaction = true;
    transaction.phase = WizardPhase::updating;
    transaction.lastError = L"File replacement failed";
    expect(plan().action == MaintenanceAction::resume, "mixed versions in an interrupted update retain continuation");
    activeTransaction = false;
    transaction.lastError.clear();
    snapshot.versionError.clear();
    snapshot.versionsMatch = true;
    snapshot.trayRunning = false;
    expect(plan().action == MaintenanceAction::maintain, "tray not running is not an incomplete installation");
    snapshot.applicationUninstallPresent = false;
    expect(plan().action == MaintenanceAction::maintain,
        "application listing is not a prerequisite for maintaining intact installed components");
    snapshot.desktopPackagePresent = snapshot.userStartupPresent = false;
    expect(plan().action == MaintenanceAction::blocked, "core-only installation is unsupported");
    snapshot = completeInstallation();
    snapshot.targetSid.clear();
    installed.targetSid.clear();
    expect(plan().action == MaintenanceAction::blocked, "missing recorded target cannot be rebound");
    snapshot = completeInstallation();
    installed.targetSid = snapshot.targetSid;
    installed.schemaVersion = kWizardStateSchemaVersion - 1;
    expect(plan().action == MaintenanceAction::blocked, "old installed schema is unsupported");
    installed.schemaVersion = kWizardStateSchemaVersion;
    activeTransaction = true;
    transaction.phase = WizardPhase::finalizing;
    transaction.schemaVersion = kWizardStateSchemaVersion - 1;
    expect(plan().action == MaintenanceAction::blocked, "previous-schema transaction cannot resume with the new installer");
    transaction.schemaVersion = kWizardStateSchemaVersion;
    // The transaction owns continuation even if the previous formal installation is unsupported.
    installed.schemaVersion = kWizardStateSchemaVersion - 1;
    expect(plan().action == MaintenanceAction::resume, "active current transaction takes precedence over the installed record");
    installed.schemaVersion = kWizardStateSchemaVersion;
    activeTransaction = false;
    snapshot.continuationTaskPresent = true;
    expect(plan().action == MaintenanceAction::blocked, "unexpected continuation blocks new maintenance");
    activeTransaction = true;
    for (auto phase : {WizardPhase::installPendingReboot, WizardPhase::updatePendingReboot,
            WizardPhase::updating, WizardPhase::uninstallPendingReboot, WizardPhase::cleaningUp}) {
        transaction.phase = phase;
        expect(isKnownPhase(static_cast<std::uint32_t>(phase)), "pending phase is defined");
        snapshot.desktopPackagePresent = snapshot.userStartupPresent = false;
        snapshot.savedCredentialServiceRunning = false;
        expect(plan(true).action == MaintenanceAction::restart && plan(true).pending,
            "current pending transaction survives intentionally disabled components");
        transaction.lastError = L"Operation failed";
        expect(plan().action == MaintenanceAction::resume && plan().attentionRequired && plan().pending,
            "failed current transaction offers only continuation");
        expect(plan(true).action == MaintenanceAction::restart && plan(true).attentionRequired,
            "failed pending transaction respects reboot boundary");
        transaction.lastError.clear();
    }
    snapshot = completeInstallation();
    activeTransaction = false;
    CompletionRecord completion{installed.lastOperationId, installed.targetSid, L"", L"", false, false};
    expect(plan(false, &completion).action == MaintenanceAction::resume, "unfinished installed result handoff resumes verification");
    completion.transactionId = L"999-999";
    expect(plan(false, &completion).action == MaintenanceAction::maintain, "unrelated result does not block maintenance");
    completion.transactionId = installed.lastOperationId;
    completion.finished = true;
    expect(plan(false, &completion).action == MaintenanceAction::maintain, "finished result allows maintenance");
    activeTransaction = true;
    for (const auto phase : {WizardPhase::preparing, WizardPhase::finalizing}) {
        transaction.phase = phase;
        snapshot.desktopPackagePresent = false;
        expect(isKnownPhase(static_cast<std::uint32_t>(phase)), "owned preparation/finalization phase is defined");
        expect(plan().action == MaintenanceAction::resume && plan().pending,
            "preparation and finalization own their resources until verified cleanup");
        expect(plan(true).action == MaintenanceAction::restart && plan(true).pending,
            "pending resource ownership respects restart boundary");
    }
    for (const auto phase : {1U, 5U, 11U, UINT32_MAX}) {
        expect(!isKnownPhase(phase), "undefined phase values are rejected");
        transaction.phase = static_cast<WizardPhase>(phase);
        expect(plan().action == MaintenanceAction::blocked, "undefined phase never triggers cleanup");
        completion.finished = false;
        expect(plan(false, &completion).action == MaintenanceAction::blocked,
            "unfinished result cannot authorize an undefined phase");
    }
    transaction.phase = WizardPhase::none;
    expect(plan().action == MaintenanceAction::blocked, "empty phase cannot represent a transaction");
    snapshot = {};
    snapshot.desktopArtifactsPresent = true;
    expect(determineMaintenancePlan(snapshot, nullptr, nullptr, nullptr, false).action == MaintenanceAction::blocked,
        "unregistered artifacts block installation");
    snapshot = {};
    snapshot.applicationUninstallPresent = true;
    expect(snapshot.hasAnyArtifacts() &&
        determineMaintenancePlan(snapshot, nullptr, nullptr, nullptr, false).action == MaintenanceAction::blocked,
        "an orphan Installed apps entry is still a registered artifact, not an empty installation");
    snapshot = completeInstallation();
    activeTransaction = false;
    snapshot.stateValid = false;
    expect(plan().action == MaintenanceAction::blocked, "invalid record fails closed");
    snapshot.stateValid = true;
    snapshot.observationValid = false;
    expect(plan().action == MaintenanceAction::blocked, "unreadable status fails closed");
    std::cout << "Component maintenance checks passed.\n";
    return EXIT_SUCCESS;
}
