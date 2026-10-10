// Created by Rui MA on 09 Oct 2026
// Separate installation/transaction persistence and atomic completion records.

#define UNICODE
#define _UNICODE
#include "SetupStateStore.h"
#include "PackageDeployment.h"
#include "SetupPlatform.h"
#include <array>
#include <cstring>
#include <vector>

namespace unlock::components {
std::optional<InstalledProduct> SetupStateStore::readInstalledProduct() const {
    if (!registryKeyExists(kInstalledProductRegistryPath.c_str())) return std::nullopt;
    InstalledProduct installed;
    installed.schemaVersion = readRegistryDword(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath.c_str(), kSchemaVersionValueName).value_or(0);
    installed.targetSid = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath.c_str(), kTargetSidValueName).value_or(L"");
    installed.installedVersion = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath.c_str(), kInstalledVersionValueName).value_or(L"");
    installed.wizardPath = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath.c_str(), kStateWizardPathValueName).value_or(L"");
    installed.lastOperationId = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath.c_str(), kLastOperationIdValueName).value_or(L"");
    if (installed.schemaVersion != kWizardStateSchemaVersion || !parseProductVersion(installed.installedVersion) ||
        installed.targetSid.empty() || installed.wizardPath != (desktopDirectory() / kInstallerFile).wstring())
        fail(L"Installed product record is incomplete or unsupported. For an older installation, uninstall with its original installer before installing this version. No migration will run.");
    validateTargetSid(installed.targetSid);
    return installed;
}

std::optional<SetupTransactionState> SetupStateStore::readTransaction() const {
    const auto phase = readRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStatePhaseValueName);
    if (!phase) {
        if (registryKeyExists(kWizardStateRegistryPath.c_str()))
            fail(L"The Setup state key exists but has no phase value.");
        return std::nullopt;
    }
    SetupTransactionState state;
    state.schemaVersion = readRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kSchemaVersionValueName).value_or(0);
    state.phase = static_cast<WizardPhase>(*phase);
    state.transactionId = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateTransactionIdValueName).value_or(L"");
    state.wizardPath = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateWizardPathValueName).value_or(L"");
    state.createdAtUtc = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateCreatedAtValueName).value_or(L"");
    state.lastError = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateLastErrorValueName).value_or(L"");
    state.targetSid = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kTargetSidValueName).value_or(L"");
    state.credentialCleanupConfirmed = readRegistryDword(
        HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kCredentialCleanupValueName).value_or(0) == 1;
    state.operation = static_cast<SetupOperation>(readRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kOperationValueName).value_or(99));
    state.sourcePath = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kSourcePathValueName).value_or(L"");
    state.installedVersion = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kInstalledVersionValueName).value_or(L"");
    state.packageVersion = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kPackageVersionValueName).value_or(L"");
    state.payloadReady = readRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kPayloadReadyValueName).value_or(0) == 1;
    if (state.schemaVersion != kWizardStateSchemaVersion || !isKnownPhase(*phase) || state.targetSid.empty())
        fail(L"Unsupported or incomplete installation record. Complete or uninstall an older installation with its original installer before installing this version. No migration will run.");
    validateTargetSid(state.targetSid);
    if (state.operation > SetupOperation::uninstall || !parseProductVersion(state.packageVersion) ||
        (state.phase == WizardPhase::installed && !parseProductVersion(state.installedVersion)))
        fail(L"Unsupported product version or operation record. No migration will run.");
    const auto packagePath = state.payloadReady ? state.wizardPath : state.sourcePath;
    if (state.phase != WizardPhase::installed && !packagePath.empty() && fileExists(packagePath))
        PackageDeployment::requireEmbeddedComponents(packagePath);
    return state;
}

void SetupStateStore::writeTransaction(const SetupTransactionState& state) const {
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kOperationValueName, static_cast<DWORD>(state.operation));
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kSourcePathValueName, state.sourcePath);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kInstalledVersionValueName, state.installedVersion);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kPackageVersionValueName, state.packageVersion);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kPayloadReadyValueName, state.payloadReady ? 1 : 0);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kTargetSidValueName, state.targetSid);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kSchemaVersionValueName, state.schemaVersion);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateTransactionIdValueName, state.transactionId);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateWizardPathValueName, state.wizardPath);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateCreatedAtValueName, state.createdAtUtc);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStateLastErrorValueName, state.lastError);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(),
        kCredentialCleanupValueName, state.credentialCleanupConfirmed ? 1 : 0);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath.c_str(), kStatePhaseValueName, static_cast<DWORD>(state.phase));
}

bool SetupStateStore::transactionRebootRequired() const {
    return registryKeyExists(kUpdateRebootGuard.c_str());
}

void SetupStateStore::markTransactionRequiresReboot() const {
    HKEY key = nullptr;
    const auto result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kUpdateRebootGuard.c_str(), 0, nullptr,
        REG_OPTION_VOLATILE, KEY_READ | KEY_WOW64_64KEY, nullptr, &key, nullptr);
    if (result != ERROR_SUCCESS) fail(L"Could not establish update reboot boundary: " + win32ErrorMessage(result));
    ScopedRegistryKey guard(key);
}

void SetupStateStore::writeCompletion(const CompletionRecord& record) const {
    // Commit all fields as one snapshot so observers never read a partially updated result.
    size_t bytes = kCompletionHeaderWords * kCompletionWordBytes;
    for (const auto& field : kCompletionTextFields) {
        const auto& text = record.*field.member;
        if (text.size() > kCompletionMaximumBytes / kCompletionCharacterBytes)
            throw ComponentError(L"Completion log exceeds its storage limit.");
        bytes += text.size() * kCompletionCharacterBytes;
    }
    if (bytes > kCompletionMaximumBytes) throw ComponentError(L"Completion record exceeds its storage limit.");
    std::array<std::uint32_t, kCompletionHeaderWords> header{};
    header[kCompletionVersionWord] = kCompletionVersion;
    header[kCompletionFlagsWord] = (record.finished ? kCompletionFinishedFlag : 0) |
        (record.success ? kCompletionSuccessFlag : 0);
    for (size_t i = 0; i < kCompletionTextFields.size(); ++i)
        header[kCompletionLengthsWord + i] = static_cast<std::uint32_t>((record.*kCompletionTextFields[i].member).size());
    std::vector<BYTE> snapshot(bytes);
    std::memcpy(snapshot.data(), header.data(), sizeof(header));
    size_t offset = sizeof(header);
    for (const auto& field : kCompletionTextFields) {
        const auto& text = record.*field.member;
        const size_t n = text.size() * kCompletionCharacterBytes;
        if (n) std::memcpy(snapshot.data() + offset, text.data(), n);
        offset += n;
    }
    ScopedRegistryKey key;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto acl = L"D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KRSD;;;" + record.targetSid + L")";
    checkWin32(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr), L"Create result registry security");
    struct Security { PSECURITY_DESCRIPTOR p; ~Security() { LocalFree(p); } } security{descriptor};
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    checkRegistry(RegCreateKeyExW(HKEY_LOCAL_MACHINE, kResultRegistryPath.c_str(), 0, nullptr, 0,
        KEY_WRITE | WRITE_DAC | KEY_WOW64_64KEY, &attributes, &key.value, nullptr), L"Create completion record");
    checkRegistry(RegSetKeySecurity(key.value, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor), L"Protect completion record");
    checkRegistry(RegSetValueExW(key.value, kSnapshotValueName, 0, REG_BINARY, snapshot.data(),
        static_cast<DWORD>(snapshot.size())), L"Commit atomic completion snapshot");
    checkRegistry(RegFlushKey(key.value), L"Flush completion record");
}
std::optional<CompletionRecord> SetupStateStore::readCompletion() const {
    ScopedRegistryKey key;
    auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kResultRegistryPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key.value);
    if (status == ERROR_FILE_NOT_FOUND) return {};
    checkRegistry(status, L"Open completion record");
    std::vector<BYTE> snapshot(kCompletionMaximumBytes);
    DWORD bytes = static_cast<DWORD>(snapshot.size());
    const auto read = RegGetValueW(key.value, nullptr, kSnapshotValueName, RRF_RT_REG_BINARY, nullptr, snapshot.data(), &bytes);
    if (read == ERROR_FILE_NOT_FOUND) return {};
    checkRegistry(read, L"Read atomic completion snapshot");
    std::array<std::uint32_t, kCompletionHeaderWords> header{};
    if (bytes < sizeof(header)) throw ComponentError(L"Truncated completion snapshot.");
    std::memcpy(header.data(), snapshot.data(), sizeof(header));
    if (header[kCompletionVersionWord] != kCompletionVersion ||
        (header[kCompletionFlagsWord] & ~kCompletionFlags) != 0)
        throw ComponentError(L"Unsupported completion snapshot.");
    CompletionRecord record;
    size_t offset = sizeof(header);
    for (size_t i = 0; i < kCompletionTextFields.size(); ++i) {
        const auto characters = header[kCompletionLengthsWord + i];
        const size_t n = static_cast<size_t>(characters) * kCompletionCharacterBytes;
        if (n > bytes - offset) throw ComponentError(L"Invalid completion snapshot string length.");
        (record.*kCompletionTextFields[i].member).assign(
            reinterpret_cast<const wchar_t*>(snapshot.data() + offset), characters);
        offset += n;
    }
    if (offset != bytes) throw ComponentError(L"Unexpected trailing completion snapshot data.");
    record.finished = (header[kCompletionFlagsWord] & kCompletionFinishedFlag) != 0;
    record.success = (header[kCompletionFlagsWord] & kCompletionSuccessFlag) != 0;
    return record;
}
void SetupStateStore::removeCompletion() const {
    checkRegistry(RegDeleteKeyExW(HKEY_LOCAL_MACHINE, kResultRegistryPath.c_str(), KEY_WOW64_64KEY, 0),
        L"Remove acknowledged result record");
}
}
