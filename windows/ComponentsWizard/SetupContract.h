// Created by Rui MA on 04 Oct 2026

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace unlock::components {
inline constexpr std::uint32_t kWizardStateSchemaVersion = 6;

enum class WizardPhase : std::uint32_t {
    none = 0,
    installed = 2,
    uninstallPendingReboot = 3,
    cleaningUp = 4,
    updatePendingReboot = 6,
    updating = 7,
    installPendingReboot = 8,
    preparing = 9,
    finalizing = 10,
};
enum class SetupOperation : std::uint32_t { install = 0, update = 1, uninstall = 2 };

[[nodiscard]] constexpr bool isKnownPhase(std::uint32_t phase) noexcept {
    switch (static_cast<WizardPhase>(phase)) {
        case WizardPhase::none:
        case WizardPhase::installed:
        case WizardPhase::uninstallPendingReboot:
        case WizardPhase::cleaningUp:
        case WizardPhase::updatePendingReboot:
        case WizardPhase::updating:
        case WizardPhase::installPendingReboot:
        case WizardPhase::preparing:
        case WizardPhase::finalizing: return true;
        default: return false;
    }
}

inline constexpr wchar_t kDesktopDirectoryName[] = L"Unlock Windows with iPhone";
inline constexpr wchar_t kSetupDirectoryName[] = L"Setup";
inline constexpr wchar_t kTransactionsDirectoryName[] = L"Transactions";
inline constexpr wchar_t kProductRegistryPath[] = L"SOFTWARE\\UnlockWindowsWithIPhone";
inline constexpr wchar_t kCredentialProviderRegistryRoot[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers";
inline constexpr wchar_t kClsidRegistryRoot[] = L"SOFTWARE\\Classes\\CLSID";
inline constexpr wchar_t kWizardStateKeyName[] = L"ComponentsWizard";
inline constexpr wchar_t kInstalledProductKeyName[] = L"InstalledProduct";
inline constexpr wchar_t kResultKeyName[] = L"ComponentResult";
inline const std::wstring kWizardStateRegistryPath = std::wstring(kProductRegistryPath) + L"\\" + kWizardStateKeyName;
inline const std::wstring kInstalledProductRegistryPath = std::wstring(kProductRegistryPath) + L"\\" + kInstalledProductKeyName;
inline const std::wstring kResultRegistryPath = std::wstring(kProductRegistryPath) + L"\\" + kResultKeyName;
inline constexpr wchar_t kApplicationUninstallRegistryPath[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\UnlockWindowsWithIPhone";
inline const std::wstring kUpdateRebootGuard = kWizardStateRegistryPath + L"\\UpdateRebootGuard";

inline constexpr wchar_t kSchemaVersionValueName[] = L"SchemaVersion";
inline constexpr wchar_t kStatePhaseValueName[] = L"Phase";
inline constexpr wchar_t kStateTransactionIdValueName[] = L"TransactionId";
inline constexpr wchar_t kStateWizardPathValueName[] = L"WizardPath";
inline constexpr wchar_t kStateCreatedAtValueName[] = L"CreatedAtUtc";
inline constexpr wchar_t kStateLastErrorValueName[] = L"LastError";
inline constexpr wchar_t kTargetSidValueName[] = L"TargetSid";
inline constexpr wchar_t kCredentialCleanupValueName[] = L"CredentialCleanupConfirmed";
inline constexpr wchar_t kOperationValueName[] = L"Operation";
inline constexpr wchar_t kSourcePathValueName[] = L"SourcePath";
inline constexpr wchar_t kInstalledVersionValueName[] = L"InstalledVersion";
inline constexpr wchar_t kPackageVersionValueName[] = L"PackageVersion";
inline constexpr wchar_t kPayloadReadyValueName[] = L"PayloadReady";
inline constexpr wchar_t kLastOperationIdValueName[] = L"LastOperationId";
inline constexpr wchar_t kFilesReleasedValueName[] = L"FilesReleased";
inline constexpr wchar_t kSnapshotValueName[] = L"Snapshot";
inline constexpr wchar_t kResultMessageName[] = L"Message";
inline constexpr wchar_t kResultLogName[] = L"Log";
inline constexpr wchar_t kUninstallStringValueName[] = L"UninstallString";
inline constexpr wchar_t kDisplayIconValueName[] = L"DisplayIcon";
inline constexpr wchar_t kDisplayVersionValueName[] = L"DisplayVersion";

inline constexpr wchar_t kStartupRegistryPath[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
inline constexpr wchar_t kBootTask[] = L"UnlockWindowsWithIPhone-CompleteOperation";
inline constexpr wchar_t kResultTask[] = L"UnlockWindowsWithIPhone-ComponentResult";
inline constexpr wchar_t kFinalizeTask[] = L"UnlockWindowsWithIPhone-FinalizeOperation";
inline constexpr wchar_t kOperationMutex[] = L"Global\\UnlockWindowsWithIPhone-ComponentOperation";
inline constexpr wchar_t kResultEventPrefix[] = L"Global\\UnlockWindowsWithIPhone-SetupResult-";
inline constexpr wchar_t kResultCopiedEvent[] = L"Copied";
inline constexpr wchar_t kResultDoneEvent[] = L"Done";
inline constexpr wchar_t kResultFailedEvent[] = L"Failed";

struct CompletionRecord final {
    std::wstring transactionId;
    std::wstring targetSid;
    std::wstring message;
    std::wstring log;
    bool finished = false;
    bool success = false;
};
struct CompletionTextField final {
    const wchar_t* name;
    std::wstring CompletionRecord::*member;
};
inline constexpr std::array<CompletionTextField, 4> kCompletionTextFields{{
    {kStateTransactionIdValueName, &CompletionRecord::transactionId},
    {kTargetSidValueName, &CompletionRecord::targetSid},
    {kResultMessageName, &CompletionRecord::message},
    {kResultLogName, &CompletionRecord::log},
}};
inline constexpr std::uint32_t kCompletionVersion = 1;
inline constexpr std::uint32_t kCompletionFinishedFlag = 1;
inline constexpr std::uint32_t kCompletionSuccessFlag = 2;
inline constexpr std::uint32_t kCompletionMaximumBytes = 1048576;
inline constexpr std::uint32_t kCompletionVersionWord = 0;
inline constexpr std::uint32_t kCompletionFlagsWord = 1;
inline constexpr std::size_t kCompletionLengthsWord = kCompletionFlagsWord + 1;
inline constexpr std::size_t kCompletionHeaderWords = kCompletionLengthsWord + kCompletionTextFields.size();
inline constexpr std::size_t kCompletionWordBytes = sizeof(std::uint32_t);
inline constexpr std::size_t kCompletionCharacterBytes = sizeof(wchar_t);
inline constexpr std::uint32_t kCompletionFlags = kCompletionFinishedFlag | kCompletionSuccessFlag;
}
