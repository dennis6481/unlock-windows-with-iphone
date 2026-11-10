#include "Platform.h"
#include "ActionPolicy.h"
#include "../CredentialProvider/UnlockCredentialProvider.h"
#include "UserIntegration.h"
#include "MsiContract.h"
#include "../ProtectedStorage.h"
#include "../DesktopApp/DesktopApp.h"
#include "../Enrollment/EnrollmentSession.h"
#include "../Enrollment/EnrollmentStore.h"
#include "../SavedCredential/SavedCredentialVault.h"
#include <msiquery.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <cwctype>
#include <utility>

using namespace unlock::components;
using namespace unlock::components::msi;
namespace {
struct MsiHandle {
    MSIHANDLE value;
    explicit MsiHandle(MSIHANDLE h = 0) : value(h) {}
    ~MsiHandle() { if (value) MsiCloseHandle(value); }
};
void msiCheck(UINT result, const wchar_t* action) {
    if (result != ERROR_SUCCESS) fail(std::wstring(action) + L" (MSI=" + std::to_wstring(result) + L")");
}
std::wstring property(MSIHANDLE install, const wchar_t* name) {
    DWORD size = 0; wchar_t empty = 0;
    const auto result = MsiGetPropertyW(install, name, &empty, &size);
    if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) msiCheck(result, L"Read MSI property");
    std::wstring value(size + 1, L'\0'); ++size;
    msiCheck(MsiGetPropertyW(install, name, value.data(), &size), L"Read MSI property");
    value.resize(size); return value;
}
void set(MSIHANDLE install, const wchar_t* name, const std::wstring& value) {
    msiCheck(MsiSetPropertyW(install, name, value.c_str()), L"Set MSI property");
}
void message(MSIHANDLE install, const std::wstring& text, INSTALLMESSAGE kind = INSTALLMESSAGE_INFO) {
    MsiHandle record(MsiCreateRecord(1));
    MsiRecordSetStringW(record.value, 0, L"[1]");
    MsiRecordSetStringW(record.value, 1, text.c_str());
    MsiProcessMessage(install, kind, record.value);
}
template<class Work> UINT action(MSIHANDLE install, Work work) noexcept {
    try { work(); return ERROR_SUCCESS; }
    catch (const winrt::hresult_error& error) {
        message(install, std::wstring(error.message().c_str()) + L" (HRESULT=" +
            std::to_wstring(static_cast<unsigned long>(error.code().value)) + L")", INSTALLMESSAGE_ERROR);
        return ERROR_INSTALL_FAILURE;
    }
    catch (const std::exception& error) {
        message(install, setupErrorText(error), INSTALLMESSAGE_ERROR); return ERROR_INSTALL_FAILURE;
    } catch (...) {
        message(install, L"Unexpected native MSI action failure.", INSTALLMESSAGE_ERROR); return ERROR_INSTALL_FAILURE;
    }
}
void validateNoExeInstallation(bool existing) {
    if (registryKeyExists(L"SOFTWARE\\UnlockWithIPhone\\ComponentsWizard") ||
        registryKeyExists(L"SOFTWARE\\UnlockWithIPhone\\ComponentResult") ||
        registryKeyExists(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\UnlockWithIPhone") ||
        (existing && readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kDeploymentKindValueName) != L"MSI") ||
        fileExists(productDirectory() / L"setup.exe"))
        fail(L"This package cannot upgrade the currently installed version. Uninstall Unlock with iPhone in Windows Settings > Apps, "
            L"then run this package again.\n\nYou will need to save your Windows password and bind your iPhone again.");
}
std::filesystem::path backupRoot() { return productDataDirectory() / L"MsiRollback"; }
std::wstring backupKey() { return std::wstring(kProductRegistryPath) + L"\\MsiRollback"; }

std::wstring configuredSid() {
    std::wstring sid; checkHresult(readSetupTargetSid(sid), L"Read configured product identity"); return sid;
}
std::vector<std::wstring> actionData(MSIHANDLE install) {
    const auto text = property(install, L"CustomActionData");
    std::vector<std::wstring> parts;
    size_t start = 0;
    for (;;) {
        const auto end = text.find(L'|', start);
        parts.push_back(text.substr(start, end == std::wstring::npos ? end : end - start));
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    if (parts.size() != 3) fail(L"Invalid MSI action data.");
    return parts;
}
Operation deferredOperation(MSIHANDLE install) {
    const auto value = std::stoul(actionData(install)[0]);
    if (value > static_cast<unsigned>(Operation::remove)) fail(L"Invalid MSI operation.");
    return static_cast<Operation>(value);
}
void snapshotUser(const std::wstring& sid) {
    withUserHive(sid, [&](HKEY hive) {
        for (const auto& item : {std::pair{kStartupRegistryPath, kDesktopDirectoryName},
            std::pair{kProductRegistryPath, kSetupPromptValueName}}) {
            const auto value = readRegistryValue(hive, item.first, item.second);
            if (value) writeRegistryValue(HKEY_LOCAL_MACHINE, backupKey().c_str(), item.second, value->type, value->bytes);
        }
    });
    writeRegistryString(HKEY_LOCAL_MACHINE, backupKey().c_str(), kTargetSidValueName, sid);
    writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"UserReady", 1);
}
void restoreStartup(const std::wstring& sid) {
    const auto value = readRegistryValue(HKEY_LOCAL_MACHINE, backupKey().c_str(), kDesktopDirectoryName);
    if (value) withUserHive(sid, [&](HKEY hive) {
        writeRegistryValue(hive, kStartupRegistryPath, kDesktopDirectoryName, value->type, value->bytes);
    });
}
void restoreUser() {
    if (readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"UserReady") != 1) return;
    const auto sid = readRegistryString(HKEY_LOCAL_MACHINE, backupKey().c_str(), kTargetSidValueName).value_or(L"");
    withUserHive(sid, [&](HKEY hive) {
        for (const auto& item : {std::pair{kStartupRegistryPath, kDesktopDirectoryName},
            std::pair{kProductRegistryPath, kSetupPromptValueName}}) {
            const auto value = readRegistryValue(HKEY_LOCAL_MACHINE, backupKey().c_str(), item.second);
            if (value) writeRegistryValue(hive, item.first, item.second, value->type, value->bytes);
            else {
                ScopedRegistryKey key;
                const auto opened = RegOpenKeyExW(hive, item.first, 0, KEY_SET_VALUE, &key.value);
                if (opened == ERROR_FILE_NOT_FOUND) continue;
                checkRegistry(opened, L"Open user registry rollback");
                const auto deleted = RegDeleteValueW(key.value, item.second);
                if (deleted != ERROR_FILE_NOT_FOUND) checkRegistry(deleted, L"Restore user registry absence");
            }
        }
    });
}
DWORD serviceState() {
    auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) fail(L"Cannot inspect service manager.");
    auto service = OpenServiceW(manager, unlock_windows::saved_credential::kServiceName, SERVICE_QUERY_STATUS);
    const auto error = service ? ERROR_SUCCESS : GetLastError();
    SERVICE_STATUS_PROCESS state{}; DWORD bytes = 0;
    const bool queried = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&state), sizeof(state), &bytes);
    if (service) CloseServiceHandle(service); CloseServiceHandle(manager);
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) return SERVICE_STOPPED;
    if (error || !queried) fail(L"Cannot inspect the credential service.");
    return state.dwCurrentState;
}
bool serviceRunning() { return serviceState() == SERVICE_RUNNING; }
void startService() {
    auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) fail(L"Cannot open service manager.");
    auto service = OpenServiceW(manager, unlock_windows::saved_credential::kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
    const auto opened = service ? ERROR_SUCCESS : GetLastError();
    const bool started = service && StartServiceW(service, 0, nullptr);
    const auto error = started ? ERROR_SUCCESS : GetLastError();
    if (service) CloseServiceHandle(service); CloseServiceHandle(manager);
    if (opened || (error && error != ERROR_SERVICE_ALREADY_RUNNING)) fail(L"Cannot start the credential service.");
    for (int i = 0; i < 100; ++i) { if (serviceRunning()) return; Sleep(100); }
    fail(L"The credential service did not reach Running.");
}
void stopServiceNormally() {
    if (serviceState() == SERVICE_STOPPED) return;
    auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) fail(L"Cannot reopen service manager during rollback.");
    auto service = OpenServiceW(manager, unlock_windows::saved_credential::kServiceName, SERVICE_STOP);
    SERVICE_STATUS status{};
    const bool stopped = service && ControlService(service, SERVICE_CONTROL_STOP, &status);
    const auto error = stopped ? ERROR_SUCCESS : GetLastError();
    if (service) CloseServiceHandle(service); CloseServiceHandle(manager);
    if (!stopped && error != ERROR_SERVICE_NOT_ACTIVE) fail(L"Cannot restore service stop state during rollback.");
    for (int i = 0; i < 100; ++i) { if (serviceState() == SERVICE_STOPPED) return; Sleep(100); }
    fail(L"Service did not stop during rollback; restart Windows before configuring credentials again.");
}
void markReboot(MSIHANDLE install) {
    ScopedRegistryKey key;
    checkRegistry(RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRebootKey, 0, nullptr, REG_OPTION_VOLATILE,
        KEY_WRITE | KEY_WOW64_64KEY, nullptr, &key.value, nullptr), L"Establish reboot boundary");
    msiCheck(MsiSetMode(install, MSIRUNMODE_REBOOTATEND, TRUE), L"Report required reboot");
}
bool pendingReplacement() {
    // MSI schedules locked files here. The guard prevents a subsequent app launch before reboot.
    const auto raw = readRegistryValue(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"PendingFileRenameOperations");
    if (!raw) return registryKeyExists(kRebootKey);
    if (raw->type != REG_MULTI_SZ || raw->bytes.size() % sizeof(wchar_t)) fail(L"Invalid pending file rename list.");
    std::wstring list(reinterpret_cast<const wchar_t*>(raw->bytes.data()), raw->bytes.size() / sizeof(wchar_t));
    for (auto& c : list) c = towlower(c);
    auto directory = productDirectory().wstring();
    for (auto& c : directory) c = towlower(c);
    return list.find(directory + L"\\") != std::wstring::npos || registryKeyExists(kRebootKey);
}
void clearBackup() {
    if (std::filesystem::exists(backupRoot())) {
        unlock_windows::storage::ensureProtectedDirectory(backupRoot(), false);
        const auto helper = backupRoot() / kCustomActionFile;
        if (fileExists(helper)) checkWin32(DeleteFileW(helper.c_str()), L"Remove normal-exit module");
        checkWin32(RemoveDirectoryW(backupRoot().c_str()), L"Remove MSI rollback directory");
    }
    deleteRegistryTree(HKEY_LOCAL_MACHINE, backupKey().c_str());
}
void restoreServiceState() {
    // MSI rolls its own service controls back. Undo a native post-install start.
    const bool wasRunning = readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"WasRunning") == 1;
    if (!wasRunning && readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"StartedService") == 1)
        stopServiceNormally();
}
std::wstring deferredSid(MSIHANDLE install) {
    const auto sid = actionData(install)[1];
    validateTargetSid(sid); return sid;
}
bool launchAsTarget(const std::wstring& sid, const std::filesystem::path& executable,
    const std::wstring& arguments, bool wait, DWORD session = WTSGetActiveConsoleSessionId()) {
    if (session == 0xffffffff) return false;
    ScopedHandle token;
    if (!WTSQueryUserToken(session, &token.value)) {
        if (GetLastError() == ERROR_NO_TOKEN) return false;
        checkWin32(FALSE, L"Read target-user launch token");
    }
    if (tokenSid(token.value) != sid) return false;
    DWORD bytes = 0;
    TOKEN_ELEVATION_TYPE elevation{};
    checkWin32(GetTokenInformation(token.value, TokenElevationType, &elevation, sizeof(elevation), &bytes), L"Read launch elevation");
    ScopedHandle linked;
    HANDLE ordinary = token.value;
    if (elevation == TokenElevationTypeFull) {
        TOKEN_LINKED_TOKEN value{};
        checkWin32(GetTokenInformation(token.value, TokenLinkedToken, &value, sizeof(value), &bytes), L"Get ordinary user token");
        linked.value = value.LinkedToken; ordinary = linked.value;
    }
    TOKEN_ELEVATION elevated{};
    checkWin32(GetTokenInformation(ordinary, TokenElevation, &elevated, sizeof(elevated), &bytes), L"Verify ordinary launch token");
    if (elevated.TokenIsElevated) fail(L"No ordinary target-user token is available; start the app manually without elevation.");
    void* environment = nullptr; checkWin32(CreateEnvironmentBlock(&environment, ordinary, FALSE), L"Create user environment");
    auto command = L"\"" + executable.wstring() + L"\" " + arguments;
    STARTUPINFOW startup{sizeof(startup)}; startup.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    PROCESS_INFORMATION process{};
    const BOOL started = CreateProcessAsUserW(ordinary, executable.c_str(), command.data(),
        nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, environment, executable.parent_path().c_str(), &startup, &process);
    const auto error = started ? ERROR_SUCCESS : GetLastError(); DestroyEnvironmentBlock(environment);
    if (!started) { SetLastError(error); checkWin32(FALSE, L"Start ordinary target-user process"); }
    ScopedHandle thread(process.hThread), owner(process.hProcess);
    if (wait) {
        // The normal-exit implementation has bounded waits for each retained app process.
        checkWin32(WaitForSingleObject(owner.value, INFINITE) == WAIT_OBJECT_0, L"Wait for target-user normal exit");
        DWORD result = 0; checkWin32(GetExitCodeProcess(owner.value, &result), L"Read normal-exit result");
        if (result != ERROR_SUCCESS) fail(L"Target-user normal exit failed (code=" + std::to_wstring(result) +
            L"). Close any password or enrollment window and retry. No process was killed.");
    }
    return true;
}
void stopTargetTray(const std::wstring& sid) {
    if (!mainInstancesPresent()) return;
    // MSI runs in session 0. A short-lived ordinary-user host is necessary to
    // enumerate the target desktop; impersonating its token does not change sessions.
    HMODULE actionModule = nullptr;
    checkWin32(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&stopTargetTray), &actionModule), L"Locate native action module");
    std::wstring path(32768, L'\0');
    const auto size = GetModuleFileNameW(actionModule, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size >= path.size()) fail(L"Cannot locate native action image.");
    path.resize(size);
    const auto helper = backupRoot() / kCustomActionFile;
    checkWin32(CopyFileW(path.c_str(), helper.c_str(), TRUE), L"Stage normal-exit module");
    const auto arguments = L"\"" + helper.wstring() + L"\",RequestUserExit " + sid;
    for (const auto session : mainInstanceSessions(sid)) {
        if (!launchAsTarget(sid, system32Directory() / L"rundll32.exe", arguments, true, session))
            fail(L"The app session has no target-user token. Close the app before maintenance.");
    }
    checkWin32(DeleteFileW(helper.c_str()), L"Release normal-exit module");
    // Confirm all installed app instances are gone, including when the target is absent.
    if (mainInstancesPresent()) fail(L"An installed app instance is still running. Close it before maintenance. No process was killed.");
}
}

extern "C" __declspec(dllexport) void CALLBACK RequestUserExit(HWND, HINSTANCE, LPSTR arguments, int) {
    try {
        if (!arguments) fail(L"Missing normal-exit identity.");
        const std::string text(arguments);
        const std::wstring sid(text.begin(), text.end());
        validateTargetSid(sid);
        if (unlock_windows::enrollment::elevatedAdmin()) fail(L"Normal-exit host must use the ordinary user token.");
        if (processSid(GetCurrentProcess()) != sid) fail(L"Normal-exit user differs from target.");
        stopTray(sid);
        ExitProcess(ERROR_SUCCESS);
    } catch (const std::exception& error) {
        OutputDebugStringW(setupErrorText(error).c_str());
        ExitProcess(ERROR_INSTALL_FAILURE);
    } catch (...) { ExitProcess(ERROR_INSTALL_FAILURE); }
}

extern "C" __declspec(dllexport) UINT __stdcall CheckExeInstallation(MSIHANDLE install) {
    return action(install, [&] {
        validateNoExeInstallation(registryKeyExists(kInstalledProductRegistryPath));
    });
}

extern "C" __declspec(dllexport) UINT __stdcall ValidateDeployment(MSIHANDLE install) {
    return action(install, [&] {
        SYSTEM_INFO native{}; GetNativeSystemInfo(&native);
#if defined(_M_ARM64)
        constexpr WORD expected = PROCESSOR_ARCHITECTURE_ARM64;
#else
        constexpr WORD expected = PROCESSOR_ARCHITECTURE_AMD64;
#endif
        if (native.wProcessorArchitecture != expected) fail(L"Use the MSI matching the native Windows architecture.");
        const bool installed = !property(install, L"Installed").empty();
        // The incoming MSI owns maintenance across the major-upgrade transaction.
        if (!property(install, L"UPGRADINGPRODUCTCODE").empty()) return;
        if (registryKeyExists(kRebootKey)) fail(L"Restart Windows to complete the preceding component replacement before maintenance.");
        if (registryKeyExists(kMaintenanceKey)) fail(L"MSI maintenance is active or interrupted. Complete it or restart Windows before retrying.");
        const bool existing = registryKeyExists(kInstalledProductRegistryPath);
        if (!existing) {
            wchar_t clsid[39]{};
            if (!StringFromGUID2(unlock_windows::credential_provider::kUnlockCredentialProviderClsid, clsid, ARRAYSIZE(clsid)))
                fail(L"Cannot format Credential Provider CLSID.");
            const auto provider = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + clsid;
            const auto com = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + clsid;
            if (registryKeyExists(provider.c_str()) || registryKeyExists(com.c_str()))
                fail(L"Unowned Credential Provider registration exists. Use the original installer to remove it.");
            auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!manager) fail(L"Cannot inspect existing service registration.");
            auto service = OpenServiceW(manager, unlock_windows::saved_credential::kServiceName, SERVICE_QUERY_STATUS);
            const auto error = service ? ERROR_SUCCESS : GetLastError();
            if (service) CloseServiceHandle(service);
            CloseServiceHandle(manager);
            if (service || error != ERROR_SERVICE_DOES_NOT_EXIST)
                fail(L"Unowned or inaccessible product service exists. Use the original installer to remove it.");
            if (fileExists(startMenuShortcut()))
                fail(L"An unowned product shortcut exists. Use the original installer to remove it.");
            for (const auto* component : kComponentFiles)
                if (fileExists(productDirectory() / component))
                    fail(L"Unowned product files exist. Use the original installer to remove them.");
        }
        if ((installed || !property(install, L"WIX_UPGRADE_DETECTED").empty()) && !existing)
            fail(L"The configured product identity is missing. Maintenance cannot choose a replacement user.");
        if (existing) {
            const auto code = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kMsiProductCodeValueName).value_or(L"");
            if (MsiQueryProductStateW(code.c_str()) != INSTALLSTATE_DEFAULT)
                fail(L"The MSI identity does not match a registered product. No changes were made.");
        }
        const auto sid = existing ? configuredSid() : consoleUserSid();
        validateTargetSid(sid);
        if (std::filesystem::exists(backupRoot()) || registryKeyExists(backupKey().c_str()))
            fail(L"An unfinished MSI rollback requires attention. No changes were made.");
        set(install, L"TARGETSID", sid);
    });
}
extern "C" __declspec(dllexport) UINT __stdcall InitializeDeployment(MSIHANDLE install) {
    return action(install, [&] {
        // REMOVE is not guaranteed to be ALL until InstallValidate has completed.
        const bool removing = property(install, L"REMOVE") == L"ALL";
        const bool installed = !property(install, L"Installed").empty();
        const bool existing = registryKeyExists(kInstalledProductRegistryPath);
        const auto op = operation(installed, removing, existing);
        const auto sid = property(install, L"TARGETSID");
        if (!removing && existing) {
            const auto text = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kInstalledVersionValueName).value_or(L"");
            const auto version = parseProductVersion(text);
            if (!version || version->text() != text || packageAction(kProductVersion, *version) == PackageAction::rejectDowngrade)
                fail(L"The installed four-part version is newer or invalid. No changes were made.");
        }
        const auto data = std::to_wstring(static_cast<unsigned>(op)) + L"|" + sid + (serviceRunning() ? L"|1" : L"|0");
        for (const auto name : {L"PrepareDeployment", L"RollbackDeployment", L"CompleteDeployment", L"CommitDeployment", L"RemoveProductData"}) set(install, name, data);
    });
}
extern "C" __declspec(dllexport) UINT __stdcall CloseApplication(MSIHANDLE install) {
    return action(install, [&] {
        // Interactive immediate actions can reach the user's desktop before InstallValidate.
        // Silent maintenance retains the session-0 exit host in PrepareDeployment.
        stopTray(property(install, L"TARGETSID"));
    });
}
extern "C" __declspec(dllexport) UINT __stdcall PrepareDeployment(MSIHANDLE install) {
    return action(install, [&] {
        const auto sid = deferredSid(install);
        const auto data = actionData(install);
        if (deferredOperation(install) == Operation::firstInstall && consoleUserSid() != sid) fail(L"Physical console user changed during installation.");
        if (deferredOperation(install) == Operation::firstInstall) {
            const auto vault = productDataDirectory() / unlock_windows::saved_credential::kVaultDirectoryName;
            bool vaultHasData = false;
            const auto attributes = GetFileAttributesW(vault.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                unlock_windows::storage::verifyProtectedPath(vault, true);
                vaultHasData = !std::filesystem::is_empty(vault);
            } else {
                const auto error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
                    fail(L"Cannot inspect saved credential directory: " + win32ErrorMessage(error));
            }
            if (vaultHasData ||
                fileExists(productDataDirectory() / unlock_windows::system_ble::kEnrollmentFileName))
                fail(L"Unowned credential or binding data exists. Use the original maintenance tool; no data was changed.");
        }
        unlock_windows::storage::ensureProtectedDirectory(productDataDirectory(), true);
        unlock_windows::storage::ensureProtectedDirectory(backupRoot(), true);
        writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"WasRunning", data[2] == L"1");
        snapshotUser(sid);
        ScopedRegistryKey maintenance;
        checkRegistry(RegCreateKeyExW(HKEY_LOCAL_MACHINE, kMaintenanceKey, 0, nullptr, REG_OPTION_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY, nullptr, &maintenance.value, nullptr), L"Block app startup during maintenance");
        removeUserStartup(sid);
        stopTargetTray(sid);
    });
}
extern "C" __declspec(dllexport) UINT __stdcall RollbackDeployment(MSIHANDLE install) {
    return action(install, [&] {
        if (readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"DataDeletionStarted") == 1)
        {
            const bool confirmed = readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"DataDeletionCompleted") == 1;
            message(install, confirmed ? L"Removal failed after password and binding deletion. Deployment rollback cannot restore the deleted credentials."
                : L"Removal failed during data deletion. Password or binding data may have been deleted; deployment rollback cannot restore them. Configure the product again before use.", INSTALLMESSAGE_WARNING);
        }
        restoreUser(); restoreServiceState();
        clearBackup();
        deleteRegistryTree(HKEY_LOCAL_MACHINE, kMaintenanceKey);
    });
}
extern "C" __declspec(dllexport) UINT __stdcall RemoveProductData(MSIHANDLE install) {
    return action(install, [&] {
        if (deferredOperation(install) != Operation::remove) fail(L"Credential deletion is permitted only for active uninstall.");
        if (configuredSid() != deferredSid(install)) fail(L"Configured user changed before removal.");
        withUserHive(deferredSid(install), [](HKEY hive) {
            ScopedRegistryKey key;
            const auto opened = RegOpenKeyExW(hive, kProductRegistryPath, 0, KEY_SET_VALUE, &key.value);
            if (opened == ERROR_FILE_NOT_FOUND) return;
            checkRegistry(opened, L"Open user setup marker for removal");
            const auto removed = RegDeleteValueW(key.value, kSetupPromptValueName);
            if (removed != ERROR_FILE_NOT_FOUND) checkRegistry(removed, L"Remove user setup marker");
        });
        if (serviceState() != SERVICE_STOPPED)
            fail(L"The credential service is not stopped. No password or binding data was deleted.");
        waitForServiceExit();
        if (serviceState() != SERVICE_STOPPED)
            fail(L"The credential service restarted. No password or binding data was deleted.");
        // Deletion is irreversible, including when a later MSI action rolls back.
        writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"DataDeletionStarted", 1);
        unlock_windows::saved_credential::Vault::clearStored();
        unlock_windows::system_ble::EnrollmentStore{}.remove();
        writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"DataDeletionCompleted", 1);
        message(install, L"Password and binding deletion confirmed. Later MSI rollback cannot restore these data.");
    });
}
extern "C" __declspec(dllexport) UINT __stdcall CompleteDeployment(MSIHANDLE install) {
    return action(install, [&] {
        const auto sid = deferredSid(install);
        if (configuredSid() != sid) fail(L"MSI product identity does not match the configured user.");
        if (deferredOperation(install) == Operation::firstInstall) {
            withUserHive(sid, [](HKEY hive) { writeRegistryDword(hive, kProductRegistryPath, kSetupPromptValueName, 1); });
            registerUserStartup(sid);
        } else restoreStartup(sid);
        if (pendingReplacement()) { markReboot(install); return; }
        writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"StartedService", 1);
        startService();
    });
}
extern "C" __declspec(dllexport) UINT __stdcall CommitDeployment(MSIHANDLE install) {
    // Commit/launch failures are reported separately: machine deployment has already succeeded.
    const auto result = action(install, [&] {
        if (pendingReplacement()) markReboot(install);
        deleteRegistryTree(HKEY_LOCAL_MACHINE, kMaintenanceKey);
        clearBackup();
        const auto op = deferredOperation(install);
        if (op != Operation::remove && !pendingReplacement())
            (void)launchAsTarget(deferredSid(install), productDirectory() / kMainAppFile,
                op == Operation::firstInstall ? unlock_windows::desktop_app::kBackgroundRole
                    : unlock_windows::desktop_app::kRestoreTrayRole, false);
    });
    if (result != ERROR_SUCCESS) message(install, L"Machine deployment committed. Post-install cleanup or app launch needs attention; see the preceding error.", INSTALLMESSAGE_WARNING);
    return ERROR_SUCCESS;
}
