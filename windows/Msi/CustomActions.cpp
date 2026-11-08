#include "Platform.h"
#include "ActionPolicy.h"
#include "LegacySchema5.h"
#include "UserIntegration.h"
#include "MsiContract.h"
#include "../ProtectedStorage.h"
#include "../DesktopApp/DesktopApp.h"
#include "../Enrollment/EnrollmentSession.h"
#include "../SavedCredential/SavedCredentialVault.h"
#include <msiquery.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <set>
#include <cwctype>
#include <utility>

using namespace unlock::components;
using namespace unlock::components::msi;
namespace {
struct MsiHandle {
    MSIHANDLE value;
    explicit MsiHandle(MSIHANDLE h) : value(h) {}
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
std::wstring recordText(MSIHANDLE record, UINT field) {
    DWORD size = 0; wchar_t empty = 0;
    const auto result = MsiRecordGetStringW(record, field, &empty, &size);
    if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) msiCheck(result, L"Read MSI database field");
    std::wstring value(size + 1, L'\0'); ++size;
    msiCheck(MsiRecordGetStringW(record, field, value.data(), &size), L"Read MSI database field");
    value.resize(size); return value;
}
std::wstring pathKey(const std::filesystem::path& path) {
    auto text = path.lexically_normal().wstring();
    for (auto& character : text) character = towlower(character);
    return text;
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
    if (parts.size() != 4) fail(L"Invalid MSI action data.");
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
void copyTree(HKEY sourceRoot, const std::wstring& source, HKEY targetRoot, const std::wstring& target) {
    ScopedRegistryKey from, to;
    checkRegistry(RegOpenKeyExW(sourceRoot, source.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &from.value), L"Open deployment registry snapshot source");
    checkRegistry(RegCreateKeyExW(targetRoot, target.c_str(), 0, nullptr, 0,
        KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, &to.value, nullptr), L"Create deployment registry snapshot");
    checkRegistry(RegCopyTreeW(from.value, nullptr, to.value), L"Copy deployment registry snapshot");
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
    for (const auto& component : kComponentFiles) {
        auto path = ((component.desktopTool ? desktopDirectory() : system32Directory()) / component.name).wstring();
        for (auto& c : path) c = towlower(c);
        if (list.find(path) != std::wstring::npos) return true;
    }
    auto desktop = desktopDirectory().wstring();
    for (auto& c : desktop) c = towlower(c);
    return list.find(desktop + L"\\") != std::wstring::npos || registryKeyExists(kRebootKey);
}
void addLegacyRemovals(MSIHANDLE install, const LegacyInstallation& legacy) {
    MsiHandle database(MsiGetActiveDatabase(install));
    MSIHANDLE raw = 0;
    msiCheck(MsiDatabaseOpenViewW(database.value,
        L"SELECT `File`.`FileName`,`Component`.`Directory_` FROM `File`,`Component` WHERE `File`.`Component_`=`Component`.`Component`", &raw), L"Read incoming MSI file ownership");
    MsiHandle incoming(raw);
    msiCheck(MsiViewExecute(incoming.value, 0), L"Read incoming MSI file ownership");
    std::set<std::wstring> incomingPaths;
    for (;;) {
        MSIHANDLE row = 0; const auto result = MsiViewFetch(incoming.value, &row);
        if (result == ERROR_NO_MORE_ITEMS) break;
        msiCheck(result, L"Read incoming MSI file row");
        MsiHandle record(row);
        auto name = recordText(row, 1);
        if (const auto separator = name.find(L'|'); separator != std::wstring::npos) name.erase(0, separator + 1);
        const auto directory = property(install, recordText(row, 2).c_str());
        if (directory.empty()) fail(L"An incoming MSI target directory is unresolved.");
        incomingPaths.insert(pathKey(std::filesystem::path(directory) / name));
    }
    msiCheck(MsiDatabaseOpenViewW(database.value,
        L"INSERT INTO `RemoveFile` (`FileKey`,`Component_`,`FileName`,`DirProperty`,`InstallMode`) VALUES (?,?,?,?,?) TEMPORARY", &raw), L"Prepare legacy file ownership");
    MsiHandle view(raw);
    size_t index = 0;
    for (const auto& file : legacy.files) {
        const auto path = legacyTarget(file);
        if (incomingPaths.contains(pathKey(path))) continue; // MSI replaces and owns current payload files.
        const auto id = L"LegacyFile" + std::to_wstring(index);
        const auto directory = L"LEGACYDIR" + std::to_wstring(index++);
        set(install, directory.c_str(), path.parent_path().wstring() + L"\\");
        MsiHandle record(MsiCreateRecord(5));
        MsiRecordSetStringW(record.value, 1, id.c_str());
        MsiRecordSetStringW(record.value, 2, L"MachineIdentity");
        MsiRecordSetStringW(record.value, 3, path.filename().c_str());
        MsiRecordSetStringW(record.value, 4, directory.c_str());
        MsiRecordSetInteger(record.value, 5, 1);
        msiCheck(MsiViewExecute(view.value, record.value), L"Adopt legacy file into MSI transaction");
    }
}
void backupLegacy(const LegacyInstallation& legacy) {
    if (std::filesystem::exists(backupRoot()) || registryKeyExists(backupKey().c_str()))
        fail(L"A migration recovery snapshot already exists. No deployment resources were modified.");
    unlock_windows::storage::ensureProtectedDirectory(productDataDirectory(), true);
    unlock_windows::storage::ensureProtectedDirectory(backupRoot(), true);
    // Ready is written last. A partial snapshot never authorizes restoring over a deployment.
    for (const auto& file : legacy.files) {
        const auto target = backupRoot() / (file.desktopTool ? L"desktop" : L"system") / file.name;
        std::filesystem::create_directories(target.parent_path());
        checkWin32(CopyFileW(legacyTarget(file).c_str(), target.c_str(), TRUE), L"Back up legacy deployment file");
    }
    checkWin32(CopyFileW(startMenuShortcut().c_str(), (backupRoot() / L"shortcut.lnk").c_str(), TRUE), L"Back up legacy shortcut");
    const auto keys = deploymentRegistryKeys();
    for (size_t i = 0; i < keys.size(); ++i) {
        if (!registryKeyExists(keys[i].c_str())) continue;
        copyTree(HKEY_LOCAL_MACHINE, keys[i], HKEY_LOCAL_MACHINE, backupKey() + L"\\" + std::to_wstring(i));
    }
    copyTree(HKEY_LOCAL_MACHINE, std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") +
        unlock_windows::saved_credential::kServiceName, HKEY_LOCAL_MACHINE, backupKey() + L"\\Service");
    writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"WasRunning", serviceRunning());
    writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"Ready", 1);
}
void clearBackup() {
    if (std::filesystem::exists(backupRoot())) {
        unlock_windows::storage::ensureProtectedDirectory(backupRoot(), false);
        // Snapshot paths are installer-owned; reject junctions rather than traversing them.
        for (const auto& entry : std::filesystem::recursive_directory_iterator(backupRoot()))
            if (GetFileAttributesW(entry.path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT) fail(L"Unsafe migration snapshot path.");
        std::filesystem::remove_all(backupRoot());
    }
    deleteRegistryTree(HKEY_LOCAL_MACHINE, backupKey().c_str());
}
void restoreLegacy(MSIHANDLE install) {
    if (readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"Ready") != 1) {
        // MSI rolls its own service controls back. Only undo a native start or
        // reset the removal-only state when a clear request may have reached it.
        const bool wasRunning = readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"WasRunning") == 1;
        if (!wasRunning && readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"StartedService") == 1)
            stopServiceNormally();
        if (wasRunning && readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"ClearAttempted") == 1 && !pendingReplacement())
            startService();
        clearBackup(); return; // Preparation failed before any deployment mutation.
    }
    if (readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"ResourcesChanged") != 1) {
        clearBackup(); return;
    }
    unlock_windows::storage::ensureProtectedDirectory(backupRoot(), false);
    const auto setup = backupRoot() / L"desktop" / kInstallerFile;
    const auto files = readLegacyManifest(setup);
    bool reboot = false;
    for (const auto& file : files) {
        const auto source = backupRoot() / (file.desktopTool ? L"desktop" : L"system") / file.name;
        const auto target = legacyTarget(file);
        std::filesystem::create_directories(target.parent_path());
        if (!CopyFileW(source.c_str(), target.c_str(), FALSE)) {
            const auto error = GetLastError();
            if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED) checkWin32(FALSE, L"Restore legacy file");
            const auto restore = target.wstring() + L".msirollback";
            checkWin32(CopyFileW(source.c_str(), restore.c_str(), TRUE), L"Stage legacy rollback replacement");
            checkWin32(MoveFileExW(restore.c_str(), target.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING), L"Schedule legacy file restoration");
            reboot = true;
        }
    }
    const auto keys = deploymentRegistryKeys();
    for (size_t i = 0; i < keys.size(); ++i) {
        deleteRegistryTree(HKEY_LOCAL_MACHINE, keys[i].c_str());
        const auto snapshot = backupKey() + L"\\" + std::to_wstring(i);
        if (registryKeyExists(snapshot.c_str())) copyTree(HKEY_LOCAL_MACHINE, snapshot, HKEY_LOCAL_MACHINE, keys[i]);
    }
    checkWin32(CopyFileW((backupRoot() / L"shortcut.lnk").c_str(), startMenuShortcut().c_str(), FALSE), L"Restore legacy shortcut");
    // MSI may remove an adopted service during rollback. Recreate through SCM, then restore its saved configuration.
    auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!manager) fail(L"Cannot restore legacy service manager.");
    auto service = OpenServiceW(manager, unlock_windows::saved_credential::kServiceName, SERVICE_CHANGE_CONFIG);
    const auto image = L"\"" + (system32Directory() / kSavedCredentialServiceFile).wstring() + L"\"";
    if (!service && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
        service = CreateServiceW(manager, unlock_windows::saved_credential::kServiceName,
            unlock_windows::saved_credential::kServiceDisplayName, SERVICE_CHANGE_CONFIG, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, image.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr);
    const bool restored = service && ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, image.c_str(), nullptr, nullptr, L"", L"LocalSystem", nullptr, nullptr);
    if (service) CloseServiceHandle(service); CloseServiceHandle(manager);
    if (!restored) fail(L"Cannot restore the legacy service. Recovery snapshot retained.");
    copyTree(HKEY_LOCAL_MACHINE, backupKey() + L"\\Service", HKEY_LOCAL_MACHINE,
        std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + unlock_windows::saved_credential::kServiceName);
    if (reboot) {
        markReboot(install);
        message(install, L"Migration rolled back. Restart Windows to finish restoring occupied legacy files.");
        clearBackup();
    } else {
        if (readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"WasRunning") == 1) startService();
        clearBackup();
    }
}
std::wstring deferredSid(MSIHANDLE install) {
    const auto sid = actionData(install)[1];
    validateTargetSid(sid); return sid;
}
bool launchAsTarget(const std::wstring& sid, const std::filesystem::path& executable,
    const std::wstring& arguments, bool wait) {
    const DWORD session = WTSGetActiveConsoleSessionId();
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
    HMODULE module = nullptr;
    checkWin32(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&stopTargetTray), &module), L"Locate native action module");
    std::wstring path(32768, L'\0');
    const auto size = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size >= path.size()) fail(L"Cannot locate native action image.");
    path.resize(size);
    const auto helper = backupRoot() / kCustomActionFile;
    checkWin32(CopyFileW(path.c_str(), helper.c_str(), TRUE), L"Stage normal-exit module");
    const auto arguments = L"\"" + helper.wstring() + L"\",RequestUserExit " + sid;
    (void)launchAsTarget(sid, system32Directory() / L"rundll32.exe", arguments, true);
    checkWin32(DeleteFileW(helper.c_str()), L"Release normal-exit module");
    // Confirm all installed app instances are gone, including when the target is absent.
    stopTray(sid);
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

extern "C" __declspec(dllexport) UINT __stdcall ValidateDeployment(MSIHANDLE install) {
    return action(install, [&] {
        SYSTEM_INFO native{}; GetNativeSystemInfo(&native);
#if defined(_M_ARM64)
        constexpr WORD expected = PROCESSOR_ARCHITECTURE_ARM64;
#else
        constexpr WORD expected = PROCESSOR_ARCHITECTURE_AMD64;
#endif
        if (native.wProcessorArchitecture != expected) fail(L"Use the MSI matching the native Windows architecture.");
        const bool removing = property(install, L"REMOVE") == L"ALL";
        const bool upgrading = !property(install, L"UPGRADINGPRODUCTCODE").empty();
        const bool installed = !property(install, L"Installed").empty();
        if (registryKeyExists(kRebootKey)) fail(L"Restart Windows to complete the preceding component replacement before maintenance.");
        if (registryKeyExists(kMaintenanceKey)) fail(L"MSI maintenance is active or interrupted. Complete it or restart Windows before retrying.");
        const auto legacy = readLegacyInstallation();
        const bool existing = registryKeyExists(kInstalledProductRegistryPath);
        if ((installed || !property(install, L"WIX_UPGRADE_DETECTED").empty()) && !existing)
            fail(L"The configured product identity is missing. Maintenance cannot choose a replacement user.");
        if (existing && !legacy) {
            const auto code = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kMsiProductCodeValueName).value_or(L"");
            if (MsiQueryProductStateW(code.c_str()) != INSTALLSTATE_DEFAULT)
                fail(L"The MSI identity does not match a registered product. No changes were made.");
        }
        const auto op = operation(installed, removing, upgrading, existing);
        const auto sid = existing ? configuredSid() : consoleUserSid();
        validateTargetSid(sid);
        if (!removing && existing) {
            const auto text = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kInstalledVersionValueName).value_or(L"");
            const auto version = parseProductVersion(text);
            if (!version || version->text() != text || packageAction(kProductVersion, *version) == PackageAction::rejectDowngrade)
                fail(L"The installed four-part version is newer or invalid. No changes were made.");
        }
        if (std::filesystem::exists(backupRoot()) || registryKeyExists(backupKey().c_str()))
            fail(L"A migration recovery snapshot requires attention. No changes were made.");
        set(install, L"TARGETSID", sid);
        const auto data = std::to_wstring(static_cast<unsigned>(op)) + L"|" + sid + (legacy ? L"|1" : L"|0") + (serviceRunning() ? L"|1" : L"|0");
        for (const auto name : {L"PrepareDeployment", L"RollbackDeployment", L"CompleteDeployment", L"CommitDeployment", L"ClearForRemoval"}) set(install, name, data);
        if (legacy && !removing) addLegacyRemovals(install, *legacy);
    });
}
extern "C" __declspec(dllexport) UINT __stdcall PrepareDeployment(MSIHANDLE install) {
    return action(install, [&] {
        const auto sid = deferredSid(install);
        const auto data = actionData(install);
        ScopedHandle legacyMutex;
        if (data[2] == L"1") {
            legacyMutex.value = CreateMutexW(nullptr, FALSE, kLegacyOperationMutex);
            checkWin32(legacyMutex.value != nullptr, L"Open EXE installer operation lock");
            const auto acquired = WaitForSingleObject(legacyMutex.value, 0);
            if (acquired != WAIT_OBJECT_0 && acquired != WAIT_ABANDONED)
                fail(L"The original EXE installer is busy. Finish its operation before MSI takeover.");
        }
        struct ReleaseLock {
            HANDLE value;
            ~ReleaseLock() { if (value) ReleaseMutex(value); }
        } release{legacyMutex.value};
        const auto legacy = data[2] == L"1" ? readLegacyInstallation() : std::nullopt;
        if (data[2] == L"1" && !legacy) fail(L"EXE deployment changed before migration.");
        if (legacy && legacy->sid != sid) fail(L"Configured user changed during installation.");
        if (deferredOperation(install) == Operation::firstInstall && consoleUserSid() != sid) fail(L"Physical console user changed during installation.");
        if (deferredOperation(install) == Operation::firstInstall) {
            const auto vault = setupKnownFolder(FOLDERID_ProgramData) / unlock_windows::saved_credential::kVaultDirectoryName;
            if ((std::filesystem::exists(vault) && !std::filesystem::is_empty(vault)) ||
                fileExists(productDataDirectory() / unlock_windows::system_ble::kEnrollmentFileName))
                fail(L"Unowned credential or binding data exists. Use the original maintenance tool; no data was changed.");
        }
        if (legacy) backupLegacy(*legacy);
        else {
            unlock_windows::storage::ensureProtectedDirectory(productDataDirectory(), true);
            unlock_windows::storage::ensureProtectedDirectory(backupRoot(), true);
            writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"WasRunning", data[3] == L"1");
        }
        snapshotUser(sid);
        ScopedRegistryKey maintenance;
        checkRegistry(RegCreateKeyExW(HKEY_LOCAL_MACHINE, kMaintenanceKey, 0, nullptr, REG_OPTION_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY, nullptr, &maintenance.value, nullptr), L"Block app startup during maintenance");
        removeUserStartup(sid);
        stopTargetTray(sid);
        if (legacy) {
            writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"ResourcesChanged", 1);
            // The schema 5 app predates the maintenance guard. Retire its normal
            // entry until MSI installs the guarded app; the deployment snapshot restores it on rollback.
            checkWin32(MoveFileExW((desktopDirectory() / kMainAppFile).c_str(),
                (backupRoot() / L"LegacyMainApp.exe").c_str(), MOVEFILE_WRITE_THROUGH), L"Retire the schema 5 app entry during takeover");
            // Retire the EXE's authority while holding its operation mutex. Its
            // own revalidation rejects a record without schema 5; rollback restores it.
            ScopedRegistryKey identity;
            checkRegistry(RegOpenKeyExW(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, 0,
                KEY_SET_VALUE | KEY_WOW64_64KEY, &identity.value), L"Retire EXE installation ownership");
            checkRegistry(RegDeleteValueW(identity.value, kLegacySchemaValueName), L"Retire EXE schema ownership");
            deleteRegistryTree(HKEY_LOCAL_MACHINE, kLegacyUninstall);
            deleteRegistryTree(HKEY_LOCAL_MACHINE, kLegacyResult);
        }
    });
}
extern "C" __declspec(dllexport) UINT __stdcall RollbackDeployment(MSIHANDLE install) {
    return action(install, [&] {
        if (readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"ClearAttempted") == 1)
        {
            const bool confirmed = readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"Cleared") == 1;
            message(install, confirmed ? L"Removal failed after password and binding deletion. Deployment rollback cannot restore the deleted credentials."
                : L"Removal stopped without a complete clear acknowledgment. Data may already have been deleted; deployment rollback cannot restore deleted credentials.", INSTALLMESSAGE_WARNING);
            stopServiceNormally();
        }
        restoreUser(); restoreLegacy(install);
        deleteRegistryTree(HKEY_LOCAL_MACHINE, kMaintenanceKey);
    });
}
extern "C" __declspec(dllexport) UINT __stdcall ClearForRemoval(MSIHANDLE install) {
    return action(install, [&] {
        if (deferredOperation(install) != Operation::remove) fail(L"Credential deletion is permitted only for active uninstall.");
        if (configuredSid() != deferredSid(install)) fail(L"Configured user changed before removal.");
        unlock_windows::saved_credential::Packet reply;
        unlock_windows::saved_credential::CallDiagnostics diagnostics;
        writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"ClearAttempted", 1);
        const bool replied = unlock_windows::saved_credential::call(unlock_windows::saved_credential::Operation::clearForRemoval,
            unlock_windows::saved_credential::SensitiveBytes{}, reply,
            unlock_windows::saved_credential::kPipeTransferLifetimeMs, &diagnostics);
        using unlock_windows::saved_credential::CallStage;
        const bool notSent = !replied && (diagnostics.stage == CallStage::requestValidation ||
            diagnostics.stage == CallStage::waitForPipe || diagnostics.stage == CallStage::openPipe ||
            diagnostics.stage == CallStage::serverVerification);
        const bool rejected = replied && reply.result != unlock_windows::saved_credential::Result::success &&
            reply.result != unlock_windows::saved_credential::Result::internalError;
        if (notSent || rejected)
            writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"ClearAttempted", 0);
        const auto detail = L"clearForRemoval result=" + std::to_wstring(static_cast<unsigned>(reply.result)) +
            L" stage=" + unlock_windows::saved_credential::callStageName(diagnostics.stage) +
            L" Win32=" + std::to_wstring(diagnostics.win32Error);
        message(install, detail);
        if (!replied || reply.result != unlock_windows::saved_credential::Result::success)
            fail(L"The service did not confirm credential and binding deletion. Unlock the configured console and retry; the service must be running. " +
                std::wstring(notSent || rejected ? L"This request did not authorize removal. " : L"Data may already have been deleted and cannot be restored. ") + detail);
        message(install, L"Password and binding deletion confirmed. This deletion is irreversible; later MSI rollback cannot restore them.");
        writeRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"Cleared", 1);
        removeUserStartup(deferredSid(install));
        withUserHive(deferredSid(install), [](HKEY hive) {
            ScopedRegistryKey key;
            const auto opened = RegOpenKeyExW(hive, kProductRegistryPath, 0, KEY_SET_VALUE, &key.value);
            if (opened == ERROR_FILE_NOT_FOUND) return;
            checkRegistry(opened, L"Open user setup marker for removal");
            const auto removed = RegDeleteValueW(key.value, kSetupPromptValueName);
            if (removed != ERROR_FILE_NOT_FOUND) checkRegistry(removed, L"Remove user setup marker");
        });
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
        if (readRegistryDword(HKEY_LOCAL_MACHINE, backupKey().c_str(), L"Ready") == 1) {
            std::set<std::filesystem::path, std::greater<>> directories;
            for (const auto& file : readLegacyManifest(backupRoot() / L"desktop" / kInstallerFile)) {
                if (!file.desktopTool) continue;
                for (auto parent = std::filesystem::path(file.name).parent_path(); !parent.empty(); parent = parent.parent_path())
                    directories.insert(desktopDirectory() / parent);
            }
            directories.insert(productDataDirectory() / L"Setup" / L"Transactions");
            directories.insert(productDataDirectory() / L"Setup");
            for (const auto& directory : directories) {
                if (!std::filesystem::exists(directory)) continue;
                unlock_windows::storage::ensureProtectedDirectory(directory, false);
                if (std::filesystem::is_empty(directory)) checkWin32(RemoveDirectoryW(directory.c_str()), L"Remove superseded empty EXE directory");
            }
            for (const auto name : {kLegacySchemaValueName, kLegacyWizardPathValueName, kLegacyLastOperationIdValueName}) {
                ScopedRegistryKey key;
                checkRegistry(RegOpenKeyExW(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key.value), L"Open migrated installation record");
                const auto status = RegDeleteValueW(key.value, name);
                if (status != ERROR_FILE_NOT_FOUND) checkRegistry(status, L"Remove superseded EXE installation value");
            }
        }
        clearBackup();
        const auto op = deferredOperation(install);
        if (op != Operation::remove && op != Operation::upgradeRemoval && !pendingReplacement())
            (void)launchAsTarget(deferredSid(install), desktopDirectory() / kMainAppFile,
                op == Operation::firstInstall ? unlock_windows::desktop_app::kBackgroundRole
                    : unlock_windows::desktop_app::kRestoreTrayRole, false);
    });
    if (result != ERROR_SUCCESS) message(install, L"Machine deployment committed. Post-install cleanup or app launch needs attention; see the preceding error.", INSTALLMESSAGE_WARNING);
    return ERROR_SUCCESS;
}
