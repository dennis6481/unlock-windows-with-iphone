// Created by Rui MA on 02 Oct 2026

#define UNICODE
#define _UNICODE
#include "WindowsAdapter.h"
#include "InstallationPaths.h"
#include "SetupFinalization.h"
#include "../PhoneApproval/EnrollmentStore.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <taskschd.h>
#include <shlobj.h>
#include <wrl/client.h>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace unlock::components {
namespace {
using Microsoft::WRL::ComPtr;

void win(BOOL ok, const std::wstring& text) {
    if (!ok) throw ComponentError(text + L" (Win32=" + std::to_wstring(GetLastError()) + L")");
}
void hr(HRESULT value, const std::wstring& text) {
    if (FAILED(value)) throw ComponentError(text + L" (HRESULT=" + std::to_wstring(static_cast<unsigned long>(value)) + L")");
}
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE handle = nullptr) : value(handle) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct Bstr {
    BSTR value;
    explicit Bstr(const std::wstring& s) : value(SysAllocString(s.c_str())) {
        if (!value) throw ComponentError(L"Out of memory allocating task text.");
    }
    ~Bstr() { SysFreeString(value); }
};
struct Com {
    HRESULT value = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    Com() { if (FAILED(value) && value != RPC_E_CHANGED_MODE) hr(value, L"Initialize COM"); }
    ~Com() { if (SUCCEEDED(value)) CoUninitialize(); }
};
struct Scheduler {
    Com apartment;
    ComPtr<ITaskService> service;
    ComPtr<ITaskFolder> root;
    Scheduler() {
        hr(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&service)), L"Create scheduler");
        VARIANT empty{}; VariantInit(&empty);
        hr(service->Connect(empty, empty, empty, empty), L"Connect scheduler");
        Bstr name(L"\\"); hr(service->GetFolder(name.value, &root), L"Open task folder");
    }
    ComPtr<IRegisteredTask> get(const wchar_t* name) {
        Bstr taskName(name); ComPtr<IRegisteredTask> task;
        HRESULT result = root->GetTask(taskName.value, &task);
        if (result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return {};
        hr(result, L"Read task " + std::wstring(name)); return task;
    }
    void remove(const wchar_t* name) {
        Bstr taskName(name);
        HRESULT result = root->DeleteTask(taskName.value, 0);
        if (result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) hr(result, L"Delete task " + std::wstring(name));
    }
};

void startResultTask(const WindowsAdapter& adapter) {
    Scheduler scheduler;
    const auto task = scheduler.get(kResultTask);
    if (!task) throw ComponentError(L"The registered user-result task is missing.");
    VARIANT empty{}; VariantInit(&empty); ComPtr<IRunningTask> running;
    const HRESULT result = task->Run(empty, &running);
    if (result == SCHED_E_USER_NOT_LOGGED_ON) {
        adapter.logOperation(L"The target user is not signed in; the result task waits for that user's next sign-in.");
        return;
    }
    hr(result, L"Start the registered ordinary-user result task");
}

std::filesystem::path systemDirectory() {
    std::array<wchar_t, 32768> path{};
    const UINT n = GetSystemDirectoryW(path.data(), static_cast<UINT>(path.size()));
    win(n && n < path.size(), L"Read System32 path"); return path.data();
}
std::wstring tokenSid(HANDLE token) {
    DWORD n = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &n);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) win(FALSE, L"Query token size");
    std::vector<BYTE> data(n);
    win(GetTokenInformation(token, TokenUser, data.data(), n, &n), L"Read token user");
    LPWSTR text = nullptr;
    win(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &text), L"Format SID");
    std::wstring result(text); LocalFree(text); return result;
}
std::wstring processSid(HANDLE process) {
    HANDLE raw = nullptr; win(OpenProcessToken(process, TOKEN_QUERY, &raw), L"Open process token");
    Handle token(raw); return tokenSid(token.value);
}
void validSid(const std::wstring& sid) {
    PSID binary = nullptr;
    win(ConvertStringSidToSidW(sid.c_str(), &binary), L"Validate target SID");
    const bool valid = IsValidSid(binary) != FALSE;
    LocalFree(binary);
    if (!valid || sid == L"S-1-5-18") throw ComponentError(L"A real console user is required.");
}
void registerTask(const wchar_t* name, const std::wstring& sid,
    const std::filesystem::path& executable, const std::wstring& arguments,
    bool system, bool notification) {
    validSid(sid);
    Scheduler scheduler; ComPtr<ITaskDefinition> definition;
    hr(scheduler.service->NewTask(0, &definition), L"Create task definition");
    ComPtr<IPrincipal> principal; hr(definition->get_Principal(&principal), L"Get principal");
    Bstr user(system ? L"S-1-5-18" : sid);
    hr(principal->put_UserId(user.value), L"Set task SID");
    const auto logon = system ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_INTERACTIVE_TOKEN;
    hr(principal->put_LogonType(logon), L"Set task logon");
    hr(principal->put_RunLevel(system ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA), L"Set task privilege");
    ComPtr<ITriggerCollection> triggers; hr(definition->get_Triggers(&triggers), L"Get triggers");
    ComPtr<ITrigger> trigger;
    hr(triggers->Create(system ? TASK_TRIGGER_BOOT : TASK_TRIGGER_LOGON, &trigger), L"Create trigger");
    Bstr unlimited(L"PT0S");
    hr(trigger->put_ExecutionTimeLimit(unlimited.value), L"Set unlimited trigger execution time");
    if (!system) {
        ComPtr<ILogonTrigger> login; hr(trigger.As(&login), L"Get logon trigger");
        hr(login->put_UserId(user.value), L"Bind logon trigger SID");
    }
    ComPtr<ITaskSettings> settings; hr(definition->get_Settings(&settings), L"Get settings");
    hr(settings->put_ExecutionTimeLimit(unlimited.value), L"Set unlimited running time");
    hr(settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE), L"Allow battery start");
    hr(settings->put_StopIfGoingOnBatteries(VARIANT_FALSE), L"Allow battery running");
    hr(settings->put_StartWhenAvailable(VARIANT_TRUE), L"Set start availability");
    hr(settings->put_MultipleInstances(wcscmp(name, kFinalizeTask) == 0 ? TASK_INSTANCES_QUEUE : TASK_INSTANCES_IGNORE_NEW), L"Set serialized task execution");
    hr(settings->put_AllowDemandStart(VARIANT_TRUE), L"Allow explicit scheduler startup");
    hr(settings->put_Enabled(VARIANT_TRUE), L"Enable registered task");
    ComPtr<IActionCollection> actions; hr(definition->get_Actions(&actions), L"Get actions");
    ComPtr<IAction> action; hr(actions->Create(TASK_ACTION_EXEC, &action), L"Create executable action");
    ComPtr<IExecAction> execution; hr(action.As(&execution), L"Get executable action");
    Bstr path(executable.wstring()), args(arguments), directory(executable.parent_path().wstring());
    hr(execution->put_Path(path.value), L"Set executable path");
    hr(execution->put_Arguments(args.value), L"Set arguments");
    hr(execution->put_WorkingDirectory(directory.value), L"Set working directory");
    Bstr taskName(name);
    Bstr security(wcscmp(name, kFinalizeTask) == 0
        ? L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;" + sid + L")"
        : notification
        ? L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGXSD;;;" + sid + L")"
        : L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;" + (system ? L"SY" : sid) + L")");
    VARIANT account{}, empty{}, acl{};
    VariantInit(&account); VariantInit(&empty); VariantInit(&acl);
    account.vt = VT_BSTR; account.bstrVal = user.value;
    acl.vt = VT_BSTR; acl.bstrVal = security.value;
    ComPtr<IRegisteredTask> registered;
    hr(scheduler.root->RegisterTaskDefinition(taskName.value, definition.Get(),
        TASK_CREATE_OR_UPDATE, account, empty, logon, acl, &registered), L"Register task " + std::wstring(name));
}

struct TraySearch {
    std::filesystem::path expected;
    std::wstring sid;
    DWORD session = 0;
    bool stop = false;
    bool found = false;
    std::wstring error;
};
std::vector<std::unique_ptr<Handle>> pinMainInstances(const std::filesystem::path& expected) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    win(snapshot.value != INVALID_HANDLE_VALUE, L"Enumerate main application processes");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<std::unique_ptr<Handle>> instances;
    BOOL found = Process32FirstW(snapshot.value, &entry);
    while (found) {
        if (_wcsicmp(entry.szExeFile, kMainAppFile) == 0) {
            auto process = std::make_unique<Handle>(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                FALSE, entry.th32ProcessID));
            win(process->value != nullptr, L"Pin main application instance");
            std::array<wchar_t, 32768> image{};
            DWORD size = static_cast<DWORD>(image.size());
            win(QueryFullProcessImageNameW(process->value, 0, image.data(), &size), L"Read main application image");
            if (_wcsicmp(image.data(), expected.c_str()) == 0) instances.push_back(std::move(process));
        }
        found = Process32NextW(snapshot.value, &entry);
    }
    if (GetLastError() != ERROR_NO_MORE_FILES) win(FALSE, L"Read main application process list");
    return instances;
}
BOOL CALLBACK visitTray(HWND window, LPARAM value) {
    auto& search = *reinterpret_cast<TraySearch*>(value);
    std::array<wchar_t, 128> name{};
    GetClassNameW(window, name.data(), static_cast<int>(name.size()));
    if (wcscmp(name.data(), L"UnlockWindowsWithIPhoneGattHost") != 0) return TRUE;
    try {
        DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        win(process.value != nullptr, L"Open Bluetooth tray process");
        DWORD session = 0; win(ProcessIdToSessionId(pid, &session), L"Read tray session");
        std::array<wchar_t, 32768> image{}; DWORD n = static_cast<DWORD>(image.size());
        win(QueryFullProcessImageNameW(process.value, 0, image.data(), &n), L"Read tray image");
        if (_wcsicmp(image.data(), search.expected.c_str()) != 0 || processSid(process.value) != search.sid)
            throw ComponentError(L"Bluetooth tray window does not match the installed image and target user.");
        if (session != search.session) {
            if (search.stop) throw ComponentError(L"Bluetooth tray is in a different console session. Operation paused.");
            return TRUE;
        }
        search.found = true;
        if (search.stop) {
            DWORD confirmed = 0; GetWindowThreadProcessId(window, &confirmed);
            if (confirmed != pid || WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT)
                throw ComponentError(L"Bluetooth tray ownership changed before shutdown.");
            win(PostMessageW(window, WM_CLOSE, 0, 0), L"Request normal Bluetooth tray exit");
            const DWORD waited = WaitForSingleObject(process.value, 30000);
            if (waited != WAIT_OBJECT_0) throw ComponentError(L"Bluetooth tray did not exit within 30 seconds. Operation paused; no process was killed.");
        }
    } catch (const ComponentError& error) { search.error = error.wideWhat(); return FALSE; }
    return TRUE;
}

struct Registry {
    HKEY value = nullptr;
    ~Registry() { if (value) RegCloseKey(value); }
};
void regCheck(LSTATUS status, const wchar_t* operation) {
    if (status != ERROR_SUCCESS) throw ComponentError(std::wstring(operation) + L" (Win32=" + std::to_wstring(status) + L")");
}
struct HivePrivilege {
    Handle token;
    TOKEN_PRIVILEGES previous{};
    bool changed = false;
    explicit HivePrivilege(const wchar_t* name) {
        win(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token.value), L"Open hive privilege token");
        TOKEN_PRIVILEGES requested{}; requested.PrivilegeCount = 1;
        win(LookupPrivilegeValueW(nullptr, name, &requested.Privileges[0].Luid), L"Look up hive privilege");
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD bytes = sizeof(previous);
        win(AdjustTokenPrivileges(token.value, FALSE, &requested, sizeof(previous), &previous, &bytes), L"Enable hive privilege");
        win(GetLastError() == ERROR_SUCCESS, L"Acquire hive privilege");
        changed = previous.PrivilegeCount != 0;
    }
    void restore() {
        if (!changed) return;
        win(AdjustTokenPrivileges(token.value, FALSE, &previous, 0, nullptr, nullptr), L"Restore hive privilege");
        win(GetLastError() == ERROR_SUCCESS, L"Restore hive privilege assignment");
        changed = false;
    }
    ~HivePrivilege() {
        if (changed && (!AdjustTokenPrivileges(token.value, FALSE, &previous, 0, nullptr, nullptr) || GetLastError() != ERROR_SUCCESS))
            OutputDebugStringW(L"Installer failed to restore registry hive privilege during exception cleanup.\n");
    }
};
void withUserHive(const std::wstring& sid, const std::function<void(HKEY)>& operation) {
    validSid(sid);
    Registry hive;
    LSTATUS status = RegOpenKeyExW(HKEY_USERS, sid.c_str(), 0, KEY_READ | KEY_WRITE, &hive.value);
    if (status == ERROR_SUCCESS) { operation(hive.value); return; }
    if (status != ERROR_FILE_NOT_FOUND) regCheck(status, L"Open target user registry hive");
    const auto profileKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid;
    std::array<wchar_t, 32768> profile{}; DWORD bytes = sizeof(profile);
    regCheck(RegGetValueW(HKEY_LOCAL_MACHINE, profileKey.c_str(), L"ProfileImagePath",
        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, profile.data(), &bytes), L"Read target user profile path");
    const auto file = std::filesystem::path(profile.data()) / L"NTUSER.DAT";
    if (!std::filesystem::is_regular_file(file)) throw ComponentError(L"Target user registry hive file is missing: " + file.wstring());
    HivePrivilege backup(SE_BACKUP_NAME), restore(SE_RESTORE_NAME);
    const auto mount = L"UnlockWindowsStartup-" + sid;
    regCheck(RegLoadKeyW(HKEY_USERS, mount.c_str(), file.c_str()), L"Load target user registry hive");
    try {
        regCheck(RegOpenKeyExW(HKEY_USERS, mount.c_str(), 0, KEY_READ | KEY_WRITE, &hive.value), L"Open loaded user registry hive");
        operation(hive.value);
    } catch (const std::exception& error) {
        const auto original = dynamic_cast<const ComponentError*>(&error);
        const std::wstring detail = original ? original->wideWhat() : L"Target user startup operation threw an exception.";
        if (hive.value) { RegCloseKey(hive.value); hive.value = nullptr; }
        const auto cleanup = RegUnLoadKeyW(HKEY_USERS, mount.c_str());
        if (cleanup != ERROR_SUCCESS) throw ComponentError(detail + L" Target hive unload also failed (Win32=" + std::to_wstring(cleanup) + L").");
        throw;
    } catch (...) {
        if (hive.value) { RegCloseKey(hive.value); hive.value = nullptr; }
        regCheck(RegUnLoadKeyW(HKEY_USERS, mount.c_str()), L"Unload target user hive after unknown startup exception");
        throw;
    }
    const auto closed = RegCloseKey(hive.value); hive.value = nullptr;
    regCheck(closed, L"Close loaded user registry hive");
    regCheck(RegUnLoadKeyW(HKEY_USERS, mount.c_str()), L"Unload target user registry hive");
    restore.restore(); backup.restore();
}
std::wstring startupCommand() { return L"\"" + (desktopDirectory() / kMainAppFile).wstring() + L"\""; }
void removeUserStartup(const std::wstring& sid) {
    withUserHive(sid, [](HKEY hive) {
        Registry key;
        LSTATUS status = RegOpenKeyExW(hive, kStartupRegistryPath, 0, KEY_SET_VALUE, &key.value);
        if (status == ERROR_FILE_NOT_FOUND) return;
        regCheck(status, L"Open Bluetooth startup key for removal");
        status = RegDeleteValueW(key.value, kDesktopDirectoryName);
        if (status != ERROR_FILE_NOT_FOUND) regCheck(status, L"Remove Bluetooth Run startup value");
        regCheck(RegFlushKey(key.value), L"Flush Bluetooth startup removal");
    });
}
}

std::wstring WindowsAdapter::consoleUserSid() const {
    DWORD session = WTSGetActiveConsoleSessionId();
    if (session == 0xFFFFFFFF) throw ComponentError(L"No active physical console session.");
    LPWSTR user = nullptr, domain = nullptr; DWORD n = 0;
    win(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSUserName, &user, &n), L"Read console user");
    std::wstring account(user); WTSFreeMemory(user);
    if (account.empty()) throw ComponentError(L"Sign in at the physical console before installing.");
    win(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSDomainName, &domain, &n), L"Read console domain");
    std::wstring qualified = std::wstring(domain) + L"\\" + account; WTSFreeMemory(domain);
    DWORD sidBytes = 0, domainChars = 0; SID_NAME_USE use{};
    LookupAccountNameW(nullptr, qualified.c_str(), nullptr, &sidBytes, nullptr, &domainChars, &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) win(FALSE, L"Resolve console SID size");
    std::vector<BYTE> sid(sidBytes); std::vector<wchar_t> authority(domainChars);
    win(LookupAccountNameW(nullptr, qualified.c_str(), sid.data(), &sidBytes, authority.data(), &domainChars, &use), L"Resolve console SID");
    LPWSTR text = nullptr; win(ConvertSidToStringSidW(sid.data(), &text), L"Format console SID");
    std::wstring result(text); LocalFree(text); validSid(result); return result;
}
bool WindowsAdapter::isSystem() const { return processSid(GetCurrentProcess()) == L"S-1-5-18"; }

bool WindowsAdapter::continuationTaskExists() const {
    Scheduler scheduler;
    return scheduler.get(kBootTask).Get() != nullptr;
}
void WindowsAdapter::registerContinuationTask(const WizardState& state) const {
    logOperation(L"Register SYSTEM boot task and ordinary-user result task for SID " + state.targetSid);
    validSid(state.targetSid);
    if (std::filesystem::path(state.wizardPath) != updateDirectory(state) / kInstallerFile)
        throw ComponentError(L"Reboot continuation must use this transaction's protected staged installer.");
    registerTask(kBootTask, state.targetSid, state.wizardPath,
        L"--resume-operation " + state.transactionId, true, false);
    registerResultTask(state);
}
void WindowsAdapter::registerResultTask(const WizardState& state) const {
    registerTask(kResultTask, state.targetSid, systemDirectory() / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe",
        encodedPowerShell(resultObserverScript(*this, state)), false, true);
}
void WindowsAdapter::startFinalization(const WizardState& state) const {
    assertSupportedAdministratorEnvironment();
    const auto current = readState();
    if (!current || current->phase != WizardPhase::finalizing || current->transactionId != state.transactionId ||
        current->targetSid != state.targetSid || current->packageVersion != state.packageVersion)
        throw ComponentError(L"Finalization requires the matching verified deployment transaction.");
    registerTask(kFinalizeTask, state.targetSid, systemDirectory() / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe",
        encodedPowerShell(finalizationScript(*this, state)), true, false);
    registerResultTask(state);
    registerFinalizationUninstall(state);
    retryFinalization(state);
}
void WindowsAdapter::runContinuation(const WizardState& state) const {
    const auto current = readState();
    if (!current || current->transactionId != state.transactionId || updateRebootRequired())
        throw ComponentError(L"Continuation does not match a reboot-completed transaction.");
    Scheduler scheduler; const auto task = scheduler.get(kBootTask);
    if (!task) throw ComponentError(L"SYSTEM continuation task is missing. No new transaction was started.");
    auto record = readCompletion();
    if (!record || record->transactionId != state.transactionId) throw ComponentError(L"Continuation result record is missing or belongs to another transaction.");
    record->finished = record->success = false;
    record->message = L"Continuing the registered operation..."; writeCompletion(*record);
    registerResultTask(state); startResultTask(*this);
    VARIANT empty{}; VariantInit(&empty); ComPtr<IRunningTask> running;
    hr(task->Run(empty, &running), L"Continue the registered SYSTEM operation");
}
bool WindowsAdapter::finalizationTaskExists() const {
    Scheduler scheduler; return scheduler.get(kFinalizeTask).Get() != nullptr;
}
void WindowsAdapter::retryFinalization(const WizardState& state) const {
    const auto current = readState();
    if (!current || current->transactionId != state.transactionId || current->phase != WizardPhase::finalizing)
        throw ComponentError(L"Finalization does not match the registered transaction.");
    Scheduler scheduler; const auto task = scheduler.get(kFinalizeTask);
    if (!task) { startFinalization(state); return; }
    registerResultTask(state);
    auto record = readCompletion();
    if (!record || record->transactionId != state.transactionId) throw ComponentError(L"Finalization result record is missing or belongs to another transaction.");
    record->finished = record->success = false;
    record->message = L"Continuing finalization..."; writeCompletion(*record);
    startResultTask(*this);
    VARIANT empty{}; VariantInit(&empty); ComPtr<IRunningTask> running;
    hr(task->Run(empty, &running), L"Run this transaction's finalization task");
}
void WindowsAdapter::registerUserStartup(const WizardState& state) const {
    logOperation(L"Register target-user Run startup: " + std::wstring(kDesktopDirectoryName) + L"; target SID=" + state.targetSid);
    withUserHive(state.targetSid, [](HKEY hive) {
        Registry key;
        regCheck(RegCreateKeyExW(hive, kStartupRegistryPath, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key.value, nullptr), L"Create target-user startup key");
        const auto command = startupCommand();
        if (command.size() >= 260) throw ComponentError(L"Bluetooth startup command exceeds the Run key length limit.");
        regCheck(RegSetValueExW(key.value, kDesktopDirectoryName, 0, REG_SZ, reinterpret_cast<const BYTE*>(command.c_str()),
            static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t))), L"Write Bluetooth Run startup value");
        regCheck(RegFlushKey(key.value), L"Flush Bluetooth startup registration");
    });
}
bool WindowsAdapter::userStartupPresent() const {
    const auto state = readState();
    if (!state || state->targetSid.empty()) return false;
    bool present = false;
    withUserHive(state->targetSid, [&present](HKEY hive) {
        std::array<wchar_t, 260> command{}; DWORD bytes = sizeof(command);
        const auto status = RegGetValueW(hive, kStartupRegistryPath, kDesktopDirectoryName, RRF_RT_REG_SZ, nullptr, command.data(), &bytes);
        if (status == ERROR_FILE_NOT_FOUND) return;
        regCheck(status, L"Read target-user Run startup");
        if (_wcsicmp(command.data(), startupCommand().c_str()) != 0)
            throw ComponentError(L"Bluetooth Run startup command differs from the installed executable.");
        present = true;
    });
    return present;
}
bool WindowsAdapter::toolsPresent() const {
    for (const auto& component : kComponentFiles)
        if (component.desktopTool && !std::filesystem::is_regular_file(componentTarget(component))) return false;
    return true;
}
bool WindowsAdapter::desktopArtifactsPresent() const {
    for (const auto& component : kComponentFiles)
        if (component.desktopTool && std::filesystem::exists(componentTarget(component))) return true;
    return std::filesystem::exists(desktopDirectory()) && !std::filesystem::is_empty(desktopDirectory());
}
bool WindowsAdapter::trayRunning() const {
    const auto state = readState();
    if (!state || state->targetSid.empty()) return false;
    TraySearch search{desktopDirectory() / kMainAppFile, state->targetSid, WTSGetActiveConsoleSessionId()};
    EnumWindows(visitTray, reinterpret_cast<LPARAM>(&search));
    if (!search.error.empty()) throw ComponentError(search.error);
    return search.found;
}
void WindowsAdapter::stopTray(const WizardState& state) const {
    logOperation(L"Remove target-user Run startup before component maintenance.");
    removeUserStartup(state.targetSid);
    TraySearch search{desktopDirectory() / kMainAppFile, state.targetSid, WTSGetActiveConsoleSessionId(), true};
    const auto instances = pinMainInstances(search.expected);
    EnumWindows(visitTray, reinterpret_cast<LPARAM>(&search));
    if (!search.error.empty()) throw ComponentError(search.error);
    for (const auto& process : instances) {
        const DWORD waited = WaitForSingleObject(process->value, 30000);
        if (waited == WAIT_FAILED) win(FALSE, L"Wait for main application instance");
        if (waited != WAIT_OBJECT_0)
            throw ComponentError(L"An Unlock with iPhone operation is still running. Close its password or manual enrollment window, then continue maintenance. No process was killed.");
    }
    if (!pinMainInstances(search.expected).empty())
        throw ComponentError(L"A main application instance started during maintenance. Close it before continuing. No process was killed.");
}
void WindowsAdapter::removeTools() const {
    for (const auto& component : kComponentFiles)
        if (component.desktopTool) deleteBinaryIfPresent(componentTarget(component));
}
void WindowsAdapter::installDesktopIntegration(const WizardState& state) const {
    registerUserStartup(state);
    registerApplicationUninstall(desktopDirectory() / kInstallerFile);
    logOperation(L"Bluetooth Run startup registered; the ordinary completion UI starts the tray once, then Windows starts it at later sign-ins.");
}
void WindowsAdapter::removeDesktopIntegration() const {
    logOperation(L"Delete target-user Run startup.");
    const auto state = readState();
    if (state && !state->targetSid.empty()) removeUserStartup(state->targetSid);
}
void WindowsAdapter::removeProductData(const WizardState& state) const {
    ensureDeploymentDirectories();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    win(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1, &descriptor, nullptr), L"Protect enrollment removal lock");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    const HANDLE raw = CreateMutexW(&attributes, FALSE, unlock_windows::phone_approval::kEnrollmentWriterMutex);
    const DWORD error = GetLastError(); LocalFree(descriptor); SetLastError(error);
    Handle writer(raw); win(raw != nullptr, L"Open enrollment writer lock");
    const DWORD waited = WaitForSingleObject(raw, 0);
    if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED) throw ComponentError(L"Phone enrollment is being modified. Uninstall paused.");
    struct Lock { HANDLE h; ~Lock() { ReleaseMutex(h); } } lock{raw};
    const auto directory = productDataDirectory();
    if (std::filesystem::exists(directory)) {
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            const auto name = entry.path().filename().wstring();
            const std::wstring prefix = std::wstring(unlock_windows::phone_approval::kEnrollmentFileName) +
                unlock_windows::phone_approval::kEnrollmentPendingSuffix;
            const bool temporary = name.size() == prefix.size() + 32 && name.starts_with(prefix) &&
                name.find_first_not_of(L"0123456789abcdef", prefix.size()) == std::wstring::npos;
            if (name != unlock_windows::phone_approval::kEnrollmentFileName && !temporary) continue;
            const DWORD flags = GetFileAttributesW(entry.path().c_str());
            if (flags == INVALID_FILE_ATTRIBUTES || (flags & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                throw ComponentError(L"Unsafe enrollment file; removal paused.");
            deleteBinaryIfPresent(entry.path());
        }
    }
    withUserHive(state.targetSid, [](HKEY hive) {
        auto status = RegDeleteTreeW(hive, L"Software\\UnlockWindowsWithIPhone\\GattHost");
        if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) regCheck(status, L"Remove target-user ComputerId");
        Registry key;
        status = RegOpenKeyExW(hive, L"Software\\UnlockWindowsWithIPhone", 0, KEY_READ, &key.value);
        if (status == ERROR_FILE_NOT_FOUND) return;
        regCheck(status, L"Inspect target-user product registry");
        DWORD subkeys = 0, values = 0;
        regCheck(RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
            &values, nullptr, nullptr, nullptr, nullptr), L"Inspect target-user remaining data");
        if (subkeys || values) throw ComponentError(L"Unknown target-user product registry data remains.");
        RegCloseKey(key.value); key.value = nullptr;
        regCheck(RegDeleteKeyW(hive, L"Software\\UnlockWindowsWithIPhone"), L"Remove empty target-user product key");
        regCheck(RegFlushKey(hive), L"Flush target-user data removal");
    });
}
void WindowsAdapter::writeCompletion(const CompletionRecord& record) const {
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
    Registry key;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto acl = L"D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KRSD;;;" + record.targetSid + L")";
    win(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr), L"Create result registry security");
    struct Security { PSECURITY_DESCRIPTOR p; ~Security() { LocalFree(p); } } security{descriptor};
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    regCheck(RegCreateKeyExW(HKEY_LOCAL_MACHINE, kResultRegistryPath.c_str(), 0, nullptr, 0,
        KEY_WRITE | WRITE_DAC | KEY_WOW64_64KEY, &attributes, &key.value, nullptr), L"Create completion record");
    regCheck(RegSetKeySecurity(key.value, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor), L"Protect completion record");
    regCheck(RegSetValueExW(key.value, kSnapshotValueName, 0, REG_BINARY, snapshot.data(),
        static_cast<DWORD>(snapshot.size())), L"Commit atomic completion snapshot");
    regCheck(RegFlushKey(key.value), L"Flush completion record");
}
std::optional<CompletionRecord> WindowsAdapter::readCompletion() const {
    Registry key;
    auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kResultRegistryPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key.value);
    if (status == ERROR_FILE_NOT_FOUND) return {};
    regCheck(status, L"Open completion record");
    std::vector<BYTE> snapshot(kCompletionMaximumBytes);
    DWORD bytes = static_cast<DWORD>(snapshot.size());
    const auto read = RegGetValueW(key.value, nullptr, kSnapshotValueName, RRF_RT_REG_BINARY, nullptr, snapshot.data(), &bytes);
    if (read == ERROR_FILE_NOT_FOUND) return {};
    regCheck(read, L"Read atomic completion snapshot");
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
void WindowsAdapter::acknowledgeCompletion(const std::wstring& transaction) const {
    const auto result = readCompletion();
    if (!result || !result->finished || result->transactionId != transaction ||
        result->targetSid != processSid(GetCurrentProcess()))
        throw ComponentError(L"Only the target user can dismiss the matching completed result.");
    Scheduler scheduler; scheduler.remove(kResultTask);
    regCheck(RegDeleteKeyExW(HKEY_LOCAL_MACHINE, kResultRegistryPath.c_str(), KEY_WOW64_64KEY, 0), L"Remove acknowledged result record");
}
void WindowsAdapter::startTrayForCompletedOperation(const std::wstring& transaction) const {
    const auto result = readCompletion();
    const auto state = readState();
    if (!result || !result->finished || !result->success || result->transactionId != transaction)
        throw ComponentError(L"Bluetooth startup requires the matching successful completion result.");
    if (!state) return;
    if (state->phase != WizardPhase::installed || state->targetSid != result->targetSid)
        throw ComponentError(L"Bluetooth startup does not match the completed installation.");
    DWORD session = 0;
    win(ProcessIdToSessionId(GetCurrentProcessId(), &session), L"Read result process session");
    if (environment().elevated || processSid(GetCurrentProcess()) != state->targetSid ||
        session != WTSGetActiveConsoleSessionId() || consoleUserSid() != state->targetSid)
        throw ComponentError(L"Bluetooth must start from the ordinary target user's physical console session.");
    if (!userStartupPresent()) throw ComponentError(L"Bluetooth Run startup is not registered.");
    if (trayRunning()) return;
    SHELLEXECUTEINFOW launch{}; launch.cbSize = sizeof(launch);
    const auto executable = desktopDirectory() / kMainAppFile;
    const auto directory = desktopDirectory();
    launch.fMask = SEE_MASK_FLAG_NO_UI;
    launch.lpVerb = L"open"; launch.lpFile = executable.c_str(); launch.lpDirectory = directory.c_str();
    launch.nShow = SW_SHOWNORMAL;
    win(ShellExecuteExW(&launch), L"Start Bluetooth tray from the ordinary completion UI");
}
}

