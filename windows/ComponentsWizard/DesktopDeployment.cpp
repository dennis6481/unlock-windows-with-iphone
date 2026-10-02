// Created by Rui MA on 02 Oct 2026

#define UNICODE
#define _UNICODE
#include "WindowsAdapter.h"
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <taskschd.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <wrl/client.h>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace unlock::components {
namespace {
using Microsoft::WRL::ComPtr;
constexpr wchar_t previousLoginTaskName[] = L"UnlockWindowsWithIPhone-GattHost";
constexpr wchar_t startupKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t startupName[] = L"Unlock Windows with iPhone";
constexpr wchar_t bootName[] = L"UnlockWindowsWithIPhone-CompleteOperation";
constexpr wchar_t resultName[] = L"UnlockWindowsWithIPhone-ComponentResult";
constexpr wchar_t resultKey[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\ComponentResult";

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
    hr(settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW), L"Set single task instance");
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
    Bstr security(notification
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

std::filesystem::path menuDirectory() {
    PWSTR raw = nullptr;
    hr(SHGetKnownFolderPath(FOLDERID_CommonPrograms, KF_FLAG_DEFAULT, nullptr, &raw), L"Find Start menu");
    std::filesystem::path directory(raw); CoTaskMemFree(raw);
    return directory / L"Unlock Windows with iPhone";
}
void shortcut(const std::filesystem::path& path, const std::filesystem::path& target, bool elevate = false) {
    ComPtr<IShellLinkW> link;
    hr(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)), L"Create shortcut");
    hr(link->SetPath(target.c_str()), L"Set shortcut target");
    if (elevate) {
        ComPtr<IShellLinkDataList> data; hr(link.As(&data), L"Configure administrative credential-manager shortcut");
        DWORD flags = 0; hr(data->GetFlags(&flags), L"Read shortcut flags");
        hr(data->SetFlags(flags | SLDF_RUNAS_USER), L"Set credential-manager Run as administrator shortcut");
    }
    ComPtr<IPersistFile> file; hr(link.As(&file), L"Get shortcut storage");
    hr(file->Save(path.c_str(), TRUE), L"Save shortcut " + path.wstring());
}

struct TraySearch {
    std::filesystem::path expected;
    std::wstring sid;
    DWORD session = 0;
    bool stop = false;
    bool found = false;
    std::wstring error;
    std::vector<std::unique_ptr<Handle>> helpers;
};
BOOL CALLBACK pinPairingHelper(HWND window, LPARAM value) {
    auto& search = *reinterpret_cast<TraySearch*>(value);
    std::array<wchar_t, 128> name{};
    GetClassNameW(window, name.data(), static_cast<int>(name.size()));
    if (wcscmp(name.data(), L"UnlockWindowsEnrollmentConfirmation") != 0) return TRUE;
    try {
        DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
        DWORD session = 0; win(ProcessIdToSessionId(pid, &session), L"Read pairing helper session");
        if (session != search.session) return TRUE;
        auto process = std::make_unique<Handle>(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        win(process->value != nullptr, L"Pin pairing helper process");
        std::array<wchar_t, 32768> image{}; DWORD n = static_cast<DWORD>(image.size());
        win(QueryFullProcessImageNameW(process->value, 0, image.data(), &n), L"Read pairing helper image");
        if (_wcsicmp(image.data(), (search.expected.parent_path() / kPairingToolFile).c_str()) != 0)
            throw ComponentError(L"Pairing window does not belong to the installed helper.");
        search.helpers.push_back(std::move(process));
    } catch (const ComponentError& error) { search.error = error.wideWhat(); return FALSE; }
    return TRUE;
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
std::wstring startupCommand() { return L"\"" + (systemDirectory() / kGattHostFile).wstring() + L"\""; }
void removeUserStartup(const std::wstring& sid) {
    withUserHive(sid, [](HKEY hive) {
        Registry key;
        LSTATUS status = RegOpenKeyExW(hive, startupKey, 0, KEY_SET_VALUE, &key.value);
        if (status == ERROR_FILE_NOT_FOUND) return;
        regCheck(status, L"Open Bluetooth startup key for removal");
        status = RegDeleteValueW(key.value, startupName);
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
    return scheduler.get(bootName).Get() != nullptr;
}
void WindowsAdapter::removeContinuationTask() const {
    Scheduler scheduler; scheduler.remove(bootName);
}
void WindowsAdapter::registerContinuationTask(const WizardState& state) const {
    logOperation(L"Register SYSTEM boot task and ordinary-user result task for SID " + state.targetSid);
    validSid(state.targetSid);
    if (std::filesystem::path(state.wizardPath) != updateDirectory(state) / kInstallerFile)
        throw ComponentError(L"Reboot continuation must use this transaction's protected staged installer.");
    registerTask(bootName, state.targetSid, state.wizardPath,
        L"--resume-operation " + state.transactionId, true, false);
    registerTask(resultName, state.targetSid, state.wizardPath,
        L"--show-result " + state.transactionId, false, true);
}
void WindowsAdapter::registerUserStartup(const WizardState& state) const {
    logOperation(L"Register target-user Run startup: " + std::wstring(startupName) + L"; target SID=" + state.targetSid);
    Scheduler scheduler; scheduler.remove(previousLoginTaskName);
    withUserHive(state.targetSid, [](HKEY hive) {
        Registry key;
        regCheck(RegCreateKeyExW(hive, startupKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key.value, nullptr), L"Create target-user startup key");
        const auto command = startupCommand();
        if (command.size() >= 260) throw ComponentError(L"Bluetooth startup command exceeds the Run key length limit.");
        regCheck(RegSetValueExW(key.value, startupName, 0, REG_SZ, reinterpret_cast<const BYTE*>(command.c_str()),
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
        const auto status = RegGetValueW(hive, startupKey, startupName, RRF_RT_REG_SZ, nullptr, command.data(), &bytes);
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
        if (component.desktopTool && !std::filesystem::is_regular_file(systemDirectory() / component.name)) return false;
    return true;
}
bool WindowsAdapter::desktopArtifactsPresent() const {
    for (const auto& component : kComponentFiles)
        if (component.desktopTool && std::filesystem::exists(systemDirectory() / component.name)) return true;
    return std::filesystem::exists(menuDirectory());
}
bool WindowsAdapter::shortcutsPresent() const {
    Com apartment;
    const std::array<const wchar_t*, 2> names{L"Saved Windows credential.lnk", L"Install or maintain.lnk"};
    for (size_t i = 0; i < names.size(); ++i) {
        auto path = menuDirectory() / names[i];
        if (!std::filesystem::is_regular_file(path)) return false;
        ComPtr<IShellLinkW> link;
        hr(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)), L"Read installed shortcut");
        ComPtr<IPersistFile> file; hr(link.As(&file), L"Read shortcut storage");
        hr(file->Load(path.c_str(), STGM_READ), L"Load installed shortcut");
        std::array<wchar_t, 32768> target{};
        hr(link->GetPath(target.data(), static_cast<int>(target.size()), nullptr, SLGP_RAWPATH), L"Read shortcut target");
        if (_wcsicmp(target.data(), (systemDirectory() / (i == 0 ? kCredentialManagerFile : kInstallerFile)).c_str()) != 0) return false;
        if (i == 0) {
            ComPtr<IShellLinkDataList> data; hr(link.As(&data), L"Verify administrative credential-manager shortcut");
            DWORD flags = 0; hr(data->GetFlags(&flags), L"Read credential-manager shortcut flags");
            if (!(flags & SLDF_RUNAS_USER)) return false;
        }
    }
    return true;
}
bool WindowsAdapter::trayRunning() const {
    const auto state = readState();
    if (!state || state->targetSid.empty()) return false;
    TraySearch search{systemDirectory() / kGattHostFile, state->targetSid, WTSGetActiveConsoleSessionId()};
    EnumWindows(visitTray, reinterpret_cast<LPARAM>(&search));
    if (!search.error.empty()) throw ComponentError(search.error);
    return search.found;
}
void WindowsAdapter::stopTray(const WizardState& state) const {
    Scheduler scheduler; auto task = scheduler.get(previousLoginTaskName);
    if (task) hr(task->put_Enabled(VARIANT_FALSE), L"Disable previous Bluetooth login task before migration");
    logOperation(L"Remove target-user Run startup before component maintenance.");
    removeUserStartup(state.targetSid);
    TraySearch search{systemDirectory() / kGattHostFile, state.targetSid, WTSGetActiveConsoleSessionId(), true};
    EnumWindows(pinPairingHelper, reinterpret_cast<LPARAM>(&search));
    if (!search.error.empty()) throw ComponentError(search.error);
    EnumWindows(visitTray, reinterpret_cast<LPARAM>(&search));
    if (!search.error.empty()) throw ComponentError(search.error);
    for (const auto& helper : search.helpers) {
        if (WaitForSingleObject(helper->value, 30000) != WAIT_OBJECT_0)
            throw ComponentError(L"Pairing helper did not finish cancellation within 30 seconds. Operation paused; no process was killed.");
    }
}
void WindowsAdapter::removeTools() const {
    for (const auto& component : kComponentFiles)
        if (component.desktopTool) deleteBinaryIfPresent(systemDirectory() / component.name);
}
void WindowsAdapter::installDesktopIntegration(const WizardState& state) const {
    registerUserStartup(state);
    Com apartment;
    auto directory = menuDirectory();
    std::filesystem::create_directories(directory);
    shortcut(directory / L"Saved Windows credential.lnk", systemDirectory() / kCredentialManagerFile, true);
    shortcut(directory / L"Install or maintain.lnk", systemDirectory() / kInstallerFile);
    logOperation(L"Bluetooth Run startup registered; the ordinary completion UI starts the tray once, then Windows starts it at later sign-ins.");
}
void WindowsAdapter::removeDesktopIntegration() const {
    logOperation(L"Delete target-user Run startup, previous Bluetooth login task and Start menu shortcuts.");
    Scheduler scheduler; scheduler.remove(previousLoginTaskName);
    const auto state = readState();
    if (state && !state->targetSid.empty()) removeUserStartup(state->targetSid);
    auto directory = menuDirectory();
    for (const auto* name : {L"Saved Windows credential.lnk", L"Install or maintain.lnk"}) {
        auto link = directory / name;
        if (!DeleteFileW(link.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
            win(FALSE, L"Delete shortcut " + link.wstring());
    }
    if (!RemoveDirectoryW(directory.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND &&
        GetLastError() != ERROR_PATH_NOT_FOUND) win(FALSE, L"Remove Start menu directory");
}
void WindowsAdapter::writeCompletion(const CompletionRecord& record) const {
    constexpr size_t maximumBytes = 1024 * 1024;
    const std::array<std::wstring, 4> strings{record.transactionId, record.targetSid, record.message, record.log};
    size_t bytes = 6 * sizeof(DWORD);
    for (const auto& text : strings) {
        if (text.size() > maximumBytes / sizeof(wchar_t)) throw ComponentError(L"Completion log exceeds its storage limit.");
        bytes += text.size() * sizeof(wchar_t);
    }
    if (bytes > maximumBytes) throw ComponentError(L"Completion record exceeds its storage limit.");
    std::array<DWORD, 6> header{1, (record.finished ? 1UL : 0UL) | (record.success ? 2UL : 0UL),
        static_cast<DWORD>(strings[0].size()), static_cast<DWORD>(strings[1].size()),
        static_cast<DWORD>(strings[2].size()), static_cast<DWORD>(strings[3].size())};
    std::vector<BYTE> snapshot(bytes);
    std::memcpy(snapshot.data(), header.data(), sizeof(header));
    size_t offset = sizeof(header);
    for (const auto& text : strings) {
        const size_t n = text.size() * sizeof(wchar_t);
        if (n) std::memcpy(snapshot.data() + offset, text.data(), n);
        offset += n;
    }
    Registry key;
    regCheck(RegCreateKeyExW(HKEY_LOCAL_MACHINE, resultKey, 0, nullptr, 0,
        KEY_WRITE | KEY_WOW64_64KEY, nullptr, &key.value, nullptr), L"Create completion record");
    regCheck(RegSetValueExW(key.value, L"Snapshot", 0, REG_BINARY, snapshot.data(),
        static_cast<DWORD>(snapshot.size())), L"Commit atomic completion snapshot");
    regCheck(RegFlushKey(key.value), L"Flush completion record");
}
std::optional<CompletionRecord> WindowsAdapter::readCompletion() const {
    Registry key;
    auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, resultKey, 0, KEY_READ | KEY_WOW64_64KEY, &key.value);
    if (status == ERROR_FILE_NOT_FOUND) return {};
    regCheck(status, L"Open completion record");
    std::vector<BYTE> snapshot(1024 * 1024);
    DWORD bytes = static_cast<DWORD>(snapshot.size());
    const auto read = RegGetValueW(key.value, nullptr, L"Snapshot", RRF_RT_REG_BINARY, nullptr, snapshot.data(), &bytes);
    if (read == ERROR_FILE_NOT_FOUND) return {};
    regCheck(read, L"Read atomic completion snapshot");
    std::array<DWORD, 6> header{};
    if (bytes < sizeof(header)) throw ComponentError(L"Truncated completion snapshot.");
    std::memcpy(header.data(), snapshot.data(), sizeof(header));
    if (header[0] != 1 || header[1] > 3) throw ComponentError(L"Unsupported completion snapshot.");
    std::array<std::wstring, 4> strings;
    size_t offset = sizeof(header);
    for (size_t i = 0; i < strings.size(); ++i) {
        const size_t n = static_cast<size_t>(header[i + 2]) * sizeof(wchar_t);
        if (n > bytes - offset) throw ComponentError(L"Invalid completion snapshot string length.");
        strings[i].assign(reinterpret_cast<const wchar_t*>(snapshot.data() + offset), header[i + 2]);
        offset += n;
    }
    if (offset != bytes) throw ComponentError(L"Unexpected trailing completion snapshot data.");
    return CompletionRecord{strings[0], strings[1], strings[2], strings[3],
        (header[1] & 1) != 0, (header[1] & 2) != 0};
}
void WindowsAdapter::acknowledgeCompletion(const std::wstring& transaction) const {
    const auto result = readCompletion();
    if (!result || !result->finished || result->transactionId != transaction ||
        result->targetSid != processSid(GetCurrentProcess()))
        throw ComponentError(L"Only the target user can dismiss the matching completed result.");
    Scheduler scheduler; scheduler.remove(resultName);
}
void WindowsAdapter::startTrayForCompletedOperation(const std::wstring& transaction) const {
    const auto result = readCompletion();
    const auto state = readState();
    if (!result || !result->finished || !result->success || result->transactionId != transaction)
        throw ComponentError(L"Bluetooth startup requires the matching successful completion result.");
    if (!state) return;
    if (state->phase == WizardPhase::cleaningUp && state->credentialCleanupConfirmed &&
        state->transactionId == transaction && state->targetSid == result->targetSid) return;
    if (state->phase != WizardPhase::installed || state->transactionId != transaction || state->targetSid != result->targetSid)
        throw ComponentError(L"Bluetooth startup does not match the completed installation.");
    DWORD session = 0;
    win(ProcessIdToSessionId(GetCurrentProcessId(), &session), L"Read result process session");
    if (environment().elevated || processSid(GetCurrentProcess()) != state->targetSid ||
        session != WTSGetActiveConsoleSessionId() || consoleUserSid() != state->targetSid)
        throw ComponentError(L"Bluetooth must start from the ordinary target user's physical console session.");
    if (!userStartupPresent()) throw ComponentError(L"Bluetooth Run startup is not registered.");
    if (trayRunning()) return;
    SHELLEXECUTEINFOW launch{}; launch.cbSize = sizeof(launch);
    const auto executable = systemDirectory() / kGattHostFile;
    const auto directory = systemDirectory();
    launch.fMask = SEE_MASK_FLAG_NO_UI;
    launch.lpVerb = L"open"; launch.lpFile = executable.c_str(); launch.lpDirectory = directory.c_str();
    launch.nShow = SW_SHOWNORMAL;
    win(ShellExecuteExW(&launch), L"Start Bluetooth tray from the ordinary completion UI");
}
}

