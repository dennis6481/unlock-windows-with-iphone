// Created by Rui MA on 02 Oct 2026
// Console identity, target-user hive, Run/shortcut integration and normal application exit.

#define UNICODE
#define _UNICODE
#include "WindowsAdapter.h"
#include "../DesktopApp/DesktopApp.h"
#include "SetupPlatform.h"
#include "../PhoneApproval/EnrollmentStore.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <wrl/client.h>
#include <array>
#include <cstring>
#include <memory>
#include <vector>
#include <set>

namespace unlock::components {
namespace {
using Microsoft::WRL::ComPtr;
std::wstring tokenSid(HANDLE token) {
    DWORD n = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &n);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) checkWin32(FALSE, L"Query token size");
    std::vector<BYTE> data(n);
    checkWin32(GetTokenInformation(token, TokenUser, data.data(), n, &n), L"Read token user");
    LPWSTR text = nullptr;
    checkWin32(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &text), L"Format SID");
    std::wstring result(text); LocalFree(text); return result;
}
std::wstring processSid(HANDLE process) {
    HANDLE raw = nullptr; checkWin32(OpenProcessToken(process, TOKEN_QUERY, &raw), L"Open process token");
    ScopedHandle token(raw); return tokenSid(token.value);
}
struct TraySearch {
    std::filesystem::path expected;
    std::wstring sid;
    DWORD session = 0;
    bool stop = false;
    bool found = false;
    std::wstring error;
};
std::vector<std::unique_ptr<ScopedHandle>> pinMainInstances(const std::filesystem::path& expected) {
    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    checkWin32(snapshot.value != INVALID_HANDLE_VALUE, L"Enumerate main application processes");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<std::unique_ptr<ScopedHandle>> instances;
    BOOL found = Process32FirstW(snapshot.value, &entry);
    while (found) {
        if (_wcsicmp(entry.szExeFile, kMainAppFile) == 0) {
            auto process = std::make_unique<ScopedHandle>(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                FALSE, entry.th32ProcessID));
            checkWin32(process->value != nullptr, L"Pin main application instance");
            std::array<wchar_t, 32768> image{};
            DWORD size = static_cast<DWORD>(image.size());
            checkWin32(QueryFullProcessImageNameW(process->value, 0, image.data(), &size), L"Read main application image");
            if (_wcsicmp(image.data(), expected.c_str()) == 0) instances.push_back(std::move(process));
        }
        found = Process32NextW(snapshot.value, &entry);
    }
    if (GetLastError() != ERROR_NO_MORE_FILES) checkWin32(FALSE, L"Read main application process list");
    return instances;
}
BOOL CALLBACK visitTray(HWND window, LPARAM value) {
    auto& search = *reinterpret_cast<TraySearch*>(value);
    std::array<wchar_t, 128> name{};
    GetClassNameW(window, name.data(), static_cast<int>(name.size()));
    if (wcscmp(name.data(), unlock_windows::desktop_app::kTrayWindowClass) != 0) return TRUE;
    try {
        DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
        ScopedHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        checkWin32(process.value != nullptr, L"Open Bluetooth tray process");
        DWORD session = 0; checkWin32(ProcessIdToSessionId(pid, &session), L"Read tray session");
        std::array<wchar_t, 32768> image{}; DWORD n = static_cast<DWORD>(image.size());
        checkWin32(QueryFullProcessImageNameW(process.value, 0, image.data(), &n), L"Read tray image");
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
            checkWin32(PostMessageW(window, WM_CLOSE, 0, 0), L"Request normal Bluetooth tray exit");
            const DWORD waited = WaitForSingleObject(process.value, 30000);
            if (waited != WAIT_OBJECT_0) throw ComponentError(L"Bluetooth tray did not exit within 30 seconds. Operation paused; no process was killed.");
        }
    } catch (const ComponentError& error) { search.error = error.wideWhat(); return FALSE; }
    return TRUE;
}

struct HivePrivilege {
    ScopedHandle token;
    TOKEN_PRIVILEGES previous{};
    bool changed = false;
    explicit HivePrivilege(const wchar_t* name) {
        checkWin32(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token.value), L"Open hive privilege token");
        TOKEN_PRIVILEGES requested{}; requested.PrivilegeCount = 1;
        checkWin32(LookupPrivilegeValueW(nullptr, name, &requested.Privileges[0].Luid), L"Look up hive privilege");
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD bytes = sizeof(previous);
        checkWin32(AdjustTokenPrivileges(token.value, FALSE, &requested, sizeof(previous), &previous, &bytes), L"Enable hive privilege");
        checkWin32(GetLastError() == ERROR_SUCCESS, L"Acquire hive privilege");
        changed = previous.PrivilegeCount != 0;
    }
    void restore() {
        if (!changed) return;
        checkWin32(AdjustTokenPrivileges(token.value, FALSE, &previous, 0, nullptr, nullptr), L"Restore hive privilege");
        checkWin32(GetLastError() == ERROR_SUCCESS, L"Restore hive privilege assignment");
        changed = false;
    }
    ~HivePrivilege() {
        if (changed && (!AdjustTokenPrivileges(token.value, FALSE, &previous, 0, nullptr, nullptr) || GetLastError() != ERROR_SUCCESS))
            OutputDebugStringW(L"Installer failed to restore registry hive privilege during exception cleanup.\n");
    }
};
}
void WindowsAdapter::withUserHive(const std::wstring& sid, const std::function<void(HKEY)>& operation) const {
    validateTargetSid(sid);
    ScopedRegistryKey hive;
    LSTATUS status = RegOpenKeyExW(HKEY_USERS, sid.c_str(), 0, KEY_READ | KEY_WRITE, &hive.value);
    if (status == ERROR_SUCCESS) { operation(hive.value); return; }
    if (status != ERROR_FILE_NOT_FOUND) checkRegistry(status, L"Open target user registry hive");
    const auto profileKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid;
    std::array<wchar_t, 32768> profile{}; DWORD bytes = sizeof(profile);
    checkRegistry(RegGetValueW(HKEY_LOCAL_MACHINE, profileKey.c_str(), L"ProfileImagePath",
        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, profile.data(), &bytes), L"Read target user profile path");
    const auto file = std::filesystem::path(profile.data()) / L"NTUSER.DAT";
    if (!std::filesystem::is_regular_file(file)) throw ComponentError(L"Target user registry hive file is missing: " + file.wstring());
    HivePrivilege backup(SE_BACKUP_NAME), restore(SE_RESTORE_NAME);
    const auto mount = L"UnlockWindowsStartup-" + sid;
    checkRegistry(RegLoadKeyW(HKEY_USERS, mount.c_str(), file.c_str()), L"Load target user registry hive");
    try {
        checkRegistry(RegOpenKeyExW(HKEY_USERS, mount.c_str(), 0, KEY_READ | KEY_WRITE, &hive.value), L"Open loaded user registry hive");
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
        checkRegistry(RegUnLoadKeyW(HKEY_USERS, mount.c_str()), L"Unload target user hive after unknown startup exception");
        throw;
    }
    const auto closed = RegCloseKey(hive.value); hive.value = nullptr;
    checkRegistry(closed, L"Close loaded user registry hive");
    checkRegistry(RegUnLoadKeyW(HKEY_USERS, mount.c_str()), L"Unload target user registry hive");
    restore.restore(); backup.restore();
}
namespace {
std::wstring startupCommand() {
    return L"\"" + (desktopDirectory() / kMainAppFile).wstring() + L"\" " +
        unlock_windows::desktop_app::kBackgroundRole;
}
}
void WindowsAdapter::removeUserStartup(const std::wstring& sid) const {
    withUserHive(sid, [](HKEY hive) {
        ScopedRegistryKey key;
        LSTATUS status = RegOpenKeyExW(hive, kStartupRegistryPath, 0, KEY_SET_VALUE, &key.value);
        if (status == ERROR_FILE_NOT_FOUND) return;
        checkRegistry(status, L"Open Bluetooth startup key for removal");
        status = RegDeleteValueW(key.value, kDesktopDirectoryName);
        if (status != ERROR_FILE_NOT_FOUND) checkRegistry(status, L"Remove Bluetooth Run startup value");
        checkRegistry(RegFlushKey(key.value), L"Flush Bluetooth startup removal");
    });
}
std::wstring WindowsAdapter::consoleUserSid() const {
    DWORD session = WTSGetActiveConsoleSessionId();
    if (session == 0xFFFFFFFF) throw ComponentError(L"No active physical console session.");
    LPWSTR user = nullptr, domain = nullptr; DWORD n = 0;
    checkWin32(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSUserName, &user, &n), L"Read console user");
    std::wstring account(user); WTSFreeMemory(user);
    if (account.empty()) throw ComponentError(L"Sign in at the physical console before installing.");
    checkWin32(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSDomainName, &domain, &n), L"Read console domain");
    std::wstring qualified = std::wstring(domain) + L"\\" + account; WTSFreeMemory(domain);
    DWORD sidBytes = 0, domainChars = 0; SID_NAME_USE use{};
    LookupAccountNameW(nullptr, qualified.c_str(), nullptr, &sidBytes, nullptr, &domainChars, &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) checkWin32(FALSE, L"Resolve console SID size");
    std::vector<BYTE> sid(sidBytes); std::vector<wchar_t> authority(domainChars);
    checkWin32(LookupAccountNameW(nullptr, qualified.c_str(), sid.data(), &sidBytes, authority.data(), &domainChars, &use), L"Resolve console SID");
    LPWSTR text = nullptr; checkWin32(ConvertSidToStringSidW(sid.data(), &text), L"Format console SID");
    std::wstring result(text); LocalFree(text); validateTargetSid(result); return result;
}
bool WindowsAdapter::isSystem() const { return processSid(GetCurrentProcess()) == L"S-1-5-18"; }

void WindowsAdapter::registerUserStartup(const std::wstring& targetSid) const {
    logOperation(L"Register target-user Run startup: " + std::wstring(kDesktopDirectoryName) + L"; target SID=" + targetSid);
    withUserHive(targetSid, [](HKEY hive) {
        ScopedRegistryKey key;
        checkRegistry(RegCreateKeyExW(hive, kStartupRegistryPath, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key.value, nullptr), L"Create target-user startup key");
        const auto command = startupCommand();
        if (command.size() >= 260) throw ComponentError(L"Bluetooth startup command exceeds the Run key length limit.");
        checkRegistry(RegSetValueExW(key.value, kDesktopDirectoryName, 0, REG_SZ, reinterpret_cast<const BYTE*>(command.c_str()),
            static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t))), L"Write Bluetooth Run startup value");
        checkRegistry(RegFlushKey(key.value), L"Flush Bluetooth startup registration");
    });
}
bool WindowsAdapter::userStartupPresent(const std::wstring& targetSid) const {
    if (targetSid.empty()) return false;
    bool present = false;
    withUserHive(targetSid, [&present](HKEY hive) {
        std::array<wchar_t, 260> command{}; DWORD bytes = sizeof(command);
        const auto status = RegGetValueW(hive, kStartupRegistryPath, kDesktopDirectoryName, RRF_RT_REG_SZ, nullptr, command.data(), &bytes);
        if (status == ERROR_FILE_NOT_FOUND) return;
        checkRegistry(status, L"Read target-user Run startup");
        if (_wcsicmp(command.data(), startupCommand().c_str()) != 0)
            throw ComponentError(L"Bluetooth Run startup command differs from the installed executable.");
        present = true;
    });
    return present;
}
bool WindowsAdapter::trayRunning(const std::wstring& targetSid) const {
    if (targetSid.empty()) return false;
    TraySearch search{desktopDirectory() / kMainAppFile, targetSid, WTSGetActiveConsoleSessionId()};
    EnumWindows(visitTray, reinterpret_cast<LPARAM>(&search));
    if (!search.error.empty()) throw ComponentError(search.error);
    return search.found;
}
void WindowsAdapter::stopTray(const std::wstring& targetSid) const {
    logOperation(L"Remove target-user Run startup before component maintenance.");
    removeUserStartup(targetSid);
    TraySearch search{desktopDirectory() / kMainAppFile, targetSid, WTSGetActiveConsoleSessionId(), true};
    const auto instances = pinMainInstances(search.expected);
    EnumWindows(visitTray, reinterpret_cast<LPARAM>(&search));
    if (!search.error.empty()) throw ComponentError(search.error);
    for (const auto& process : instances) {
        const DWORD waited = WaitForSingleObject(process->value, 30000);
        if (waited == WAIT_FAILED) checkWin32(FALSE, L"Wait for main application instance");
        if (waited != WAIT_OBJECT_0)
            throw ComponentError(L"An Unlock with iPhone operation is still running. Close its password or manual enrollment window, then continue maintenance. No process was killed.");
    }
    if (!pinMainInstances(search.expected).empty())
        throw ComponentError(L"A main application instance started during maintenance. Close it before continuing. No process was killed.");
}
void WindowsAdapter::installDesktopIntegration(const std::wstring& targetSid, const std::wstring& version) const {
    ScopedComApartment apartment;
    ComPtr<IShellLinkW> shortcut;
    checkHresult(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&shortcut)), L"Create Start Menu shortcut");
    const auto executable = desktopDirectory() / kMainAppFile;
    checkHresult(shortcut->SetPath(executable.c_str()), L"Set Start Menu shortcut executable");
    checkHresult(shortcut->SetWorkingDirectory(desktopDirectory().c_str()), L"Set Start Menu shortcut working directory");
    checkHresult(shortcut->SetIconLocation(executable.c_str(), 0), L"Set Start Menu shortcut icon");
    checkHresult(shortcut->SetShowCmd(SW_SHOWNORMAL), L"Set Start Menu shortcut window state");
    ComPtr<IPersistFile> file;
    checkHresult(shortcut.As(&file), L"Get Start Menu shortcut persistence");
    checkHresult(file->Save(startMenuShortcut().c_str(), TRUE), L"Save Start Menu shortcut");
    logOperation(L"Start Menu shortcut registered.");
    registerUserStartup(targetSid);
    registerApplicationUninstall(desktopDirectory() / kInstallerFile, version);
    logOperation(L"Bluetooth Run startup registered; the ordinary completion UI starts the tray once, then Windows starts it at later sign-ins.");
}
void WindowsAdapter::removeDesktopIntegration(const std::wstring& targetSid) const {
    deleteFileIfPresent(startMenuShortcut());
    logOperation(L"Delete target-user Run startup.");
    if (!targetSid.empty()) removeUserStartup(targetSid);
}

std::wstring WindowsAdapter::currentUserSid() const { return processSid(GetCurrentProcess()); }
void WindowsAdapter::startTray(const std::wstring& targetSid, bool setup) const {
    DWORD session = 0;
    checkWin32(ProcessIdToSessionId(GetCurrentProcessId(), &session), L"Read result process session");
    if (environment().elevated || processSid(GetCurrentProcess()) != targetSid ||
        session != WTSGetActiveConsoleSessionId() || consoleUserSid() != targetSid)
        throw ComponentError(L"Bluetooth must start from the ordinary target user's physical console session.");
    if (!userStartupPresent(targetSid)) throw ComponentError(L"Bluetooth Run startup is not registered.");
    if (trayRunning(targetSid) && !setup) return;
    SHELLEXECUTEINFOW launch{}; launch.cbSize = sizeof(launch);
    const auto executable = desktopDirectory() / kMainAppFile;
    const auto directory = desktopDirectory();
    launch.fMask = SEE_MASK_FLAG_NO_UI;
    launch.lpVerb = L"open"; launch.lpFile = executable.c_str(); launch.lpDirectory = directory.c_str();
    launch.lpParameters = setup ? unlock_windows::desktop_app::kSetupRole : unlock_windows::desktop_app::kBackgroundRole;
    launch.nShow = SW_SHOWNORMAL;
    checkWin32(ShellExecuteExW(&launch), L"Start Bluetooth tray from the ordinary completion UI");
}
}
