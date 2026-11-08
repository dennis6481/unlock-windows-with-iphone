// Created by Rui MA on 02 Oct 2026
// Console identity, target-user hive, startup and normal application exit.

#include "UserIntegration.h"
#include "../DesktopApp/DesktopApp.h"
#include "../Enrollment/EnrollmentSession.h"
#include "Platform.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <shlobj.h>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace unlock::components {
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
namespace {
struct TraySearch {
    std::filesystem::path expected;
    std::wstring sid;
    DWORD session = 0;
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
            throw ComponentError(L"Bluetooth tray is in a different console session. Operation paused.");
        }
        DWORD confirmed = 0; GetWindowThreadProcessId(window, &confirmed);
        if (confirmed != pid || WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT)
            throw ComponentError(L"Bluetooth tray ownership changed before shutdown.");
        checkWin32(PostMessageW(window, WM_CLOSE, 0, 0), L"Request normal Bluetooth tray exit");
        const DWORD waited = WaitForSingleObject(process.value, 30000);
        if (waited != WAIT_OBJECT_0) throw ComponentError(L"Bluetooth tray did not exit within 30 seconds. Operation paused; no process was killed.");
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
void withUserHive(const std::wstring& sid, const std::function<void(HKEY)>& operation) {
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
void removeUserStartup(const std::wstring& sid) {
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
std::wstring consoleUserSid() { return unlock_windows::enrollment::queryConsole().sid; }

void registerUserStartup(const std::wstring& targetSid) {
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
void stopTray(const std::wstring& targetSid) {

    TraySearch search{desktopDirectory() / kMainAppFile, targetSid, WTSGetActiveConsoleSessionId()};
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
bool mainInstancesPresent() { return !pinMainInstances(desktopDirectory() / kMainAppFile).empty(); }
}
