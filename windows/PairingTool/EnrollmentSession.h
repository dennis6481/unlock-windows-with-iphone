// Created by Rui MA on 02 Oct 2026

#pragma once

#include <Windows.h>
#include <sddl.h>
#include <wtsapi32.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace unlock_windows::enrollment {

inline constexpr ULONGLONG kPairingLifetime = 120000;
inline constexpr wchar_t kCancelPrefix[] = L"Local\\UnlockWindowsWithIPhone-Pairing-";

enum class ExitCode : DWORD {
    saved = 0,
    error = 1,
    cancelled = 3,
    expired = 4,
    invalidated = 5,
    rejected = 6,
    alreadyRegistered = 7,
    savedReloadFailed = 8,
    busy = 9,
};

struct Handle final {
    HANDLE value = nullptr;
    Handle() = default;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};

inline void require(BOOL result, const char* operation) {
    if (!result) {
        const DWORD error = GetLastError();
        throw std::runtime_error(std::string(operation) + ": Win32=" + std::to_string(error));
    }
}

inline std::wstring sidText(PSID sid) {
    LPWSTR text = nullptr;
    require(ConvertSidToStringSidW(sid, &text), "ConvertSidToStringSidW");
    const std::wstring result(text);
    LocalFree(text);
    return result;
}

inline bool elevatedAdmin() {
    Handle token;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token.value),
        "OpenProcessToken");
    DWORD bytes = 0;
    TOKEN_ELEVATION elevation{};
    require(GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &bytes),
        "GetTokenInformation(TokenElevation)");
    Handle impersonation;
    require(DuplicateToken(token.value, SecurityIdentification, &impersonation.value), "DuplicateToken");
    BYTE administrators[SECURITY_MAX_SID_SIZE]{};
    DWORD size = sizeof(administrators);
    require(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &size),
        "CreateWellKnownSid");
    BOOL member = FALSE;
    require(CheckTokenMembership(impersonation.value, administrators, &member), "CheckTokenMembership");
    return elevation.TokenIsElevated != 0 && member != FALSE;
}

inline std::wstring wtsString(DWORD session, WTS_INFO_CLASS field) {
    struct Memory final {
        LPWSTR value = nullptr;
        ~Memory() { if (value) WTSFreeMemory(value); }
    } memory;
    DWORD bytes = 0;
    require(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, field,
        &memory.value, &bytes), "WTSQuerySessionInformationW(account)");
    if (!memory.value || bytes < sizeof(wchar_t) || bytes % sizeof(wchar_t) != 0 ||
        memory.value[0] == L'\0' || memory.value[bytes / sizeof(wchar_t) - 1] != L'\0')
        throw std::runtime_error("Physical console account response is malformed");
    return memory.value;
}

struct Console final {
    DWORD session = 0xffffffff;
    std::wstring sid;
    std::wstring account;
    bool locked = true;
};

inline Console queryConsole() {
    Console result;
    result.session = WTSGetActiveConsoleSessionId();
    if (result.session == 0xffffffff) throw std::runtime_error("No physical console session");
    result.account = wtsString(result.session, WTSDomainName) + L"\\" +
        wtsString(result.session, WTSUserName);
    DWORD sidBytes = 0;
    DWORD domainChars = 0;
    SID_NAME_USE use{};
    if (LookupAccountNameW(nullptr, result.account.c_str(), nullptr, &sidBytes, nullptr,
            &domainChars, &use) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0)
        throw std::runtime_error("Physical console SID size query failed");
    std::vector<BYTE> sid(sidBytes);
    std::vector<wchar_t> domain(domainChars == 0 ? 1 : domainChars);
    require(LookupAccountNameW(nullptr, result.account.c_str(), sid.data(), &sidBytes,
        domain.data(), &domainChars, &use), "LookupAccountNameW(console)");
    if (use != SidTypeUser) throw std::runtime_error("Physical console SID is not a user SID");
    result.sid = sidText(sid.data());
    struct Memory final {
        LPWSTR value = nullptr;
        ~Memory() { if (value) WTSFreeMemory(value); }
    } memory;
    DWORD bytes = 0;
    require(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, result.session, WTSSessionInfoEx,
        &memory.value, &bytes), "WTSQuerySessionInformationW(lock state)");
    if (!memory.value || bytes < sizeof(WTSINFOEXW)) throw std::runtime_error("Malformed console lock state");
    const auto& info = *reinterpret_cast<const WTSINFOEXW*>(memory.value);
    const auto& level = info.Data.WTSInfoExLevel1;
    if (info.Level != 1 || level.SessionId != result.session || level.SessionState != WTSActive ||
        (level.SessionFlags != WTS_SESSIONSTATE_LOCK && level.SessionFlags != WTS_SESSIONSTATE_UNLOCK))
        throw std::runtime_error("Physical console lock state cannot be confirmed");
    result.locked = level.SessionFlags == WTS_SESSIONSTATE_LOCK;
    if (WTSGetActiveConsoleSessionId() != result.session)
        throw std::runtime_error("Physical console changed during query");
    return result;
}

inline std::wstring groupedFingerprint(const std::string& fingerprint) {
    std::wstring result;
    for (std::size_t index = 0; index < fingerprint.size(); ++index) {
        if (index != 0 && index % 8 == 0) result += L' ';
        result += static_cast<wchar_t>(fingerprint[index]);
    }
    return result;
}

} // namespace unlock_windows::enrollment
