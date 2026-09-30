// Created by Rui MA on 29 Sep 2026

#include "Protocol.h"

#include "EnrollmentStore.h"

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <ntsecapi.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <sspi.h>
#include <NTSecPKG.h>
#include <sddl.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using unlock_windows::lsa_convert_probe::Request;

LSA_SECPKG_FUNCTION_TABLE g_lsaFunctions{};
SRWLOCK g_stateLock = SRWLOCK_INIT;
bool g_spInitialized = false;
volatile LONG g_automaticProbeQueued = 0;

struct AccountIdentity final {
    std::wstring name;
    std::wstring domain;

    [[nodiscard]] std::wstring samName() const {
        return domain.empty() ? name : domain + L"\\" + name;
    }
};

struct AutomaticProbeAccount final {
    std::wstring notifiedName;
    std::wstring notifiedSid;
    std::wstring samName;
    std::wstring authority;
    std::wstring sid;
    SECPKG_NAME_TYPE nameType = SecNameSamCompatible;
};

class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
    }
    [[nodiscard]] HANDLE get() const noexcept { return value_; }

private:
    HANDLE value_;
};

class LocalMemory final {
public:
    explicit LocalMemory(HLOCAL value = nullptr) noexcept : value_(value) {}
    LocalMemory(const LocalMemory&) = delete;
    LocalMemory& operator=(const LocalMemory&) = delete;
    ~LocalMemory() {
        if (value_ != nullptr) {
            LocalFree(value_);
        }
    }
    [[nodiscard]] HLOCAL get() const noexcept { return value_; }

private:
    HLOCAL value_;
};

[[nodiscard]] std::wstring statusText(const NTSTATUS status) {
    std::wostringstream output;
    output << L"0x" << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<unsigned long>(status)
           << L" (win32=" << std::dec << LsaNtStatusToWinError(status) << L")";
    return output.str();
}

[[nodiscard]] std::string win32Text(
    const std::string_view operation,
    const DWORD error = GetLastError()
) {
    return std::string(operation) + " failed: " + std::to_string(error);
}

[[nodiscard]] std::wstring sidText(PSID sid) {
    if (sid == nullptr || !IsValidSid(sid)) {
        throw std::runtime_error("invalid SID");
    }
    LPWSTR raw = nullptr;
    if (!ConvertSidToStringSidW(sid, &raw)) {
        throw std::runtime_error(win32Text("ConvertSidToStringSidW"));
    }
    const LocalMemory memory(raw);
    return static_cast<const wchar_t*>(memory.get());
}

[[nodiscard]] bool isSamAccountSid(PSID sid) noexcept {
    if (sid == nullptr || !IsValidSid(sid)) {
        return false;
    }
    constexpr SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    const auto* authority = GetSidIdentifierAuthority(sid);
    const auto* count = GetSidSubAuthorityCount(sid);
    return authority != nullptr && count != nullptr &&
        std::memcmp(authority, &ntAuthority, sizeof(ntAuthority)) == 0 &&
        *count >= 5 &&
        *GetSidSubAuthority(sid, 0) == SECURITY_NT_NON_UNIQUE;
}

[[nodiscard]] std::wstring programDataDirectory() {
    const DWORD required = GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (required == 0) {
        throw std::runtime_error(win32Text("GetEnvironmentVariableW(ProgramData)"));
    }
    std::wstring value(required, L'\0');
    const DWORD length = GetEnvironmentVariableW(
        L"ProgramData",
        value.data(),
        required
    );
    if (length == 0 || length >= required) {
        throw std::runtime_error(win32Text("GetEnvironmentVariableW(ProgramData)"));
    }
    value.resize(length);
    return value;
}

[[nodiscard]] std::wstring targetAccountSetting(
    const wchar_t* name
) {
    const std::wstring path = programDataDirectory() +
        L"\\UnlockWindowsWithIPhone\\LsaConvertProbeInstaller\\target-account.ini";
    std::vector<wchar_t> value(512);
    const DWORD length = GetPrivateProfileStringW(
        L"Target",
        name,
        nullptr,
        value.data(),
        static_cast<DWORD>(value.size()),
        path.c_str()
    );
    if (length == 0) {
        throw std::runtime_error("target account setting is missing");
    }
    if (length + 1 >= value.size()) {
        throw std::runtime_error("target account setting is too long");
    }
    return std::wstring(value.data(), length);
}

[[nodiscard]] AutomaticProbeAccount configuredProbeAccount() {
    AutomaticProbeAccount account;
    account.samName = targetAccountSetting(L"SamName");
    account.sid = targetAccountSetting(L"Sid");

    const auto slash = account.samName.find(L'\\');
    if (slash == std::wstring::npos || slash == 0 ||
        slash + 1 >= account.samName.size()) {
        throw std::runtime_error("configured target is not SAM-compatible");
    }
    account.authority = account.samName.substr(0, slash);

    PSID rawSid = nullptr;
    if (!ConvertStringSidToSidW(account.sid.c_str(), &rawSid)) {
        throw std::runtime_error(win32Text("ConvertStringSidToSidW(configured target)"));
    }
    const LocalMemory sid(rawSid);
    if (!isSamAccountSid(rawSid)) {
        throw std::runtime_error("configured target SID is not a SAM account SID");
    }
    return account;
}

[[nodiscard]] std::wstring unicodeStringValue(const UNICODE_STRING& value) {
    if (value.Length == 0) {
        return {};
    }
    if (value.Buffer == nullptr || value.Length % sizeof(wchar_t) != 0 ||
        value.MaximumLength < value.Length) {
        throw std::invalid_argument("invalid UNICODE_STRING");
    }
    return std::wstring(value.Buffer, value.Length / sizeof(wchar_t));
}

[[nodiscard]] AccountIdentity accountIdentity(PSID sid) {
    DWORD nameLength = 0;
    DWORD domainLength = 0;
    SID_NAME_USE use{};
    LookupAccountSidW(
        nullptr,
        sid,
        nullptr,
        &nameLength,
        nullptr,
        &domainLength,
        &use
    );
    const DWORD sizeError = GetLastError();
    if (sizeError == ERROR_NONE_MAPPED) {
        return {L"<unmapped>", L""};
    }
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || nameLength == 0) {
        throw std::runtime_error(win32Text("LookupAccountSidW(size)", sizeError));
    }

    std::wstring name(nameLength, L'\0');
    std::wstring domain(domainLength, L'\0');
    if (!LookupAccountSidW(
            nullptr,
            sid,
            name.data(),
            &nameLength,
            domain.data(),
            &domainLength,
            &use
        )) {
        throw std::runtime_error(win32Text("LookupAccountSidW"));
    }
    name.resize(nameLength);
    domain.resize(domainLength);
    return {std::move(name), std::move(domain)};
}

[[nodiscard]] std::wstring accountName(PSID sid) {
    const auto identity = accountIdentity(sid);
    return identity.samName();
}

[[nodiscard]] std::vector<std::uint8_t> tokenInformation(
    const HANDLE token,
    const TOKEN_INFORMATION_CLASS informationClass
) {
    DWORD required = 0;
    GetTokenInformation(token, informationClass, nullptr, 0, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
        throw std::runtime_error(win32Text("GetTokenInformation(size)"));
    }
    std::vector<std::uint8_t> value(required);
    if (!GetTokenInformation(
            token,
            informationClass,
            value.data(),
            static_cast<DWORD>(value.size()),
            &required
        )) {
        throw std::runtime_error(win32Text("GetTokenInformation"));
    }
    return value;
}

template<typename Value>
[[nodiscard]] Value fixedTokenInformation(
    const HANDLE token,
    const TOKEN_INFORMATION_CLASS informationClass,
    const char* operation
) {
    Value value{};
    DWORD returned = 0;
    if (!GetTokenInformation(
            token,
            informationClass,
            &value,
            static_cast<DWORD>(sizeof(value)),
            &returned
        )) {
        throw std::runtime_error(win32Text(operation));
    }
    if (returned != sizeof(value)) {
        throw std::runtime_error(std::string(operation) + " returned size " +
                                 std::to_string(returned));
    }
    return value;
}

[[nodiscard]] bool tokenHasRestrictions(const HANDLE token) {
    DWORD value = 0;
    DWORD returned = 0;
    if (!GetTokenInformation(
            token,
            TokenHasRestrictions,
            &value,
            sizeof(value),
            &returned
        )) {
        throw std::runtime_error(
            win32Text("GetTokenInformation(TokenHasRestrictions)")
        );
    }
    if (returned != sizeof(BOOLEAN) && returned != sizeof(DWORD)) {
        throw std::runtime_error(
            "GetTokenInformation(TokenHasRestrictions) returned size " +
            std::to_string(returned)
        );
    }
    return value != 0;
}

[[nodiscard]] std::wstring privilegeName(const LUID luid) {
    DWORD required = 0;
    LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&luid), nullptr, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
        throw std::runtime_error(win32Text("LookupPrivilegeNameW(size)"));
    }
    std::wstring name(required + 1, L'\0');
    if (!LookupPrivilegeNameW(
            nullptr,
            const_cast<PLUID>(&luid),
            name.data(),
            &required
        )) {
        throw std::runtime_error(win32Text("LookupPrivilegeNameW"));
    }
    name.resize(required);
    return name;
}

[[nodiscard]] std::wstring defaultDaclSddl(PACL dacl) {
    if (dacl == nullptr) {
        return L"<null>";
    }
    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, FALSE)) {
        throw std::runtime_error(win32Text("construct default DACL descriptor"));
    }
    LPWSTR raw = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            &descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &raw,
            nullptr
        )) {
        throw std::runtime_error(
            win32Text("ConvertSecurityDescriptorToStringSecurityDescriptorW")
        );
    }
    const LocalMemory memory(raw);
    return static_cast<const wchar_t*>(memory.get());
}

[[nodiscard]] const wchar_t* elevationTypeName(TOKEN_ELEVATION_TYPE value) {
    switch (value) {
    case TokenElevationTypeDefault: return L"Default";
    case TokenElevationTypeFull: return L"Full";
    case TokenElevationTypeLimited: return L"Limited";
    default: return L"Unknown";
    }
}

[[nodiscard]] const wchar_t* tokenTypeName(TOKEN_TYPE value) {
    switch (value) {
    case TokenPrimary: return L"Primary";
    case TokenImpersonation: return L"Impersonation";
    default: return L"Unknown";
    }
}

void appendTokenReport(
    std::wostringstream& output,
    const HANDLE token,
    const bool resolveNames
) {
    const auto userBuffer = tokenInformation(token, TokenUser);
    const auto groupsBuffer = tokenInformation(token, TokenGroups);
    const auto privilegesBuffer = tokenInformation(token, TokenPrivileges);
    const auto primaryGroupBuffer = tokenInformation(token, TokenPrimaryGroup);
    const auto ownerBuffer = tokenInformation(token, TokenOwner);
    const auto defaultDaclBuffer = tokenInformation(token, TokenDefaultDacl);
    const auto statisticsBuffer = tokenInformation(token, TokenStatistics);
    const auto integrityBuffer = tokenInformation(token, TokenIntegrityLevel);
    const auto elevationType = fixedTokenInformation<TOKEN_ELEVATION_TYPE>(
        token, TokenElevationType, "GetTokenInformation(TokenElevationType)"
    );
    const auto elevation = fixedTokenInformation<TOKEN_ELEVATION>(
        token, TokenElevation, "GetTokenInformation(TokenElevation)"
    );
    const auto type = fixedTokenInformation<TOKEN_TYPE>(
        token, TokenType, "GetTokenInformation(TokenType)"
    );

    const auto* user = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groupsBuffer.data());
    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(
        privilegesBuffer.data()
    );
    const auto* primaryGroup = reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(
        primaryGroupBuffer.data()
    );
    const auto* owner = reinterpret_cast<const TOKEN_OWNER*>(ownerBuffer.data());
    const auto* defaultDacl = reinterpret_cast<const TOKEN_DEFAULT_DACL*>(
        defaultDaclBuffer.data()
    );
    const auto* statistics = reinterpret_cast<const TOKEN_STATISTICS*>(
        statisticsBuffer.data()
    );
    const auto* integrity = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(
        integrityBuffer.data()
    );

    output << L"\n[ConvertAuthDataToToken result]\n"
           << L"  userSid=" << sidText(user->User.Sid) << L"\n";
    if (resolveNames) {
        output << L"  user=" << accountName(user->User.Sid) << L"\n";
    }
    output
           << L"  authenticationId=" << statistics->AuthenticationId.HighPart
           << L":" << statistics->AuthenticationId.LowPart << L"\n"
           << L"  tokenType=" << tokenTypeName(type) << L"\n"
           << L"  elevationType=" << elevationTypeName(elevationType) << L"\n"
           << L"  elevated=" << (elevation.TokenIsElevated ? L"true" : L"false")
           << L"\n"
           << L"  hasRestrictions=" << (tokenHasRestrictions(token) ? L"true" : L"false")
           << L"\n"
           << L"  integrityLevel=" << sidText(integrity->Label.Sid);
    if (resolveNames) {
        output << L" " << accountName(integrity->Label.Sid);
    }
    output << L" attributes=0x" << std::hex << integrity->Label.Attributes
           << std::dec << L"\n"
           << L"  primaryGroup=" << sidText(primaryGroup->PrimaryGroup);
    if (resolveNames) {
        output << L" " << accountName(primaryGroup->PrimaryGroup);
    }
    output << L"\n"
           << L"  owner="
           << (owner->Owner == nullptr ? L"<default-user>" : sidText(owner->Owner))
           << L"\n"
           << L"  defaultDacl=" << defaultDaclSddl(defaultDacl->DefaultDacl) << L"\n";

    output << L"\n[groups] count=" << groups->GroupCount << L"\n";
    for (DWORD index = 0; index < groups->GroupCount; ++index) {
        const auto& group = groups->Groups[index];
        output << L"  " << sidText(group.Sid);
        if (resolveNames) {
            output << L" " << accountName(group.Sid);
        }
        output << L" attributes=0x" << std::hex << group.Attributes << std::dec
               << L"\n";
    }

    output << L"\n[privileges] count=" << privileges->PrivilegeCount << L"\n";
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index) {
        const auto& privilege = privileges->Privileges[index];
        output << L"  ";
        if (resolveNames) {
            output << privilegeName(privilege.Luid);
        } else {
            output << L"luid=" << privilege.Luid.HighPart << L":"
                   << privilege.Luid.LowPart;
        }
        output << L" attributes=0x" << std::hex << privilege.Attributes
               << std::dec << L"\n";
    }
}

[[nodiscard]] std::wstring tokenUserSid(const HANDLE token) {
    const auto userBuffer = tokenInformation(token, TokenUser);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    return sidText(user->User.Sid);
}

[[nodiscard]] UNICODE_STRING unicodeString(std::wstring& value) {
    if (value.size() > std::numeric_limits<USHORT>::max() / sizeof(wchar_t)) {
        throw std::runtime_error("Unicode string is too long");
    }
    UNICODE_STRING result{};
    result.Buffer = value.data();
    result.Length = static_cast<USHORT>(value.size() * sizeof(wchar_t));
    result.MaximumLength = result.Length;
    return result;
}

[[nodiscard]] SECURITY_STRING securityString(std::wstring& value) {
    if (value.size() > std::numeric_limits<USHORT>::max() / sizeof(wchar_t)) {
        throw std::runtime_error("Security string is too long");
    }
    SECURITY_STRING result{};
    result.Buffer = reinterpret_cast<unsigned short*>(value.data());
    result.Length = static_cast<USHORT>(value.size() * sizeof(wchar_t));
    result.MaximumLength = result.Length;
    return result;
}

class LsaReturnBuffer final {
public:
    LsaReturnBuffer(
        PVOID value,
        PLSA_FREE_LSA_HEAP freeFunction
    ) noexcept : value_(value), freeFunction_(freeFunction) {}
    LsaReturnBuffer(const LsaReturnBuffer&) = delete;
    LsaReturnBuffer& operator=(const LsaReturnBuffer&) = delete;
    ~LsaReturnBuffer() {
        if (value_ != nullptr && freeFunction_ != nullptr) {
            freeFunction_(value_);
        }
    }

private:
    PVOID value_;
    PLSA_FREE_LSA_HEAP freeFunction_;
};

[[nodiscard]] std::wstring runProbe(
    NTSTATUS& protocolStatus,
    const AutomaticProbeAccount* automaticAccount = nullptr
) {
    std::wostringstream output;
    output << L"Unlock Windows with iPhone - LSA ConvertAuthDataToToken probe\n"
           << L"mode=GetAuthDataForUser+ConvertAuthDataToToken\n"
           << L"requestedLogonType=Interactive\n"
           << L"productionTokenConstruction=not-authorized\n";

    try {
        LSA_SECPKG_FUNCTION_TABLE functions{};
        AcquireSRWLockShared(&g_stateLock);
        const bool ready = g_spInitialized;
        if (ready) {
            functions = g_lsaFunctions;
        }
        ReleaseSRWLockShared(&g_stateLock);

        output << L"\n[LSA helper availability]\n"
               << L"  SpInitialize=" << (ready ? L"called" : L"not-called") << L"\n"
               << L"  GetAuthDataForUser="
               << (functions.GetAuthDataForUser != nullptr ? L"available" : L"missing")
               << L"\n"
               << L"  ConvertAuthDataToToken="
               << (functions.ConvertAuthDataToToken != nullptr ? L"available" : L"missing")
               << L"\n"
               << L"  FreeReturnBuffer="
               << (functions.FreeReturnBuffer != nullptr ? L"available" : L"missing")
               << L"\n"
               << L"  AllocateClientBuffer="
               << (functions.AllocateClientBuffer != nullptr ? L"available" : L"missing")
               << L"\n"
               << L"  FreeClientBuffer="
               << (functions.FreeClientBuffer != nullptr ? L"available" : L"missing")
               << L"\n"
               << L"  CopyToClientBuffer="
               << (functions.CopyToClientBuffer != nullptr ? L"available" : L"missing")
               << L"\n";

        if (!ready) {
            protocolStatus = STATUS_INVALID_SERVER_STATE;
            output << L"probeStatus=" << statusText(protocolStatus) << L"\n"
                   << L"error=SpInitialize did not provide the LSA function table\n";
            return output.str();
        }
        if (functions.GetAuthDataForUser == nullptr ||
            functions.ConvertAuthDataToToken == nullptr ||
            functions.FreeReturnBuffer == nullptr) {
            protocolStatus = STATUS_NOT_SUPPORTED;
            output << L"probeStatus=" << statusText(protocolStatus) << L"\n"
                   << L"error=one or more conversion helpers are unavailable\n";
            return output.str();
        }

        AccountIdentity identity;
        std::wstring targetSid;
        std::wstring samName;
        std::wstring authority;
        SECPKG_NAME_TYPE nameType = SecNameSamCompatible;
        if (automaticAccount != nullptr) {
            samName = automaticAccount->samName;
            authority = automaticAccount->authority;
            targetSid = automaticAccount->sid;
            nameType = automaticAccount->nameType;
            output << L"accountSource=installer-config\n"
                   << L"triggerAccount=" << automaticAccount->notifiedName << L"\n"
                   << L"triggerSid=" << automaticAccount->notifiedSid << L"\n";
        } else {
            const unlock_windows::service::EnrollmentStore store;
            const auto enrollment = store.load();
            if (!enrollment) {
                protocolStatus = STATUS_NO_SUCH_USER;
                output << L"probeStatus=" << statusText(protocolStatus) << L"\n"
                       << L"error=protected enrollment record is missing\n";
                return output.str();
            }

            PSID rawSid = nullptr;
            if (!ConvertStringSidToSidW(enrollment->accountSid.c_str(), &rawSid)) {
                throw std::runtime_error(win32Text("ConvertStringSidToSidW"));
            }
            const LocalMemory sid(rawSid);
            identity = accountIdentity(rawSid);
            targetSid = enrollment->accountSid;
            samName = identity.samName();
            authority = identity.domain;
            output << L"accountSource=protected-enrollment\n";
        }

        auto name = securityString(samName);
        auto authorityName = unicodeString(authority);

        output << L"targetSid=" << targetSid << L"\n"
               << L"samName=" << samName << L"\n"
               << L"authority=" << authority << L"\n";

        PUCHAR authData = nullptr;
        ULONG authDataSize = 0;
        const NTSTATUS getStatus = functions.GetAuthDataForUser(
            &name,
            nameType,
            nullptr,
            &authData,
            &authDataSize,
            nullptr
        );
        const LsaReturnBuffer authDataOwner(authData, functions.FreeReturnBuffer);
        output << L"GetAuthDataForUser.status=" << statusText(getStatus)
               << L"\nGetAuthDataForUser.bytes=" << authDataSize << L"\n";
        if (getStatus < 0) {
            protocolStatus = getStatus;
            output << L"probeStatus=" << statusText(protocolStatus) << L"\n";
            return output.str();
        }

        TOKEN_SOURCE source{};
        constexpr char sourceName[sizeof(source.SourceName)] = {
            'U', 'W', 'I', 'P', 'r', 'o', 'b', 'e'
        };
        std::memcpy(source.SourceName, sourceName, sizeof(source.SourceName));
        if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
            throw std::runtime_error(win32Text("AllocateLocallyUniqueId"));
        }

        HANDLE rawToken = nullptr;
        LUID logonId{};
        UNICODE_STRING convertedAccountName{};
        NTSTATUS subStatus = STATUS_SUCCESS;
        const NTSTATUS convertStatus = functions.ConvertAuthDataToToken(
            authData,
            authDataSize,
            SecurityImpersonation,
            &source,
            Interactive,
            &authorityName,
            &rawToken,
            &logonId,
            &convertedAccountName,
            &subStatus
        );
        const Handle token(rawToken);

        output << L"ConvertAuthDataToToken.status=" << statusText(convertStatus)
               << L"\nConvertAuthDataToToken.subStatus=" << statusText(subStatus)
               << L"\nreturnedLogonId=" << logonId.HighPart << L":" << logonId.LowPart
               << L"\n";
        if (convertedAccountName.Buffer != nullptr) {
            output << L"returnedAccountName="
                   << std::wstring_view(
                          convertedAccountName.Buffer,
                          convertedAccountName.Length / sizeof(wchar_t)
                      )
                   << L"\n";
        }

        if (convertStatus < 0) {
            protocolStatus = convertStatus;
            output << L"probeStatus=" << statusText(protocolStatus) << L"\n";
            return output.str();
        }
        if (rawToken == nullptr || rawToken == INVALID_HANDLE_VALUE) {
            protocolStatus = STATUS_INVALID_HANDLE;
            output << L"error=conversion succeeded without a valid token handle\n";
            return output.str();
        }

        appendTokenReport(output, token.get(), automaticAccount == nullptr);
        if (automaticAccount != nullptr) {
            const std::wstring convertedUserSid = tokenUserSid(token.get());
            const bool matchesTarget = convertedUserSid == targetSid;
            output << L"\nexpectedUserSid=" << targetSid
                   << L"\nexpectedUserSidMatch="
                   << (matchesTarget ? L"true" : L"false") << L"\n";
            if (!matchesTarget) {
                protocolStatus = STATUS_INVALID_SID;
                output << L"probeStatus=" << statusText(protocolStatus) << L"\n"
                       << L"error=converted token user SID does not match installer target\n";
                return output.str();
            }
        }
        protocolStatus = STATUS_SUCCESS;
        output << L"\nprobeStatus=" << statusText(protocolStatus) << L"\n";
    } catch (const std::exception& error) {
        protocolStatus = STATUS_INTERNAL_ERROR;
        output << L"probeStatus=" << statusText(protocolStatus) << L"\n"
               << L"error=" << error.what() << L"\n";
    } catch (...) {
        protocolStatus = STATUS_INTERNAL_ERROR;
        output << L"probeStatus=" << statusText(protocolStatus) << L"\n"
               << L"error=unknown exception\n";
    }
    return output.str();
}

[[nodiscard]] std::wstring automaticReportPath() {
    return programDataDirectory() +
        L"\\UnlockWindowsWithIPhone\\LsaConvertProbeInstaller\\report.txt";
}

void writeAutomaticReport(const std::wstring& report) {
    const std::wstring path = automaticReportPath();
    const Handle file(CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));
    if (file.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(win32Text("CreateFileW(automatic report)"));
    }

    constexpr wchar_t byteOrderMark = 0xfeff;
    DWORD written = 0;
    if (!WriteFile(
            file.get(),
            &byteOrderMark,
            sizeof(byteOrderMark),
            &written,
            nullptr
        ) || written != sizeof(byteOrderMark)) {
        throw std::runtime_error(win32Text("WriteFile(automatic report BOM)"));
    }

    if (report.size() > std::numeric_limits<DWORD>::max() / sizeof(wchar_t)) {
        throw std::runtime_error("automatic report is too large");
    }
    const DWORD bytes = static_cast<DWORD>(report.size() * sizeof(wchar_t));
    written = 0;
    if (bytes != 0 &&
        (!WriteFile(file.get(), report.data(), bytes, &written, nullptr) ||
         written != bytes)) {
        throw std::runtime_error(win32Text("WriteFile(automatic report body)"));
    }
}

void writeAutomaticReportNoexcept(const std::wstring& report) noexcept {
    try {
        writeAutomaticReport(report);
    } catch (const std::exception& error) {
        OutputDebugStringA("LSA convert probe could not write its automatic report: ");
        OutputDebugStringA(error.what());
        OutputDebugStringA("\n");
    } catch (...) {
        OutputDebugStringA(
            "LSA convert probe could not write its automatic report: unknown error\n"
        );
    }
}

[[nodiscard]] std::wstring initializationReport(
    const LSA_SECPKG_FUNCTION_TABLE& functions
) {
    std::wostringstream output;
    output << L"Unlock Windows with iPhone - LSA ConvertAuthDataToToken probe\n"
           << L"mode=automatic-SpAcceptCredentials\n"
           << L"stage=SpInitialize\n"
           << L"productionTokenConstruction=not-authorized\n\n"
           << L"[LSA helper availability]\n"
           << L"  GetAuthDataForUser="
           << (functions.GetAuthDataForUser != nullptr ? L"available" : L"missing")
           << L"\n  ConvertAuthDataToToken="
           << (functions.ConvertAuthDataToToken != nullptr ? L"available" : L"missing")
           << L"\n  FreeReturnBuffer="
           << (functions.FreeReturnBuffer != nullptr ? L"available" : L"missing")
           << L"\n";
    try {
        const AutomaticProbeAccount target = configuredProbeAccount();
        output << L"configuredSamName=" << target.samName
               << L"\nconfiguredSid=" << target.sid << L"\n";
    } catch (const std::exception& error) {
        output << L"targetConfigError=" << error.what() << L"\n";
    }
    output << L"waitingFor=interactive-or-unlock-trigger\n";
    return output.str();
}

DWORD WINAPI automaticProbeWorker(PVOID context) {
    try {
        const std::unique_ptr<AutomaticProbeAccount> account(
            static_cast<AutomaticProbeAccount*>(context)
        );
        if (!account) {
            throw std::invalid_argument("automatic probe account is missing");
        }
        NTSTATUS status = STATUS_INTERNAL_ERROR;
        const std::wstring report = runProbe(status, account.get());
        writeAutomaticReportNoexcept(report);
        return status < 0 ? 1 : 0;
    } catch (const std::exception& error) {
        OutputDebugStringA("LSA convert probe worker failed: ");
        OutputDebugStringA(error.what());
        OutputDebugStringA("\n");
    } catch (...) {
        OutputDebugStringA("LSA convert probe worker failed: unknown error\n");
    }
    return 1;
}

[[nodiscard]] NTSTATUS copyReportToClient(
    PLSA_CLIENT_REQUEST clientRequest,
    const std::wstring& report,
    PVOID* protocolReturnBuffer,
    PULONG returnBufferLength
) noexcept {
    if (g_lsaFunctions.AllocateClientBuffer == nullptr ||
        g_lsaFunctions.FreeClientBuffer == nullptr ||
        g_lsaFunctions.CopyToClientBuffer == nullptr) {
        return STATUS_INVALID_SERVER_STATE;
    }
    if (report.size() >
        (unlock_windows::lsa_convert_probe::kMaximumReportBytes / sizeof(wchar_t)) - 1) {
        return STATUS_BUFFER_OVERFLOW;
    }
    const auto bytes = static_cast<ULONG>((report.size() + 1) * sizeof(wchar_t));
    PVOID clientBuffer = nullptr;
    NTSTATUS status = g_lsaFunctions.AllocateClientBuffer(
        clientRequest,
        bytes,
        &clientBuffer
    );
    if (status < 0) {
        return status;
    }
    status = g_lsaFunctions.CopyToClientBuffer(
        clientRequest,
        bytes,
        clientBuffer,
        const_cast<wchar_t*>(report.c_str())
    );
    if (status < 0) {
        g_lsaFunctions.FreeClientBuffer(clientRequest, clientBuffer);
        return status;
    }
    *protocolReturnBuffer = clientBuffer;
    *returnBufferLength = bytes;
    return STATUS_SUCCESS;
}

[[nodiscard]] PLSA_STRING allocatePackageName(
    const LSA_DISPATCH_TABLE& dispatch
) noexcept {
    constexpr std::string_view name = unlock_windows::lsa_convert_probe::kPackageName;
    auto* value = static_cast<PLSA_STRING>(
        dispatch.AllocateLsaHeap(sizeof(LSA_STRING))
    );
    if (value == nullptr) {
        return nullptr;
    }
    auto* buffer = static_cast<PCHAR>(dispatch.AllocateLsaHeap(name.size() + 1));
    if (buffer == nullptr) {
        dispatch.FreeLsaHeap(value);
        return nullptr;
    }
    std::memcpy(buffer, name.data(), name.size());
    buffer[name.size()] = '\0';
    value->Buffer = buffer;
    value->Length = static_cast<USHORT>(name.size());
    value->MaximumLength = static_cast<USHORT>(name.size() + 1);
    return value;
}

NTSTATUS NTAPI initializePackage(
    ULONG,
    PLSA_DISPATCH_TABLE dispatch,
    PLSA_STRING,
    PLSA_STRING,
    PLSA_STRING* packageName
) {
    if (dispatch == nullptr || packageName == nullptr ||
        dispatch->AllocateLsaHeap == nullptr || dispatch->FreeLsaHeap == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *packageName = allocatePackageName(*dispatch);
    if (*packageName == nullptr) {
        return STATUS_NO_MEMORY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI rejectLogon(
    PLSA_CLIENT_REQUEST,
    SECURITY_LOGON_TYPE,
    PVOID,
    PVOID,
    ULONG,
    PVOID* profileBuffer,
    PULONG profileBufferSize,
    PLUID,
    PNTSTATUS subStatus,
    PLSA_TOKEN_INFORMATION_TYPE,
    PVOID* tokenInformation,
    PUNICODE_STRING*,
    PUNICODE_STRING*,
    PUNICODE_STRING*,
    PSECPKG_PRIMARY_CRED,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY*
) {
    if (profileBuffer != nullptr) *profileBuffer = nullptr;
    if (profileBufferSize != nullptr) *profileBufferSize = 0;
    if (tokenInformation != nullptr) *tokenInformation = nullptr;
    if (subStatus != nullptr) *subStatus = STATUS_NOT_SUPPORTED;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI callPackage(
    PLSA_CLIENT_REQUEST clientRequest,
    PVOID protocolSubmitBuffer,
    PVOID,
    ULONG submitBufferLength,
    PVOID* protocolReturnBuffer,
    PULONG returnBufferLength,
    PNTSTATUS protocolStatus
) {
    if (protocolReturnBuffer == nullptr || returnBufferLength == nullptr ||
        protocolStatus == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *protocolReturnBuffer = nullptr;
    *returnBufferLength = 0;
    *protocolStatus = STATUS_INVALID_PARAMETER;
    if (clientRequest == nullptr || protocolSubmitBuffer == nullptr ||
        submitBufferLength != sizeof(Request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Request request{};
    std::memcpy(&request, protocolSubmitBuffer, sizeof(request));
    if (request.magic != unlock_windows::lsa_convert_probe::kRequestMagic ||
        request.version != unlock_windows::lsa_convert_probe::kRequestVersion ||
        request.operation != unlock_windows::lsa_convert_probe::kRunInteractiveConversion ||
        request.reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    const std::wstring report = runProbe(*protocolStatus);
    return copyReportToClient(
        clientRequest,
        report,
        protocolReturnBuffer,
        returnBufferLength
    );
}

NTSTATUS NTAPI rejectPackageCall(
    PLSA_CLIENT_REQUEST,
    PVOID,
    PVOID,
    ULONG,
    PVOID* protocolReturnBuffer,
    PULONG returnBufferLength,
    PNTSTATUS protocolStatus
) {
    if (protocolReturnBuffer != nullptr) *protocolReturnBuffer = nullptr;
    if (returnBufferLength != nullptr) *returnBufferLength = 0;
    if (protocolStatus != nullptr) *protocolStatus = STATUS_ACCESS_DENIED;
    return STATUS_ACCESS_DENIED;
}

VOID NTAPI logonTerminated(PLUID) {}

NTSTATUS NTAPI spInitialize(
    ULONG_PTR,
    PSECPKG_PARAMETERS,
    PLSA_SECPKG_FUNCTION_TABLE functions
) {
    if (functions == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    AcquireSRWLockExclusive(&g_stateLock);
    g_lsaFunctions = *functions;
    g_spInitialized = true;
    ReleaseSRWLockExclusive(&g_stateLock);
    writeAutomaticReportNoexcept(initializationReport(*functions));
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI acceptCredentials(
    SECURITY_LOGON_TYPE logonType,
    PUNICODE_STRING accountName,
    PSECPKG_PRIMARY_CRED primaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED
) {
    if (logonType != Interactive && logonType != Unlock) {
        return STATUS_SUCCESS;
    }

    bool claimedAutomaticProbe = false;
    try {
        if (accountName == nullptr || accountName->Buffer == nullptr ||
            accountName->Length == 0 ||
            accountName->Length % sizeof(wchar_t) != 0) {
            throw std::invalid_argument(
                "SpAcceptCredentials supplied an invalid account name"
            );
        }
        if (primaryCredentials == nullptr ||
            primaryCredentials->UserSid == nullptr ||
            !IsValidSid(primaryCredentials->UserSid)) {
            throw std::invalid_argument(
                "SpAcceptCredentials supplied no valid primary-credential SID"
            );
        }

        const std::wstring notifiedName = unicodeStringValue(*accountName);
        const std::wstring notifiedSamName = unicodeStringValue(
            primaryCredentials->DownlevelName
        );

        const bool serviceIdentity =
            IsWellKnownSid(primaryCredentials->UserSid, WinLocalSystemSid) ||
            IsWellKnownSid(primaryCredentials->UserSid, WinLocalServiceSid) ||
            IsWellKnownSid(primaryCredentials->UserSid, WinNetworkServiceSid);
        const bool machineAccount =
            (!notifiedName.empty() && notifiedName.back() == L'$') ||
            (!notifiedSamName.empty() && notifiedSamName.back() == L'$');
        if (serviceIdentity || machineAccount) {
            return STATUS_SUCCESS;
        }

        auto account = std::make_unique<AutomaticProbeAccount>(
            configuredProbeAccount()
        );
        account->notifiedName = notifiedName;
        account->notifiedSid = sidText(primaryCredentials->UserSid);

        if (InterlockedCompareExchange(&g_automaticProbeQueued, 1, 0) != 0) {
            return STATUS_SUCCESS;
        }
        claimedAutomaticProbe = true;
        if (!QueueUserWorkItem(
                automaticProbeWorker,
                account.get(),
                WT_EXECUTEDEFAULT
            )) {
            throw std::runtime_error(win32Text("QueueUserWorkItem"));
        }
        account.release();
    } catch (const std::exception& error) {
        if (claimedAutomaticProbe) {
            InterlockedExchange(&g_automaticProbeQueued, 0);
        }
        std::wostringstream output;
        output << L"Unlock Windows with iPhone - LSA ConvertAuthDataToToken probe\n"
               << L"mode=automatic-SpAcceptCredentials\n"
               << L"stage=SpAcceptCredentials\n"
               << L"productionTokenConstruction=not-authorized\n"
               << L"probeStatus=not-started\n"
               << L"error=" << error.what() << L"\n";
        writeAutomaticReportNoexcept(output.str());
    } catch (...) {
        if (claimedAutomaticProbe) {
            InterlockedExchange(&g_automaticProbeQueued, 0);
        }
        writeAutomaticReportNoexcept(
            L"Unlock Windows with iPhone - LSA ConvertAuthDataToToken probe\n"
            L"mode=automatic-SpAcceptCredentials\n"
            L"stage=SpAcceptCredentials\n"
            L"productionTokenConstruction=not-authorized\n"
            L"probeStatus=not-started\n"
            L"error=unknown exception\n"
        );
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI spShutdown() {
    AcquireSRWLockExclusive(&g_stateLock);
    g_lsaFunctions = {};
    g_spInitialized = false;
    ReleaseSRWLockExclusive(&g_stateLock);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI spGetInfo(PSecPkgInfo packageInfo) {
    if (packageInfo == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    static SEC_CHAR name[] = "UnlockWindowsWithIPhoneConvertProbe";
    static SEC_CHAR comment[] = "Diagnostic-only interactive token conversion probe";
    *packageInfo = {};
    packageInfo->fCapabilities = SECPKG_FLAG_LOGON;
    packageInfo->wVersion = 1;
    packageInfo->wRPCID = SECPKG_ID_NONE;
    packageInfo->Name = name;
    packageInfo->Comment = comment;
    return STATUS_SUCCESS;
}

SECPKG_FUNCTION_TABLE g_packageFunctions = [] {
    SECPKG_FUNCTION_TABLE functions{};
    functions.InitializePackage = initializePackage;
    functions.CallPackage = callPackage;
    functions.LogonTerminated = logonTerminated;
    functions.CallPackageUntrusted = rejectPackageCall;
    functions.CallPackagePassthrough = rejectPackageCall;
    functions.LogonUserEx2 = rejectLogon;
    functions.Initialize = spInitialize;
    functions.Shutdown = spShutdown;
    functions.GetInfo = spGetInfo;
    functions.AcceptCredentials = acceptCredentials;
    return functions;
}();

} // namespace

extern "C" __declspec(dllexport) NTSTATUS SEC_ENTRY SpLsaModeInitialize(
    const ULONG lsaVersion,
    PULONG packageVersion,
    PSECPKG_FUNCTION_TABLE* tables,
    PULONG tableCount
) {
    if (packageVersion == nullptr || tables == nullptr || tableCount == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (lsaVersion < SECPKG_INTERFACE_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    *packageVersion = SECPKG_INTERFACE_VERSION;
    *tables = &g_packageFunctions;
    *tableCount = 1;
    return STATUS_SUCCESS;
}
