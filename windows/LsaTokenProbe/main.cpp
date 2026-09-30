// Created by Rui MA on 29 Sep 2026

#include "EnrollmentStore.h"

#include <Windows.h>
#include <authz.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

class Handle final {
public:
    Handle() = default;
    explicit Handle(HANDLE value) noexcept : value_(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    Handle(Handle&& other) noexcept : value_(other.value_) {
        other.value_ = nullptr;
    }

    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
                CloseHandle(value_);
            }
            value_ = other.value_;
            other.value_ = nullptr;
        }
        return *this;
    }

    ~Handle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
    }

    [[nodiscard]] HANDLE get() const noexcept {
        return value_;
    }

private:
    HANDLE value_ = nullptr;
};

class AuthzResourceManager final {
public:
    AuthzResourceManager() {
        if (!AuthzInitializeResourceManager(
                AUTHZ_RM_FLAG_NO_AUDIT,
                nullptr,
                nullptr,
                nullptr,
                L"UnlockWindowsWithIPhoneTokenProbe",
                &value_
            )) {
            throw std::runtime_error("AuthzInitializeResourceManager failed: " +
                                     std::to_string(GetLastError()));
        }
    }

    AuthzResourceManager(const AuthzResourceManager&) = delete;
    AuthzResourceManager& operator=(const AuthzResourceManager&) = delete;

    ~AuthzResourceManager() {
        if (value_ != nullptr) {
            AuthzFreeResourceManager(value_);
        }
    }

    [[nodiscard]] AUTHZ_RESOURCE_MANAGER_HANDLE get() const noexcept {
        return value_;
    }

private:
    AUTHZ_RESOURCE_MANAGER_HANDLE value_ = nullptr;
};

class AuthzContext final {
public:
    AuthzContext(PSID userSid, const AUTHZ_RESOURCE_MANAGER_HANDLE resourceManager) {
        LUID identifier{};
        if (!AllocateLocallyUniqueId(&identifier)) {
            throw std::runtime_error("AllocateLocallyUniqueId failed: " +
                                     std::to_string(GetLastError()));
        }
        if (!AuthzInitializeContextFromSid(
                AUTHZ_COMPUTE_PRIVILEGES,
                userSid,
                resourceManager,
                nullptr,
                identifier,
                nullptr,
                &value_
            )) {
            throw std::runtime_error("AuthzInitializeContextFromSid failed: " +
                                     std::to_string(GetLastError()));
        }
    }

    AuthzContext(const AuthzContext&) = delete;
    AuthzContext& operator=(const AuthzContext&) = delete;

    ~AuthzContext() {
        if (value_ != nullptr) {
            AuthzFreeContext(value_);
        }
    }

    [[nodiscard]] AUTHZ_CLIENT_CONTEXT_HANDLE get() const noexcept {
        return value_;
    }

private:
    AUTHZ_CLIENT_CONTEXT_HANDLE value_ = nullptr;
};

struct GroupEntry final {
    std::wstring sid;
    std::wstring account;
    DWORD attributes = 0;
};

struct PrivilegeEntry final {
    std::wstring name;
    DWORD attributes = 0;
};

struct AccountIdentity final {
    std::wstring name;
    std::wstring domain;

    [[nodiscard]] std::wstring qualifiedName() const {
        return domain.empty() ? name : domain + L"\\" + name;
    }
};

struct TokenSnapshot final {
    std::wstring userSid;
    std::wstring userAccount;
    LUID authenticationId{};
    TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
    bool elevated = false;
    bool hasRestrictions = false;
    TOKEN_TYPE tokenType = TokenPrimary;
    std::wstring integrityLevelSid;
    std::wstring integrityLevelAccount;
    DWORD integrityLevelAttributes = 0;
    std::wstring primaryGroupSid;
    std::wstring primaryGroupAccount;
    std::wstring ownerSid;
    std::wstring defaultDacl;
    std::vector<GroupEntry> groups;
    std::vector<PrivilegeEntry> privileges;
};

[[nodiscard]] std::string win32Failure(
    const std::string_view operation,
    const DWORD error = GetLastError()
) {
    return std::string(operation) + " failed: " + std::to_string(error);
}

[[nodiscard]] std::wstring sidText(PSID sid) {
    if (sid == nullptr || !IsValidSid(sid)) {
        throw std::runtime_error("encountered an invalid SID");
    }
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) {
        throw std::runtime_error(win32Failure("ConvertSidToStringSidW"));
    }
    std::wstring result(text);
    LocalFree(text);
    return result;
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
    const auto sizeError = GetLastError();
    if (sizeError == ERROR_NONE_MAPPED) {
        return {L"<unmapped>", L""};
    }
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || nameLength == 0) {
        throw std::runtime_error(win32Failure("LookupAccountSidW(size)", sizeError));
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
        throw std::runtime_error(win32Failure("LookupAccountSidW"));
    }
    name.resize(nameLength);
    domain.resize(domainLength);
    return {std::move(name), std::move(domain)};
}

[[nodiscard]] std::wstring accountName(PSID sid) {
    return accountIdentity(sid).qualifiedName();
}

[[nodiscard]] std::vector<std::uint8_t> tokenInformation(
    const HANDLE token,
    const TOKEN_INFORMATION_CLASS informationClass
) {
    DWORD required = 0;
    GetTokenInformation(token, informationClass, nullptr, 0, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
        throw std::runtime_error(win32Failure("GetTokenInformation(size)"));
    }

    std::vector<std::uint8_t> buffer(required);
    if (!GetTokenInformation(
            token,
            informationClass,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &required
        )) {
        throw std::runtime_error(win32Failure("GetTokenInformation"));
    }
    return buffer;
}

template<typename Value>
[[nodiscard]] Value fixedTokenInformation(
    const HANDLE token,
    const TOKEN_INFORMATION_CLASS informationClass,
    const std::string_view operation
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
        throw std::runtime_error(win32Failure(operation));
    }
    if (returned != static_cast<DWORD>(sizeof(value))) {
        throw std::runtime_error(
            std::string(operation) + " returned an unexpected size: " +
            std::to_string(returned)
        );
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
            static_cast<DWORD>(sizeof(value)),
            &returned
        )) {
        throw std::runtime_error(
            win32Failure("GetTokenInformation(TokenHasRestrictions)")
        );
    }
    if (returned != static_cast<DWORD>(sizeof(BOOLEAN)) &&
        returned != static_cast<DWORD>(sizeof(DWORD))) {
        throw std::runtime_error(
            "GetTokenInformation(TokenHasRestrictions) returned an unexpected size: " +
            std::to_string(returned)
        );
    }
    return value != 0;
}

[[nodiscard]] std::vector<std::uint8_t> authzInformation(
    const AUTHZ_CLIENT_CONTEXT_HANDLE context,
    const AUTHZ_CONTEXT_INFORMATION_CLASS informationClass
) {
    DWORD required = 0;
    AuthzGetInformationFromContext(context, informationClass, 0, &required, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
        throw std::runtime_error(win32Failure("AuthzGetInformationFromContext(size)"));
    }

    std::vector<std::uint8_t> buffer(required);
    if (!AuthzGetInformationFromContext(
            context,
            informationClass,
            static_cast<DWORD>(buffer.size()),
            &required,
            buffer.data()
        )) {
        throw std::runtime_error(win32Failure("AuthzGetInformationFromContext"));
    }
    return buffer;
}

[[nodiscard]] std::vector<GroupEntry> groups(const TOKEN_GROUPS& tokenGroups) {
    std::vector<GroupEntry> result;
    result.reserve(tokenGroups.GroupCount);
    for (DWORD index = 0; index < tokenGroups.GroupCount; ++index) {
        const auto& group = tokenGroups.Groups[index];
        result.push_back(GroupEntry{
            sidText(group.Sid),
            accountName(group.Sid),
            group.Attributes,
        });
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.sid < right.sid;
    });
    return result;
}

[[nodiscard]] std::wstring privilegeName(const LUID luid) {
    DWORD required = 0;
    LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&luid), nullptr, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
        throw std::runtime_error(win32Failure("LookupPrivilegeNameW(size)"));
    }
    std::wstring name(required + 1, L'\0');
    if (!LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&luid), name.data(), &required)) {
        throw std::runtime_error(win32Failure("LookupPrivilegeNameW"));
    }
    name.resize(required);
    return name;
}

[[nodiscard]] std::vector<PrivilegeEntry> privileges(
    const TOKEN_PRIVILEGES& tokenPrivileges
) {
    std::vector<PrivilegeEntry> result;
    result.reserve(tokenPrivileges.PrivilegeCount);
    for (DWORD index = 0; index < tokenPrivileges.PrivilegeCount; ++index) {
        const auto& privilege = tokenPrivileges.Privileges[index];
        result.push_back(PrivilegeEntry{
            privilegeName(privilege.Luid),
            privilege.Attributes,
        });
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.name < right.name;
    });
    return result;
}

[[nodiscard]] std::optional<GroupEntry> findGroup(
    const std::vector<GroupEntry>& entries,
    const std::wstring& sid
) {
    const auto found = std::find_if(entries.begin(), entries.end(), [&](const auto& entry) {
        return entry.sid == sid;
    });
    return found == entries.end() ? std::nullopt : std::optional<GroupEntry>(*found);
}

[[nodiscard]] std::optional<PrivilegeEntry> findPrivilege(
    const std::vector<PrivilegeEntry>& entries,
    const std::wstring& name
) {
    const auto found = std::find_if(entries.begin(), entries.end(), [&](const auto& entry) {
        return entry.name == name;
    });
    return found == entries.end() ? std::nullopt : std::optional<PrivilegeEntry>(*found);
}

void printGroups(const wchar_t* heading, const std::vector<GroupEntry>& entries) {
    std::wcout << L"\n[" << heading << L"] count=" << entries.size() << L"\n";
    for (const auto& entry : entries) {
        std::wcout << L"  " << entry.sid << L" " << entry.account
                   << L" attributes=0x" << std::hex << entry.attributes << std::dec << L"\n";
    }
}

void printPrivileges(const wchar_t* heading, const std::vector<PrivilegeEntry>& entries) {
    std::wcout << L"\n[" << heading << L"] count=" << entries.size() << L"\n";
    for (const auto& entry : entries) {
        std::wcout << L"  " << entry.name
                   << L" attributes=0x" << std::hex << entry.attributes << std::dec << L"\n";
    }
}

[[nodiscard]] std::wstring defaultDaclSddl(PACL dacl) {
    if (dacl == nullptr) {
        return L"<null>";
    }
    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, FALSE)) {
        throw std::runtime_error(win32Failure("construct default DACL descriptor"));
    }
    LPWSTR sddl = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            &descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &sddl,
            nullptr
        )) {
        throw std::runtime_error(win32Failure("ConvertSecurityDescriptorToStringSecurityDescriptorW"));
    }
    std::wstring result(sddl);
    LocalFree(sddl);
    return result;
}

[[nodiscard]] TokenSnapshot inspectToken(const HANDLE token) {
    const auto userBuffer = tokenInformation(token, TokenUser);
    const auto groupsBuffer = tokenInformation(token, TokenGroups);
    const auto privilegesBuffer = tokenInformation(token, TokenPrivileges);
    const auto primaryGroupBuffer = tokenInformation(token, TokenPrimaryGroup);
    const auto ownerBuffer = tokenInformation(token, TokenOwner);
    const auto defaultDaclBuffer = tokenInformation(token, TokenDefaultDacl);
    const auto statisticsBuffer = tokenInformation(token, TokenStatistics);
    const auto elevationType = fixedTokenInformation<TOKEN_ELEVATION_TYPE>(
        token,
        TokenElevationType,
        "GetTokenInformation(TokenElevationType)"
    );
    const auto elevation = fixedTokenInformation<TOKEN_ELEVATION>(
        token,
        TokenElevation,
        "GetTokenInformation(TokenElevation)"
    );
    const auto hasRestrictions = tokenHasRestrictions(token);
    const auto tokenType = fixedTokenInformation<TOKEN_TYPE>(
        token,
        TokenType,
        "GetTokenInformation(TokenType)"
    );
    const auto integrityLevelBuffer = tokenInformation(token, TokenIntegrityLevel);

    const auto* user = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    const auto* groupData = reinterpret_cast<const TOKEN_GROUPS*>(groupsBuffer.data());
    const auto* privilegeData = reinterpret_cast<const TOKEN_PRIVILEGES*>(
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
    const auto* integrityLevel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(
        integrityLevelBuffer.data()
    );

    return TokenSnapshot{
        sidText(user->User.Sid),
        accountName(user->User.Sid),
        statistics->AuthenticationId,
        elevationType,
        elevation.TokenIsElevated != 0,
        hasRestrictions,
        tokenType,
        sidText(integrityLevel->Label.Sid),
        accountName(integrityLevel->Label.Sid),
        integrityLevel->Label.Attributes,
        sidText(primaryGroup->PrimaryGroup),
        accountName(primaryGroup->PrimaryGroup),
        owner->Owner == nullptr ? L"<default-user>" : sidText(owner->Owner),
        defaultDaclSddl(defaultDacl->DefaultDacl),
        groups(*groupData),
        privileges(*privilegeData),
    };
}

[[nodiscard]] const wchar_t* elevationTypeName(const TOKEN_ELEVATION_TYPE type) {
    switch (type) {
    case TokenElevationTypeDefault:
        return L"Default";
    case TokenElevationTypeFull:
        return L"Full";
    case TokenElevationTypeLimited:
        return L"Limited";
    default:
        return L"Unknown";
    }
}

[[nodiscard]] const wchar_t* tokenTypeName(const TOKEN_TYPE type) {
    switch (type) {
    case TokenPrimary:
        return L"Primary";
    case TokenImpersonation:
        return L"Impersonation";
    default:
        return L"Unknown";
    }
}

[[nodiscard]] std::optional<Handle> linkedToken(
    const HANDLE token,
    const TOKEN_ELEVATION_TYPE elevationType
) {
    if (elevationType == TokenElevationTypeDefault) {
        return std::nullopt;
    }
    if (elevationType != TokenElevationTypeFull &&
        elevationType != TokenElevationTypeLimited) {
        throw std::runtime_error("the desktop token has an unknown elevation type");
    }

    TOKEN_LINKED_TOKEN linked{};
    DWORD returned = 0;
    if (!GetTokenInformation(
            token,
            TokenLinkedToken,
            &linked,
            sizeof(linked),
            &returned
        )) {
        throw std::runtime_error(win32Failure("GetTokenInformation(TokenLinkedToken)"));
    }
    if (linked.LinkedToken == nullptr || linked.LinkedToken == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(
            "GetTokenInformation(TokenLinkedToken) returned an invalid handle"
        );
    }
    return Handle(linked.LinkedToken);
}

void printTokenSummary(const wchar_t* heading, const TokenSnapshot& token) {
    std::wcout << L"\n[" << heading << L"]\n"
               << L"  userSid=" << token.userSid << L"\n"
               << L"  user=" << token.userAccount << L"\n"
               << L"  authenticationId=" << token.authenticationId.HighPart
               << L":" << token.authenticationId.LowPart << L"\n"
               << L"  tokenType=" << tokenTypeName(token.tokenType) << L"\n"
               << L"  elevationType=" << elevationTypeName(token.elevationType) << L"\n"
               << L"  elevated=" << (token.elevated ? L"true" : L"false") << L"\n"
               << L"  hasRestrictions="
               << (token.hasRestrictions ? L"true" : L"false") << L"\n"
               << L"  integrityLevel=" << token.integrityLevelSid << L" "
               << token.integrityLevelAccount
               << L" attributes=0x" << std::hex << token.integrityLevelAttributes
               << std::dec << L"\n"
               << L"  primaryGroup=" << token.primaryGroupSid << L" "
               << token.primaryGroupAccount << L"\n"
               << L"  owner=" << token.ownerSid << L"\n"
               << L"  defaultDacl=" << token.defaultDacl << L"\n";
}

[[nodiscard]] std::string ntStatusFailure(
    const std::string_view operation,
    const NTSTATUS status,
    const NTSTATUS subStatus = 0
) {
    std::ostringstream output;
    output << operation << " failed: status=0x" << std::hex
           << static_cast<unsigned long>(status)
           << " win32=" << std::dec << LsaNtStatusToWinError(status);
    if (subStatus != 0) {
        output << " subStatus=0x" << std::hex
               << static_cast<unsigned long>(subStatus)
               << " subStatusWin32=" << std::dec << LsaNtStatusToWinError(subStatus);
    }
    return output.str();
}

[[nodiscard]] Handle createMsvS4uToken(PSID accountSid) {
    const auto identity = accountIdentity(accountSid);
    if (identity.name == L"<unmapped>" || identity.name.empty()) {
        throw std::runtime_error("the enrolled SID could not be mapped to an account name");
    }

    if (identity.name.size() > std::numeric_limits<USHORT>::max() / sizeof(wchar_t) ||
        identity.domain.size() > std::numeric_limits<USHORT>::max() / sizeof(wchar_t)) {
        throw std::runtime_error("the mapped account name is too long for an S4U request");
    }

    const auto nameBytes = identity.name.size() * sizeof(wchar_t);
    const auto domainBytes = identity.domain.size() * sizeof(wchar_t);
    std::vector<std::uint8_t> submitBuffer(
        sizeof(MSV1_0_S4U_LOGON) + nameBytes + domainBytes
    );
    auto* request = reinterpret_cast<MSV1_0_S4U_LOGON*>(submitBuffer.data());
    request->MessageType = MsV1_0S4ULogon;
    request->Flags = MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS;

    auto* cursor = reinterpret_cast<wchar_t*>(submitBuffer.data() + sizeof(*request));
    request->UserPrincipalName.Buffer = cursor;
    request->UserPrincipalName.Length = static_cast<USHORT>(nameBytes);
    request->UserPrincipalName.MaximumLength = static_cast<USHORT>(nameBytes);
    std::memcpy(cursor, identity.name.data(), nameBytes);

    cursor = reinterpret_cast<wchar_t*>(
        reinterpret_cast<std::uint8_t*>(cursor) + nameBytes
    );
    request->DomainName.Buffer = cursor;
    request->DomainName.Length = static_cast<USHORT>(domainBytes);
    request->DomainName.MaximumLength = static_cast<USHORT>(domainBytes);
    std::memcpy(cursor, identity.domain.data(), domainBytes);

    LSA_HANDLE lsa = nullptr;
    const auto connectStatus = LsaConnectUntrusted(&lsa);
    if (connectStatus < 0) {
        throw std::runtime_error(ntStatusFailure("LsaConnectUntrusted", connectStatus));
    }

    LSA_STRING packageName{};
    packageName.Buffer = const_cast<PCHAR>(MSV1_0_PACKAGE_NAME);
    packageName.Length = static_cast<USHORT>(std::strlen(MSV1_0_PACKAGE_NAME));
    packageName.MaximumLength = packageName.Length;
    ULONG packageId = 0;
    const auto lookupStatus = LsaLookupAuthenticationPackage(
        lsa,
        &packageName,
        &packageId
    );
    if (lookupStatus < 0) {
        LsaDeregisterLogonProcess(lsa);
        throw std::runtime_error(
            ntStatusFailure("LsaLookupAuthenticationPackage(MSV1_0)", lookupStatus)
        );
    }

    LSA_STRING origin{};
    char originText[] = "UWIProbe";
    origin.Buffer = originText;
    origin.Length = 8;
    origin.MaximumLength = 8;
    TOKEN_SOURCE source{};
    std::memcpy(source.SourceName, originText, sizeof(source.SourceName));
    if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
        const auto error = GetLastError();
        LsaDeregisterLogonProcess(lsa);
        throw std::runtime_error(win32Failure("AllocateLocallyUniqueId", error));
    }

    PVOID profile = nullptr;
    ULONG profileSize = 0;
    LUID logonId{};
    HANDLE token = nullptr;
    QUOTA_LIMITS quotas{};
    NTSTATUS subStatus = 0;
    const auto logonStatus = LsaLogonUser(
        lsa,
        &origin,
        Interactive,
        packageId,
        request,
        static_cast<ULONG>(submitBuffer.size()),
        nullptr,
        &source,
        &profile,
        &profileSize,
        &logonId,
        &token,
        &quotas,
        &subStatus
    );
    if (profile != nullptr) {
        LsaFreeReturnBuffer(profile);
    }
    LsaDeregisterLogonProcess(lsa);
    if (logonStatus < 0) {
        throw std::runtime_error(
            ntStatusFailure("LsaLogonUser(MSV1_0 S4U)", logonStatus, subStatus)
        );
    }
    if (token == nullptr) {
        throw std::runtime_error("LsaLogonUser(MSV1_0 S4U) returned no token");
    }
    return Handle(token);
}

void printDifferences(
    const wchar_t* heading,
    const wchar_t* leftName,
    const std::vector<GroupEntry>& leftGroups,
    const std::vector<PrivilegeEntry>& leftPrivileges,
    const wchar_t* rightName,
    const std::vector<GroupEntry>& rightGroups,
    const std::vector<PrivilegeEntry>& rightPrivileges
) {
    std::wcout << L"\n[" << heading << L" - group differences]\n";
    for (const auto& entry : leftGroups) {
        const auto other = findGroup(rightGroups, entry.sid);
        if (!other) {
            std::wcout << L"  " << leftName << L"-only " << entry.sid << L" "
                       << entry.account << L"\n";
        } else if (other->attributes != entry.attributes) {
            std::wcout << L"  attribute-mismatch " << entry.sid
                       << L" " << leftName << L"=0x" << std::hex << entry.attributes
                       << L" " << rightName << L"=0x" << other->attributes
                       << std::dec << L"\n";
        }
    }
    for (const auto& entry : rightGroups) {
        if (!findGroup(leftGroups, entry.sid)) {
            std::wcout << L"  " << rightName << L"-only " << entry.sid << L" "
                       << entry.account << L"\n";
        }
    }

    std::wcout << L"\n[" << heading << L" - privilege differences]\n";
    for (const auto& entry : leftPrivileges) {
        const auto other = findPrivilege(rightPrivileges, entry.name);
        if (!other) {
            std::wcout << L"  " << leftName << L"-only " << entry.name << L"\n";
        } else if (other->attributes != entry.attributes) {
            std::wcout << L"  attribute-mismatch " << entry.name
                       << L" " << leftName << L"=0x" << std::hex << entry.attributes
                       << L" " << rightName << L"=0x" << other->attributes
                       << std::dec << L"\n";
        }
    }
    for (const auto& entry : rightPrivileges) {
        if (!findPrivilege(leftPrivileges, entry.name)) {
            std::wcout << L"  " << rightName << L"-only " << entry.name << L"\n";
        }
    }
}

} // namespace

int wmain(const int argc, wchar_t** argv) {
    try {
        const bool runS4u = argc == 2 && std::wstring_view(argv[1]) == L"--s4u";
        if (argc > 2 || (argc == 2 && !runS4u)) {
            std::wcerr << L"Usage: unlock_lsa_token_probe.exe [--s4u]\n";
            return 2;
        }

        const DWORD sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xffffffff) {
            throw std::runtime_error("there is no active physical console session");
        }

        HANDLE rawToken = nullptr;
        if (!WTSQueryUserToken(sessionId, &rawToken)) {
            throw std::runtime_error(
                win32Failure("WTSQueryUserToken") +
                "; run this probe as LocalSystem with SeTcbPrivilege"
            );
        }
        const Handle token(rawToken);

        const auto userBuffer = tokenInformation(token.get(), TokenUser);
        const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
        const auto tokenSid = sidText(tokenUser->User.Sid);

        unlock_windows::service::EnrollmentStore enrollmentStore;
        const auto enrollment = enrollmentStore.load();
        if (!enrollment) {
            throw std::runtime_error("the protected enrollment record is missing");
        }
        if (tokenSid != enrollment->accountSid) {
            throw std::runtime_error(
                "the active console token SID does not match the enrolled account SID"
            );
        }

        const auto activeToken = inspectToken(token.get());
        auto linkedTokenHandle = linkedToken(token.get(), activeToken.elevationType);
        std::optional<TokenSnapshot> linkedTokenSnapshot;
        if (linkedTokenHandle) {
            linkedTokenSnapshot = inspectToken(linkedTokenHandle->get());
            if (linkedTokenSnapshot->userSid != activeToken.userSid) {
                throw std::runtime_error(
                    "the linked token user SID does not match the active console token"
                );
            }
        }

        const AuthzResourceManager resourceManager;
        const AuthzContext authzContext(tokenUser->User.Sid, resourceManager.get());
        const auto authzGroupsBuffer = authzInformation(
            authzContext.get(),
            AuthzContextInfoGroupsSids
        );
        const auto authzPrivilegesBuffer = authzInformation(
            authzContext.get(),
            AuthzContextInfoPrivileges
        );
        const auto* authzGroupData = reinterpret_cast<const TOKEN_GROUPS*>(
            authzGroupsBuffer.data()
        );
        const auto* authzPrivilegeData = reinterpret_cast<const TOKEN_PRIVILEGES*>(
            authzPrivilegesBuffer.data()
        );

        const auto inferredGroups = groups(*authzGroupData);
        const auto inferredPrivileges = privileges(*authzPrivilegeData);

        std::wcout << L"Unlock Windows with iPhone - LSA token feasibility probe\n"
                   << L"mode=" << (runS4u ? L"s4u-token-comparison" : L"read-only") << L"\n"
                   << L"activeConsoleSessionId=" << sessionId << L"\n"
                   << L"enrolledSid=" << enrollment->accountSid << L"\n"
                   << L"tokenUserSid=" << tokenSid << L"\n";

        printTokenSummary(L"desktop token", activeToken);
        printGroups(L"desktop token groups", activeToken.groups);
        printPrivileges(L"desktop token privileges", activeToken.privileges);

        if (linkedTokenSnapshot) {
            printTokenSummary(L"linked token", *linkedTokenSnapshot);
            printGroups(L"linked token groups", linkedTokenSnapshot->groups);
            printPrivileges(L"linked token privileges", linkedTokenSnapshot->privileges);
        } else {
            std::wcout
                << L"\n[linked token]\n"
                << L"  available=false\n"
                << L"  reason=The desktop token has TokenElevationTypeDefault; "
                   L"this account or UAC policy does not expose a linked token for comparison.\n";
        }

        printGroups(L"Authz SID-derived groups", inferredGroups);
        printPrivileges(L"Authz SID-derived privileges", inferredPrivileges);

        if (linkedTokenSnapshot) {
            printDifferences(
                L"desktop token versus linked token",
                L"desktop",
                activeToken.groups,
                activeToken.privileges,
                L"linked",
                linkedTokenSnapshot->groups,
                linkedTokenSnapshot->privileges
            );
            printDifferences(
                L"linked token versus Authz SID-derived candidate",
                L"linked",
                linkedTokenSnapshot->groups,
                linkedTokenSnapshot->privileges,
                L"authz",
                inferredGroups,
                inferredPrivileges
            );
        }
        printDifferences(
            L"desktop token versus Authz SID-derived candidate",
            L"desktop",
            activeToken.groups,
            activeToken.privileges,
            L"authz",
            inferredGroups,
            inferredPrivileges
        );

        if (runS4u) {
            const auto s4uTokenHandle = createMsvS4uToken(tokenUser->User.Sid);
            const auto s4uToken = inspectToken(s4uTokenHandle.get());
            if (s4uToken.userSid != enrollment->accountSid) {
                throw std::runtime_error("the S4U token SID does not match enrollment");
            }
            printTokenSummary(L"MSV1_0 S4U token", s4uToken);
            printGroups(L"MSV1_0 S4U token groups", s4uToken.groups);
            printPrivileges(L"MSV1_0 S4U token privileges", s4uToken.privileges);
            printDifferences(
                L"desktop token versus MSV1_0 S4U token",
                L"desktop",
                activeToken.groups,
                activeToken.privileges,
                L"s4u",
                s4uToken.groups,
                s4uToken.privileges
            );
        }

        std::wcout
            << L"\n[result]\n"
            << L"  collection=complete\n"
            << L"  productionTokenConstruction=not-authorized\n"
            << L"  note=Authz similarity to a linked token would not prove that a custom authentication package receives native UAC split-token processing.\n"
            << L"  note=This probe does not authorize copying any observed token fields into the custom authentication package.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "LSA token feasibility probe failed: " << error.what() << "\n";
        return 1;
    }
}
