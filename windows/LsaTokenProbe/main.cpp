// Created by Rui MA on 29 Sep 2026

#include "EnrollmentStore.h"

#include <Windows.h>
#include <authz.h>
#include <sddl.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
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

[[nodiscard]] std::wstring accountName(PSID sid) {
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
        return L"<unmapped>";
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
    return domain.empty() ? name : domain + L"\\" + name;
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

void printDifferences(
    const std::vector<GroupEntry>& tokenGroups,
    const std::vector<GroupEntry>& authzGroups,
    const std::vector<PrivilegeEntry>& tokenPrivileges,
    const std::vector<PrivilegeEntry>& authzPrivileges
) {
    std::wcout << L"\n[group differences]\n";
    for (const auto& entry : tokenGroups) {
        const auto other = findGroup(authzGroups, entry.sid);
        if (!other) {
            std::wcout << L"  token-only " << entry.sid << L" " << entry.account << L"\n";
        } else if (other->attributes != entry.attributes) {
            std::wcout << L"  attribute-mismatch " << entry.sid
                       << L" token=0x" << std::hex << entry.attributes
                       << L" authz=0x" << other->attributes << std::dec << L"\n";
        }
    }
    for (const auto& entry : authzGroups) {
        if (!findGroup(tokenGroups, entry.sid)) {
            std::wcout << L"  authz-only " << entry.sid << L" " << entry.account << L"\n";
        }
    }

    std::wcout << L"\n[privilege differences]\n";
    for (const auto& entry : tokenPrivileges) {
        const auto other = findPrivilege(authzPrivileges, entry.name);
        if (!other) {
            std::wcout << L"  token-only " << entry.name << L"\n";
        } else if (other->attributes != entry.attributes) {
            std::wcout << L"  attribute-mismatch " << entry.name
                       << L" token=0x" << std::hex << entry.attributes
                       << L" authz=0x" << other->attributes << std::dec << L"\n";
        }
    }
    for (const auto& entry : authzPrivileges) {
        if (!findPrivilege(tokenPrivileges, entry.name)) {
            std::wcout << L"  authz-only " << entry.name << L"\n";
        }
    }
}

} // namespace

int wmain() {
    try {
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

        const auto groupsBuffer = tokenInformation(token.get(), TokenGroups);
        const auto privilegesBuffer = tokenInformation(token.get(), TokenPrivileges);
        const auto primaryGroupBuffer = tokenInformation(token.get(), TokenPrimaryGroup);
        const auto ownerBuffer = tokenInformation(token.get(), TokenOwner);
        const auto defaultDaclBuffer = tokenInformation(token.get(), TokenDefaultDacl);
        const auto statisticsBuffer = tokenInformation(token.get(), TokenStatistics);

        const auto* tokenGroupData = reinterpret_cast<const TOKEN_GROUPS*>(groupsBuffer.data());
        const auto* tokenPrivilegeData = reinterpret_cast<const TOKEN_PRIVILEGES*>(
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

        const auto tokenGroups = groups(*tokenGroupData);
        const auto inferredGroups = groups(*authzGroupData);
        const auto tokenPrivileges = privileges(*tokenPrivilegeData);
        const auto inferredPrivileges = privileges(*authzPrivilegeData);

        std::wcout << L"Unlock Windows with iPhone - LSA token feasibility probe\n"
                   << L"mode=read-only\n"
                   << L"activeConsoleSessionId=" << sessionId << L"\n"
                   << L"enrolledSid=" << enrollment->accountSid << L"\n"
                   << L"tokenUserSid=" << tokenSid << L"\n"
                   << L"tokenUser=" << accountName(tokenUser->User.Sid) << L"\n"
                   << L"authenticationId=" << statistics->AuthenticationId.HighPart
                   << L":" << statistics->AuthenticationId.LowPart << L"\n"
                   << L"primaryGroup=" << sidText(primaryGroup->PrimaryGroup) << L" "
                   << accountName(primaryGroup->PrimaryGroup) << L"\n"
                   << L"owner=" << (owner->Owner == nullptr ? L"<default-user>" : sidText(owner->Owner))
                   << L"\n"
                   << L"defaultDacl=" << defaultDaclSddl(defaultDacl->DefaultDacl) << L"\n";

        printGroups(L"existing token groups", tokenGroups);
        printGroups(L"Authz SID-derived groups", inferredGroups);
        printPrivileges(L"existing token privileges", tokenPrivileges);
        printPrivileges(L"Authz SID-derived privileges", inferredPrivileges);
        printDifferences(tokenGroups, inferredGroups, tokenPrivileges, inferredPrivileges);

        std::wcout
            << L"\n[result]\n"
            << L"  collection=complete\n"
            << L"  productionTokenConstruction=not-authorized\n"
            << L"  note=This probe does not classify which groups LSA adds automatically.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "LSA token feasibility probe failed: " << error.what() << "\n";
        return 1;
    }
}
