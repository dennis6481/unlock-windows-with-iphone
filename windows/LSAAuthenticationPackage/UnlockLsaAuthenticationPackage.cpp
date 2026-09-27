// Created by Rui MA on 27 Sep 2026

#include "UnlockLsaAuthenticationPackage.h"

#include "EnrollmentStore.h"
#include "UnlockLsaLogonVerifier.h"
#include "UnlockLogonBuffer.h"

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr wchar_t kAuditAccountName[] = L"UnlockWindowsWithIPhone";
constexpr std::size_t kMaxTrackedRequests = 256;

struct TrackedRequest final {
    std::array<std::uint8_t, unlock_windows::protocol::kRequestIdSize> requestId{};
    std::int64_t issuedAtMilliseconds = 0;
};

LSA_DISPATCH_TABLE g_lsaDispatch{};
SRWLOCK g_dispatchLock = SRWLOCK_INIT;
bool g_initialized = false;

std::vector<TrackedRequest> g_trackedRequests;
SRWLOCK g_trackedRequestsLock = SRWLOCK_INIT;

[[nodiscard]] std::int64_t nowMilliseconds() noexcept {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = now.dwLowDateTime;
    ticks.HighPart = now.dwHighDateTime;
    constexpr std::uint64_t kUnixEpochOffset100Nanoseconds =
        116444736000000000ULL;
    return static_cast<std::int64_t>(
        (ticks.QuadPart - kUnixEpochOffset100Nanoseconds) / 10000ULL
    );
}

[[nodiscard]] bool getDispatch(LSA_DISPATCH_TABLE& output) noexcept {
    AcquireSRWLockShared(&g_dispatchLock);
    const bool ready = g_initialized;
    if (ready) {
        output = g_lsaDispatch;
    }
    ReleaseSRWLockShared(&g_dispatchLock);
    return ready;
}

void freeLsa(
    const LSA_DISPATCH_TABLE& dispatch,
    PVOID value
) noexcept {
    if (value != nullptr && dispatch.FreeLsaHeap != nullptr) {
        dispatch.FreeLsaHeap(value);
    }
}

template <typename Character>
[[nodiscard]] PVOID allocateLsa(
    const LSA_DISPATCH_TABLE& dispatch,
    const std::size_t bytes
) noexcept {
    if (dispatch.AllocateLsaHeap == nullptr ||
        bytes > std::numeric_limits<ULONG>::max()) {
        return nullptr;
    }
    return dispatch.AllocateLsaHeap(static_cast<ULONG>(bytes));
}

[[nodiscard]] PLSA_STRING allocatePackageName(
    const LSA_DISPATCH_TABLE& dispatch
) noexcept {
    constexpr std::string_view name =
        unlock_windows::protocol::kUnlockLsaAuthenticationPackageName;
    auto* result = static_cast<PLSA_STRING>(
        allocateLsa<char>(dispatch, sizeof(LSA_STRING))
    );
    if (result == nullptr) {
        return nullptr;
    }

    auto* buffer = static_cast<PCHAR>(
        allocateLsa<char>(dispatch, name.size() + 1)
    );
    if (buffer == nullptr) {
        freeLsa(dispatch, result);
        return nullptr;
    }
    std::memcpy(buffer, name.data(), name.size());
    buffer[name.size()] = '\0';
    result->Length = static_cast<USHORT>(name.size());
    result->MaximumLength = static_cast<USHORT>(name.size() + 1);
    result->Buffer = buffer;
    return result;
}

[[nodiscard]] PUNICODE_STRING allocateUnicodeString(
    const LSA_DISPATCH_TABLE& dispatch,
    const std::wstring_view value
) noexcept {
    if (value.size() > (std::numeric_limits<USHORT>::max() / sizeof(wchar_t)) - 1) {
        return nullptr;
    }
    auto* result = static_cast<PUNICODE_STRING>(
        allocateLsa<wchar_t>(dispatch, sizeof(UNICODE_STRING))
    );
    if (result == nullptr) {
        return nullptr;
    }

    const auto byteLength = value.size() * sizeof(wchar_t);
    auto* buffer = static_cast<PWSTR>(
        allocateLsa<wchar_t>(dispatch, byteLength + sizeof(wchar_t))
    );
    if (buffer == nullptr) {
        freeLsa(dispatch, result);
        return nullptr;
    }
    std::memcpy(buffer, value.data(), byteLength);
    buffer[value.size()] = L'\0';
    result->Length = static_cast<USHORT>(byteLength);
    result->MaximumLength = static_cast<USHORT>(byteLength + sizeof(wchar_t));
    result->Buffer = buffer;
    return result;
}

[[nodiscard]] NTSTATUS verificationFailureStatus(
    const unlock_windows::lsa::LogonVerificationCode code
) noexcept {
    using Code = unlock_windows::lsa::LogonVerificationCode;
    switch (code) {
        case Code::invalid_buffer:
        case Code::audience_mismatch:
            return STATUS_BAD_VALIDATION_CLASS;
        case Code::challenge_not_yet_valid:
        case Code::challenge_expired:
        case Code::enrollment_missing:
        case Code::enrollment_invalid:
        case Code::key_id_mismatch:
        case Code::sid_mismatch:
        case Code::invalid_signature:
        case Code::cryptographic_failure:
            return STATUS_LOGON_FAILURE;
        case Code::valid:
            return STATUS_SUCCESS;
    }
    return STATUS_LOGON_FAILURE;
}

[[nodiscard]] bool claimRequest(
    const std::array<std::uint8_t, unlock_windows::protocol::kRequestIdSize>& requestId,
    const std::int64_t issuedAtMilliseconds,
    const std::int64_t now
) noexcept {
    AcquireSRWLockExclusive(&g_trackedRequestsLock);
    g_trackedRequests.erase(
        std::remove_if(
            g_trackedRequests.begin(),
            g_trackedRequests.end(),
            [now, issuedAtMilliseconds](const TrackedRequest& tracked) {
                return now >= tracked.issuedAtMilliseconds &&
                    now - tracked.issuedAtMilliseconds >
                        unlock_windows::protocol::kChallengeLifetimeMilliseconds;
            }
        ),
        g_trackedRequests.end()
    );

    const auto duplicate = std::any_of(
        g_trackedRequests.begin(),
        g_trackedRequests.end(),
        [&requestId](const TrackedRequest& tracked) {
            return tracked.requestId == requestId;
        }
    );
    if (duplicate) {
        ReleaseSRWLockExclusive(&g_trackedRequestsLock);
        return false;
    }

    if (g_trackedRequests.size() >= kMaxTrackedRequests) {
        g_trackedRequests.erase(g_trackedRequests.begin());
    }
    g_trackedRequests.push_back(TrackedRequest{requestId, issuedAtMilliseconds});
    ReleaseSRWLockExclusive(&g_trackedRequestsLock);
    return true;
}

[[nodiscard]] NTSTATUS returnUnsupportedPackageCall(
    PVOID* protocolReturnBuffer,
    PULONG returnBufferLength,
    PNTSTATUS protocolStatus
) noexcept {
    if (protocolReturnBuffer != nullptr) {
        *protocolReturnBuffer = nullptr;
    }
    if (returnBufferLength != nullptr) {
        *returnBufferLength = 0;
    }
    if (protocolStatus != nullptr) {
        *protocolStatus = STATUS_NOT_SUPPORTED;
    }
    return STATUS_NOT_SUPPORTED;
}

} // namespace

extern "C" __declspec(dllexport) NTSTATUS NTAPI LsaApInitializePackage(
    const ULONG,
    PLSA_DISPATCH_TABLE lsaDispatchTable,
    PLSA_STRING,
    PLSA_STRING,
    PLSA_STRING* authenticationPackageName
) {
    if (lsaDispatchTable == nullptr || authenticationPackageName == nullptr ||
        lsaDispatchTable->AllocateLsaHeap == nullptr ||
        lsaDispatchTable->FreeLsaHeap == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *authenticationPackageName = nullptr;

    const auto packageName = allocatePackageName(*lsaDispatchTable);
    if (packageName == nullptr) {
        return STATUS_NO_MEMORY;
    }

    AcquireSRWLockExclusive(&g_dispatchLock);
    g_lsaDispatch = *lsaDispatchTable;
    g_initialized = true;
    ReleaseSRWLockExclusive(&g_dispatchLock);
    *authenticationPackageName = packageName;
    return STATUS_SUCCESS;
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI LsaApLogonUserEx2(
    PLSA_CLIENT_REQUEST,
    const SECURITY_LOGON_TYPE logonType,
    PVOID protocolSubmitBuffer,
    PVOID,
    const ULONG submitBufferSize,
    PVOID* profileBuffer,
    PULONG profileBufferSize,
    PLUID logonId,
    PNTSTATUS subStatus,
    PLSA_TOKEN_INFORMATION_TYPE tokenInformationType,
    PVOID* tokenInformation,
    PUNICODE_STRING* accountName,
    PUNICODE_STRING* authenticatingAuthority,
    PUNICODE_STRING* machineName,
    PSECPKG_PRIMARY_CRED primaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supplementalCredentials
) {
    if (profileBuffer == nullptr || profileBufferSize == nullptr ||
        logonId == nullptr || subStatus == nullptr ||
        tokenInformationType == nullptr || tokenInformation == nullptr ||
        accountName == nullptr || authenticatingAuthority == nullptr ||
        machineName == nullptr || primaryCredentials == nullptr ||
        supplementalCredentials == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *profileBuffer = nullptr;
    *profileBufferSize = 0;
    *logonId = LUID{};
    *subStatus = STATUS_LOGON_FAILURE;
    *tokenInformationType = LsaTokenInformationV2;
    *tokenInformation = nullptr;
    *accountName = nullptr;
    *authenticatingAuthority = nullptr;
    *machineName = nullptr;
    std::memset(primaryCredentials, 0, sizeof(*primaryCredentials));
    *supplementalCredentials = nullptr;

    LSA_DISPATCH_TABLE dispatch{};
    if (!getDispatch(dispatch) || dispatch.CreateLogonSession == nullptr) {
        return STATUS_DLL_INIT_FAILED;
    }

    *accountName = allocateUnicodeString(dispatch, kAuditAccountName);
    if (*accountName == nullptr) {
        return STATUS_NO_MEMORY;
    }

    if (logonType != Unlock) {
        *subStatus = STATUS_INVALID_LOGON_TYPE;
        return STATUS_INVALID_LOGON_TYPE;
    }

    try {
        const auto path = unlock_windows::service::EnrollmentStore::defaultPath();
        const unlock_windows::lsa::UnlockLsaLogonVerifier verifier(path);
        const auto result = verifier.verify(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(protocolSubmitBuffer),
                submitBufferSize
            ),
            nowMilliseconds()
        );
        if (!result.succeeded()) {
            const auto status = verificationFailureStatus(result.code);
            *subStatus = status;
            return status;
        }

        const auto now = nowMilliseconds();
        const auto buffer = reinterpret_cast<const unlock_windows::protocol::UnlockLogonBuffer*>(
            protocolSubmitBuffer
        );
        if (buffer == nullptr) {
            *subStatus = STATUS_BAD_VALIDATION_CLASS;
            return STATUS_BAD_VALIDATION_CLASS;
        }
        std::array<std::uint8_t, unlock_windows::protocol::kRequestIdSize> requestId{};
        std::copy(
            std::begin(buffer->requestId),
            std::end(buffer->requestId),
            requestId.begin()
        );
        if (!claimRequest(
                requestId,
                buffer->issuedAtMilliseconds,
                now
            )) {
            *subStatus = STATUS_LOGON_FAILURE;
            return STATUS_LOGON_FAILURE;
        }

        PSID parsedSid = nullptr;
        if (!ConvertStringSidToSidW(result.accountSid.c_str(), &parsedSid)) {
            *subStatus = STATUS_LOGON_FAILURE;
            return STATUS_LOGON_FAILURE;
        }
        const auto sidLength = GetLengthSid(parsedSid);
        if (sidLength == 0 || sidLength >
            std::numeric_limits<ULONG>::max() - sizeof(LSA_TOKEN_INFORMATION_V2)) {
            LocalFree(parsedSid);
            *subStatus = STATUS_LOGON_FAILURE;
            return STATUS_LOGON_FAILURE;
        }

        const auto tokenBytes = sizeof(LSA_TOKEN_INFORMATION_V2) + sidLength;
        auto* token = static_cast<PLSA_TOKEN_INFORMATION_V2>(
            allocateLsa<LSA_TOKEN_INFORMATION_V2>(dispatch, tokenBytes)
        );
        if (token == nullptr) {
            LocalFree(parsedSid);
            *subStatus = STATUS_NO_MEMORY;
            return STATUS_NO_MEMORY;
        }
        std::memset(token, 0, tokenBytes);
        auto* tokenSid = reinterpret_cast<PSID>(
            reinterpret_cast<std::uint8_t*>(token) + sizeof(LSA_TOKEN_INFORMATION_V2)
        );
        std::memcpy(tokenSid, parsedSid, sidLength);
        LocalFree(parsedSid);

        token->ExpirationTime.QuadPart = std::numeric_limits<LONGLONG>::max();
        token->User.User.Sid = tokenSid;
        token->PrimaryGroup.PrimaryGroup = tokenSid;
        if (dispatch.CreateLogonSession(logonId) < 0) {
            freeLsa(dispatch, token);
            *subStatus = STATUS_LOGON_FAILURE;
            return STATUS_LOGON_FAILURE;
        }

        *tokenInformation = token;
        *tokenInformationType = LsaTokenInformationV2;
        *subStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    } catch (...) {
        *subStatus = STATUS_LOGON_FAILURE;
        return STATUS_LOGON_FAILURE;
    }
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI LsaApCallPackage(
    PLSA_CLIENT_REQUEST,
    PVOID,
    PVOID,
    const ULONG,
    PVOID* protocolReturnBuffer,
    PULONG returnBufferLength,
    PNTSTATUS protocolStatus
) {
    return returnUnsupportedPackageCall(
        protocolReturnBuffer,
        returnBufferLength,
        protocolStatus
    );
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI LsaApCallPackageUntrusted(
    PLSA_CLIENT_REQUEST,
    PVOID,
    PVOID,
    const ULONG,
    PVOID* protocolReturnBuffer,
    PULONG returnBufferLength,
    PNTSTATUS protocolStatus
) {
    return returnUnsupportedPackageCall(
        protocolReturnBuffer,
        returnBufferLength,
        protocolStatus
    );
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI LsaApCallPackagePassthrough(
    PLSA_CLIENT_REQUEST,
    PVOID,
    PVOID,
    const ULONG,
    PVOID* protocolReturnBuffer,
    PULONG returnBufferLength,
    PNTSTATUS protocolStatus
) {
    return returnUnsupportedPackageCall(
        protocolReturnBuffer,
        returnBufferLength,
        protocolStatus
    );
}

extern "C" __declspec(dllexport) VOID NTAPI LsaApLogonTerminated(
    PLUID
) {}
