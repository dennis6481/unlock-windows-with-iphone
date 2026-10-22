// Created by Rui MA on 30 Sep 2026
// Modified by Liam on 21 Oct 2026

#pragma once

#include <Windows.h>
#include <ntsecapi.h>
#include "../Bluetooth/SystemBleContract.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace unlock_windows::saved_credential {

inline constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\unlock-windows-saved-credential-v1";
inline constexpr wchar_t kServiceName[] = L"UnlockWindowsSavedCredentialService";
inline constexpr std::size_t kMaxPacket = 16 * 1024;
inline constexpr std::size_t kMaxPasswordChars = 1024;
inline constexpr std::size_t kNonceSize = 16;
inline constexpr std::uint16_t kProtocolVersion = 3;
inline constexpr DWORD kPipeTransferLifetimeMs = 2000;
inline constexpr wchar_t kBindingCancelPrefix[] = L"Global\\UnlockWindowsWithIPhone-Pairing-";

enum class Operation : std::uint16_t {
    captureIdentity = 1,
    status = 2,
    setCredential = 3,
    updateCredential = 4,
    clearCredential = 5,
    claimCredential = 7,
    clearForRemoval = 8,
    beginVerification = 9,
    takeAutoSubmitOffer = 12,
    verificationStatus = 15,
    unlockEligibility = 16,
    captureProvisioningIdentity = 18,
    credentialSummary = 19,
    bindingStatus = 20, beginBinding = 21, removeBinding = 22, saveThreshold = 23,
    cancelVerification = 24, bindingTaskStatus = 25, serviceDiagnostics = 26,
    reportUnlockResult = 27, lastUnlockStatus = 28, beginAutomaticVerification = 29,
};

inline constexpr bool isKnownOperation(const std::uint16_t value) noexcept {
    switch (static_cast<Operation>(value)) {
    case Operation::captureIdentity:
    case Operation::status:
    case Operation::setCredential:
    case Operation::updateCredential:
    case Operation::clearCredential:
    case Operation::claimCredential:
    case Operation::clearForRemoval:
    case Operation::beginVerification:
    case Operation::beginAutomaticVerification:
    case Operation::takeAutoSubmitOffer:
    case Operation::verificationStatus:
    case Operation::unlockEligibility:
    case Operation::captureProvisioningIdentity:
    case Operation::bindingStatus:
    case Operation::beginBinding:
    case Operation::removeBinding:
    case Operation::saveThreshold:
    case Operation::cancelVerification:
    case Operation::bindingTaskStatus:
    case Operation::serviceDiagnostics:
    case Operation::credentialSummary:
    case Operation::reportUnlockResult:
    case Operation::lastUnlockStatus:
        return true;
    default:
        return false;
    }
}

enum class Result : std::uint32_t {
    success = 0,
    rejected = 1,
    invalidRequest = 2,
    internalError = 3,
    busy = 4,
};

inline constexpr bool requiresLogonUi(Operation operation) noexcept {
    switch (operation) {
    case Operation::captureIdentity:
    case Operation::captureProvisioningIdentity:
    case Operation::claimCredential:
    case Operation::beginVerification:
    case Operation::beginAutomaticVerification:
    case Operation::verificationStatus:
    case Operation::unlockEligibility:
    case Operation::takeAutoSubmitOffer:
    case Operation::reportUnlockResult: return true;
    default: return false;
    }
}

struct SensitiveBytes final {
    std::vector<std::uint8_t> value;
    SensitiveBytes() = default;
    SensitiveBytes(const SensitiveBytes&) = delete;
    SensitiveBytes& operator=(const SensitiveBytes&) = delete;
    SensitiveBytes(SensitiveBytes&&) noexcept = default;
    SensitiveBytes& operator=(SensitiveBytes&& other) noexcept;
    ~SensitiveBytes();
    void clear() noexcept;
};

struct Identity final {
    std::wstring sid;
    std::wstring qualifiedUserName;
    GUID providerId{};
};

[[nodiscard]] bool sameIdentity(const Identity& left, const Identity& right) noexcept;

struct CredentialSummary {
    Identity identity;
    bool credentialPresent = false;
    bool credentialMatches = false;
};

struct StatusPayload final : CredentialSummary {
    std::array<std::uint8_t, kNonceSize> snapshotNonce{};
};

struct AutoSubmitOffer final {
    std::array<std::uint8_t, kNonceSize> nonce{};
    ULONGLONG expiresAt = 0;
};

struct UnlockResult final {
    std::array<std::uint8_t, kNonceSize> nonce{};
    NTSTATUS status = 0;
    NTSTATUS substatus = 0;
};

struct LastUnlockSummary final {
    ULONGLONG completedAt = 0;
    std::int32_t rssi = 0;
};

[[nodiscard]] bool encodeUnlockResult(const UnlockResult& result, SensitiveBytes& output);
[[nodiscard]] bool decodeUnlockResult(const std::uint8_t* data, std::size_t size, UnlockResult& output);
[[nodiscard]] bool encodeLastUnlock(const std::optional<LastUnlockSummary>& summary, SensitiveBytes& output);
[[nodiscard]] bool decodeLastUnlock(const std::uint8_t* data, std::size_t size, std::optional<LastUnlockSummary>& output);

enum class AuthenticationStage : std::uint8_t {
    idle, verifying, approved, failed, consumed, completed,
};

enum class AuthenticationFailure : std::uint8_t {
    none, rssiTooLow, rssiUnavailable, connectionLost, protectedOperationFailed,
    expired, sessionChanged, associationInvalid, bondRejected, cancelled, bindingChanged,
    storageFailed, evidenceExpired, internalError,
};

struct AuthenticationStatus final {
    std::string requestId;
    AuthenticationStage stage = AuthenticationStage::idle;
    AuthenticationFailure failure = AuthenticationFailure::none;
    ULONGLONG deadline = 0;
};

struct BindingSummary final {
    system_ble::BindingState state = system_ble::BindingState::absent;
    system_ble::BindingRecord record;
    bool operator==(const BindingSummary&) const = default;
};

struct BindingChange final {
    BindingSummary expected;
    system_ble::BindingRecord candidate;
    std::wstring cancelEvent;
};

struct BindingRemoval final {
    BindingSummary expected;
    std::wstring cancelEvent;
};

[[nodiscard]] bool encodeBinding(const system_ble::BindingRecord& record, SensitiveBytes& output);
[[nodiscard]] bool decodeBinding(const std::uint8_t* data, std::size_t size, system_ble::BindingRecord& output);
[[nodiscard]] bool encodeBindingSummary(const BindingSummary& summary, SensitiveBytes& output);
[[nodiscard]] bool decodeBindingSummary(const std::uint8_t* data, std::size_t size, BindingSummary& output);
[[nodiscard]] bool encodeBindingChange(const BindingChange& change, SensitiveBytes& output);
[[nodiscard]] bool decodeBindingChange(const std::uint8_t* data, std::size_t size, BindingChange& output);
[[nodiscard]] bool encodeBindingRemoval(const BindingRemoval& removal, SensitiveBytes& output);
[[nodiscard]] bool decodeBindingRemoval(const std::uint8_t* data, std::size_t size, BindingRemoval& output);


inline constexpr AuthenticationFailure authenticationExpiry(
    ULONGLONG now, ULONGLONG deadline, bool sameConsole, bool locked) noexcept {
    if (!sameConsole || !locked) return AuthenticationFailure::sessionChanged;
    return now >= deadline ? AuthenticationFailure::expired : AuthenticationFailure::none;
}

inline constexpr bool isObservedConsoleEvent(DWORD eventSession, DWORD observedSession) noexcept {
    return observedSession != 0xffffffff && eventSession == observedSession;
}

[[nodiscard]] const wchar_t* authenticationStatusText(const AuthenticationStatus& status) noexcept;
[[nodiscard]] bool encodeAuthenticationStatus(const AuthenticationStatus& status, SensitiveBytes& output);
[[nodiscard]] bool decodeAuthenticationStatus(const std::uint8_t* data, std::size_t size, AuthenticationStatus& output);

struct Packet final {
    Operation operation = Operation::status;
    Result result = Result::success;
    SensitiveBytes payload;
};

enum class CallStage {
    none,
    requestValidation,
    waitForPipe,
    openPipe,
    serverVerification,
    requestWrite,
    replyRead,
    replyValidation,
    replyAcknowledgment,
};

struct CallDiagnostics final {
    CallStage stage = CallStage::none;
    DWORD win32Error = NO_ERROR;
    const wchar_t* serverCheck = L"";
};

[[nodiscard]] bool encodeIdentity(const Identity& identity, SensitiveBytes& output);
[[nodiscard]] bool decodeIdentity(const std::uint8_t* data, std::size_t size, Identity& output);
[[nodiscard]] bool encodeStatus(const StatusPayload& status, SensitiveBytes& output);
[[nodiscard]] bool decodeStatus(const std::uint8_t* data, std::size_t size, StatusPayload& output);
[[nodiscard]] bool encodeCredentialSummary(const CredentialSummary& summary, SensitiveBytes& output);
[[nodiscard]] bool decodeCredentialSummary(const std::uint8_t* data, std::size_t size, CredentialSummary& output);
[[nodiscard]] bool encodeAutoSubmitOffer(const AutoSubmitOffer& offer, SensitiveBytes& output);
[[nodiscard]] bool decodeAutoSubmitOffer(const std::uint8_t* data, std::size_t size, AutoSubmitOffer& output);
struct PipeIoContext final {
    std::uint64_t deadline;
    HANDLE stopEvent = nullptr;
};
[[nodiscard]] bool connectPipe(HANDLE pipe, HANDLE stopEvent);
[[nodiscard]] bool writePacket(HANDLE pipe, const Packet& packet, const PipeIoContext& context);
[[nodiscard]] bool readPacket(HANDLE pipe, Packet& packet, const PipeIoContext& context);
[[nodiscard]] bool writeReplyAcknowledgment(HANDLE pipe, Operation operation, const PipeIoContext& context);
[[nodiscard]] bool awaitReplyAcknowledgment(HANDLE pipe, Operation operation, const PipeIoContext& context);
[[nodiscard]] const wchar_t* callStageName(CallStage stage);
[[nodiscard]] bool call(Operation operation, SensitiveBytes&& request, Packet& reply,
    DWORD waitMs = kPipeTransferLifetimeMs, CallDiagnostics* diagnostics = nullptr);

} // namespace unlock_windows::saved_credential
