// Created by Rui MA on 30 Sep 2026

#pragma once

#include <Windows.h>
#include "../Protocol/SigningPayload.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace unlock_windows::saved_credential {

inline constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\unlock-windows-saved-credential-v1";
inline constexpr wchar_t kPhonePipeName[] = L"\\\\.\\pipe\\unlock-windows-phone-approval-v1";
inline constexpr wchar_t kServiceName[] = L"UnlockWindowsSavedCredentialService";
inline constexpr std::size_t kMaxPacket = 16 * 1024;
inline constexpr std::size_t kNonceSize = 16;
inline constexpr ULONGLONG kPhoneAuthenticationLifetimeMs = protocol::kChallengeLifetimeMilliseconds;

enum class Operation : std::uint16_t {
    captureIdentity = 1,
    status = 2,
    setCredential = 3,
    updateCredential = 4,
    clearCredential = 5,
    claimCredential = 7,
    clearForRemoval = 8,
    beginPhoneAuthentication = 9,
    submitPhoneAssertion = 10,
    reloadPhoneEnrollment = 11,
    takeAutoSubmitOffer = 12,
    takePhoneChallenge = 13,
    reportPhoneFailure = 14,
    phoneAuthenticationStatus = 15,
    unlockEligibility = 16,
    peekPhoneAuthentication = 17,
    captureProvisioningIdentity = 18,
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
    case Operation::beginPhoneAuthentication:
    case Operation::submitPhoneAssertion:
    case Operation::reloadPhoneEnrollment:
    case Operation::takeAutoSubmitOffer:
    case Operation::takePhoneChallenge:
    case Operation::reportPhoneFailure:
    case Operation::phoneAuthenticationStatus:
    case Operation::unlockEligibility:
    case Operation::peekPhoneAuthentication:
    case Operation::captureProvisioningIdentity:
        return true;
    default:
        return false;
    }
}

inline constexpr bool isPhoneOperation(Operation operation) noexcept {
    return operation == Operation::takePhoneChallenge || operation == Operation::reportPhoneFailure ||
        operation == Operation::submitPhoneAssertion || operation == Operation::peekPhoneAuthentication;
}

class PhoneChallengeDeliveryState final {
public:
    bool beginDelivery(Operation operation) noexcept {
        if (operation != Operation::takePhoneChallenge || delivered_) return false;
        delivered_ = true;
        return true;
    }
    bool delivered() const noexcept { return delivered_; }
private:
    bool delivered_ = false;
};

enum class Result : std::uint32_t {
    success = 0,
    rejected = 1,
    invalidRequest = 2,
    internalError = 3,
};

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

struct StatusPayload final {
    Identity identity;
    std::array<std::uint8_t, kNonceSize> snapshotNonce{};
    bool credentialPresent = false;
    bool credentialMatches = false;
};

struct AutoSubmitOffer final {
    std::array<std::uint8_t, kNonceSize> nonce{};
    ULONGLONG expiresAt = 0;
};

enum class AuthenticationStage : std::uint8_t {
    idle, waitingPhone, awaitingAssertion, approved, failed, consumed,
};

enum class AuthenticationFailure : std::uint8_t {
    none, rssiTooLow, automaticDisabled, rssiUnavailable, subscriptionLost,
    deliveryFailed, signingFailed, expired, sessionChanged, invalidAssertion,
};

struct AuthenticationStatus final {
    std::string requestId;
    AuthenticationStage stage = AuthenticationStage::idle;
    AuthenticationFailure failure = AuthenticationFailure::none;
    ULONGLONG deadline = 0;
};

struct PhoneChallengePayload final {
    AuthenticationStatus status;
    std::string json;
};

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
[[nodiscard]] bool encodePhoneChallenge(const PhoneChallengePayload& challenge, SensitiveBytes& output);
[[nodiscard]] bool decodePhoneChallenge(const std::uint8_t* data, std::size_t size, PhoneChallengePayload& output);

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
[[nodiscard]] bool encodeAutoSubmitOffer(const AutoSubmitOffer& offer, SensitiveBytes& output);
[[nodiscard]] bool decodeAutoSubmitOffer(const std::uint8_t* data, std::size_t size, AutoSubmitOffer& output);
[[nodiscard]] bool writePacket(HANDLE pipe, const Packet& packet);
[[nodiscard]] bool readPacket(HANDLE pipe, Packet& packet);
[[nodiscard]] bool writePacket(HANDLE pipe, const Packet& packet, DWORD waitMs);
[[nodiscard]] bool readPacket(HANDLE pipe, Packet& packet, DWORD waitMs);
[[nodiscard]] bool awaitReplyAcknowledgment(HANDLE pipe, Operation operation, DWORD waitMs);
[[nodiscard]] const wchar_t* callStageName(CallStage stage);
[[nodiscard]] bool call(Operation operation, SensitiveBytes&& request, Packet& reply,
    DWORD waitMs = 2000, CallDiagnostics* diagnostics = nullptr);
[[nodiscard]] bool callPhone(Operation operation, SensitiveBytes&& request, Packet& reply,
    DWORD waitMs = 2000, CallDiagnostics* diagnostics = nullptr);

} // namespace unlock_windows::saved_credential
