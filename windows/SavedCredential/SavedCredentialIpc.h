// Created by Rui MA on 30 Sep 2026

#pragma once

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace unlock_windows::saved_credential {

inline constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\unlock-windows-saved-credential-v1";
inline constexpr wchar_t kPhonePipeName[] = L"\\\\.\\pipe\\unlock-windows-phone-approval-v1";
inline constexpr wchar_t kServiceName[] = L"UnlockWindowsSavedCredentialService";
inline constexpr wchar_t kServiceExeName[] = L"unlock_saved_credential_service.exe";
inline constexpr std::size_t kMaxPacket = 16 * 1024;
inline constexpr std::size_t kNonceSize = 16;

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
};

struct AutoSubmitOffer final {
    std::array<std::uint8_t, kNonceSize> nonce{};
    ULONGLONG expiresAt = 0;
};

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
[[nodiscard]] bool awaitReplyAcknowledgment(HANDLE pipe, Operation operation, DWORD waitMs);
[[nodiscard]] const wchar_t* callStageName(CallStage stage);
[[nodiscard]] bool call(Operation operation, SensitiveBytes&& request, Packet& reply,
    DWORD waitMs = 2000, CallDiagnostics* diagnostics = nullptr);
[[nodiscard]] bool callPhone(Operation operation, SensitiveBytes&& request, Packet& reply,
    DWORD waitMs = 2000, CallDiagnostics* diagnostics = nullptr);

} // namespace unlock_windows::saved_credential
