// Created by Rui MA on 26 Sep 2026

#pragma once

#include "SigningPayload.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace unlock_windows::phone_approval {

enum class AssertionCode {
    authenticated,
    malformed_json,
    unsupported_version,
    invalid_request_id,
    request_mismatch,
    challenge_expired,
    challenge_replayed,
    key_not_enrolled,
    invalid_key_id,
    invalid_public_key,
    key_id_mismatch,
    invalid_signature_encoding,
    invalid_signature,
    cryptographic_api_failure,
};

struct IssuedChallenge final {
    protocol::FixedChallenge challenge;
    std::string json;
};

struct PendingUnlockApproval final {
    std::int64_t issuedAtMilliseconds = 0;
    std::string accountSid;
};

struct AssertionResult final {
    AssertionCode code;
    std::string accountSid;

    [[nodiscard]] bool authenticated() const noexcept {
        return code == AssertionCode::authenticated;
    }

    [[nodiscard]] bool unlockApproved() const noexcept {
        return authenticated() && !accountSid.empty();
    }
};

// Owns the phone-approval security state used by the Windows service.
class PhoneApprovalCore final {
public:
    explicit PhoneApprovalCore(
        std::string audience = protocol::kUnlockAudience,
        std::int64_t challengeLifetimeMilliseconds = protocol::kChallengeLifetimeMilliseconds
    );

    PhoneApprovalCore(const PhoneApprovalCore&) = delete;
    PhoneApprovalCore& operator=(const PhoneApprovalCore&) = delete;

    [[nodiscard]] IssuedChallenge issueChallenge(std::int64_t issuedAtMilliseconds);

    [[nodiscard]] AssertionResult verifyAssertion(
        std::string_view assertionJson,
        std::int64_t nowMilliseconds
    );

    // Consumes the one-time approval created by a valid enrolled assertion.
    // An expired or already consumed approval is never returned.
    [[nodiscard]] std::optional<PendingUnlockApproval> consumeUnlockApproval(
        std::int64_t nowMilliseconds
    );

    // Until a key is installed, no assertion is allowed to authenticate.
    void setEnrolledPublicKey(std::vector<std::uint8_t> rawPublicKey);
    void setEnrolledAccountSid(std::string accountSid);
    void clearEnrolledPublicKey() noexcept;

    [[nodiscard]] static std::string serializeChallenge(
        const protocol::FixedChallenge& challenge
    );

    [[nodiscard]] static std::string requestIdString(
        const protocol::FixedChallenge& challenge
    );

private:
    std::string audience_;
    std::int64_t challengeLifetimeMilliseconds_;
    std::mutex mutex_;
    std::optional<protocol::FixedChallenge> outstandingChallenge_;
    std::optional<std::vector<std::uint8_t>> enrolledPublicKey_;
    std::optional<std::string> enrolledAccountSid_;
    std::optional<PendingUnlockApproval> pendingUnlockApproval_;
    bool outstandingChallengeConsumed_ = false;
};

[[nodiscard]] const char* assertionCodeName(AssertionCode code) noexcept;

} // namespace unlock_windows::phone_approval
