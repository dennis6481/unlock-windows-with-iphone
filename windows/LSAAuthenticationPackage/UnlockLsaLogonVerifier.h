// Created by Rui MA on 27 Sep 2026

#pragma once

#include "UnlockCrypto.h"
#include "UnlockLogonBufferCodec.h"

#include <cstdint>
#include <span>
#include <string>

namespace unlock_windows::lsa {

enum class LogonVerificationCode {
    valid,
    invalid_buffer,
    audience_mismatch,
    challenge_not_yet_valid,
    challenge_expired,
    enrollment_missing,
    enrollment_invalid,
    key_id_mismatch,
    sid_mismatch,
    invalid_signature,
    cryptographic_failure,
};

struct LogonVerificationResult final {
    LogonVerificationCode code;
    std::wstring accountSid;

    [[nodiscard]] bool succeeded() const noexcept {
        return code == LogonVerificationCode::valid;
    }
};

// Re-validates the complete logon buffer without trusting UnlockService or
// Credential Provider output. The verifier is deliberately independent of
// UnlockServiceCore so the LSA boundary checks the enrolled key-to-SID mapping,
// audience, freshness and signature itself.
class UnlockLsaLogonVerifier final {
public:
    UnlockLsaLogonVerifier(
        std::wstring enrollmentPath,
        std::int64_t challengeLifetimeMilliseconds =
            protocol::kChallengeLifetimeMilliseconds,
        std::string expectedAudience = protocol::kUnlockAudience
    );

    [[nodiscard]] LogonVerificationResult verify(
        std::span<const std::uint8_t> bufferBytes,
        std::int64_t nowMilliseconds
    ) const noexcept;

private:
    std::wstring enrollmentPath_;
    std::int64_t challengeLifetimeMilliseconds_;
    std::string expectedAudience_;
};

} // namespace unlock_windows::lsa
