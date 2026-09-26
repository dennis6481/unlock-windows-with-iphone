#pragma once

#include "SigningPayload.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace unlock_windows::service {

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

struct AssertionResult final {
    AssertionCode code;

    [[nodiscard]] bool authenticated() const noexcept {
        return code == AssertionCode::authenticated;
    }
};

// Owns the security state that must not live in the GATT transport process.
// The current implementation keeps one outstanding challenge in memory. A
// Windows Service persistence/IPC layer will wrap this core later.
class UnlockServiceCore final {
public:
    explicit UnlockServiceCore(
        std::string audience = "windows-unlock",
        std::int64_t challengeLifetimeMilliseconds = 30'000
    );

    UnlockServiceCore(const UnlockServiceCore&) = delete;
    UnlockServiceCore& operator=(const UnlockServiceCore&) = delete;

    [[nodiscard]] IssuedChallenge issueChallenge(std::int64_t issuedAtMilliseconds);

    [[nodiscard]] AssertionResult verifyAssertion(
        std::string_view assertionJson,
        std::int64_t nowMilliseconds
    );

    // The real enrollment flow will load this value from protected storage.
    // Until a key is installed, no assertion is allowed to authenticate.
    void setEnrolledPublicKey(std::vector<std::uint8_t> rawPublicKey);

    [[nodiscard]] const std::string& audience() const noexcept {
        return audience_;
    }

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
    bool outstandingChallengeConsumed_ = false;
};

[[nodiscard]] const char* assertionCodeName(AssertionCode code) noexcept;

} // namespace unlock_windows::service
