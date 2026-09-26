#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace unlock_windows::protocol {

struct FixedChallenge {
    std::uint32_t version = 0;
    std::array<std::uint8_t, 16> requestId{}; // RFC 4122 byte order
    std::array<std::uint8_t, 32> nonce{};
    std::int64_t issuedAtMilliseconds = 0;
    std::string audience; // already decoded as UTF-8
};

enum class PayloadBuildCode {
    success,
    invalid_version,
    invalid_audience,
    allocation_failure,
};

struct PayloadBuildResult {
    PayloadBuildCode code;
    std::vector<std::uint8_t> bytes;

    [[nodiscard]] bool succeeded() const noexcept {
        return code == PayloadBuildCode::success;
    }
};

// Builds the exact byte sequence that iOS signs. The output starts with the
// protocol context and never includes JSON punctuation or base64 text.
[[nodiscard]] PayloadBuildResult buildSigningPayload(const FixedChallenge& challenge) noexcept;

} // namespace unlock_windows::protocol
