#include "SigningPayload.h"

#include <limits>
#include <utility>

namespace unlock_windows::protocol {
namespace {

constexpr char kSignatureContext[] = "unlock-windows-with-iphone/v1";

void appendUInt16BE(std::vector<std::uint8_t>& output, const std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    output.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void appendUInt32BE(std::vector<std::uint8_t>& output, const std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    output.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    output.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void appendUInt64BE(std::vector<std::uint8_t>& output, const std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
    }
}

} // namespace

PayloadBuildResult buildSigningPayload(const FixedChallenge& challenge) noexcept {
    if (challenge.version != 1) {
        return PayloadBuildResult{PayloadBuildCode::invalid_version, {}};
    }
    if (challenge.audience.empty() || challenge.audience.size() > std::numeric_limits<std::uint16_t>::max()) {
        return PayloadBuildResult{PayloadBuildCode::invalid_audience, {}};
    }

    try {
        std::vector<std::uint8_t> output;
        output.reserve(sizeof(kSignatureContext) - 1 + 1 + 4 + 16 + 32 + 8 + 2 + challenge.audience.size());
        output.insert(output.end(), kSignatureContext, kSignatureContext + (sizeof(kSignatureContext) - 1));
        output.push_back(0);
        appendUInt32BE(output, challenge.version);
        output.insert(output.end(), challenge.requestId.begin(), challenge.requestId.end());
        output.insert(output.end(), challenge.nonce.begin(), challenge.nonce.end());
        appendUInt64BE(output, static_cast<std::uint64_t>(challenge.issuedAtMilliseconds));
        appendUInt16BE(output, static_cast<std::uint16_t>(challenge.audience.size()));
        output.insert(output.end(), challenge.audience.begin(), challenge.audience.end());
        return PayloadBuildResult{PayloadBuildCode::success, std::move(output)};
    } catch (...) {
        return PayloadBuildResult{PayloadBuildCode::allocation_failure, {}};
    }
}

} // namespace unlock_windows::protocol
