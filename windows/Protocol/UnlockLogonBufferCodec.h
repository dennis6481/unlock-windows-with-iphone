// Created by Rui MA on 27 Sep 2026

#pragma once

#include "SigningPayload.h"
#include "UnlockLogonBuffer.h"

#include <cstdint>
#include <span>

namespace unlock_windows::protocol {

enum class UnlockLogonBufferCode {
    valid,
    null_buffer,
    invalid_size,
    invalid_magic,
    unsupported_version,
    invalid_total_size,
    invalid_key_id,
    invalid_audience,
    invalid_sid,
    invalid_signature,
};

struct UnlockLogonBufferResult final {
    UnlockLogonBufferCode code;

    [[nodiscard]] bool succeeded() const noexcept {
        return code == UnlockLogonBufferCode::valid;
    }
};

// Builds the fixed-size buffer that a future Credential Provider will submit
// to LogonUI. The SID is copied into the buffer for transport only; the LSA
// side must still resolve the enrolled key and compare its protected mapping.
[[nodiscard]] UnlockLogonBufferResult buildUnlockLogonBuffer(
    const FixedChallenge& challenge,
    std::span<const std::uint8_t> keyId,
    std::span<const std::uint8_t> sid,
    std::span<const std::uint8_t> signature,
    UnlockLogonBuffer& output
) noexcept;

// Validates untrusted bytes before a Credential Provider or LSA implementation
// reads any variable-length field. This checks structure only; signature
// verification and protected key-to-SID mapping remain separate operations.
[[nodiscard]] UnlockLogonBufferResult validateUnlockLogonBuffer(
    std::span<const std::uint8_t> bytes
) noexcept;

} // namespace unlock_windows::protocol
