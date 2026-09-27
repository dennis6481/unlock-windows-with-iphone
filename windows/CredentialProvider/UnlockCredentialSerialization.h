// Created by Rui MA on 27 Sep 2026

#pragma once

#include "UnlockCredentialProvider.h"
#include "UnlockLogonBufferCodec.h"

#include <array>
#include <cstdint>
#include <vector>

namespace unlock_windows::credential_provider {

// This is the only input shape the future IPC adapter may pass to the
// Credential Provider. The caller must have obtained the values from a
// protected, short-lived approval; this helper does not verify the signature.
struct ApprovedUnlock final {
    protocol::FixedChallenge challenge;
    std::array<std::uint8_t, protocol::kKeyIdSize> keyId{};
    std::vector<std::uint8_t> sid;
    std::array<std::uint8_t, protocol::kRawSignatureSize> signature{};
};

enum class SerializationCode {
    valid,
    invalid_logon_buffer,
    allocation_failure,
};

struct SerializationResult final {
    SerializationCode code;
    protocol::UnlockLogonBufferCode bufferCode;

    [[nodiscard]] bool succeeded() const noexcept {
        return code == SerializationCode::valid;
    }
};

// Allocates a Windows Credential Provider serialization containing exactly
// one UnlockLogonBuffer. The caller owns rgbSerialization and must release it
// with CoTaskMemFree. LSA remains responsible for independent verification.
[[nodiscard]] SerializationResult buildCredentialSerialization(
    const protocol::UnlockLogonBuffer& buffer,
    ULONG authenticationPackage,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& output
) noexcept;

// Builds and validates the shared buffer from an already-approved input. This
// overload is the test-side stand-in for the future protected IPC client.
[[nodiscard]] SerializationResult buildCredentialSerialization(
    const ApprovedUnlock& approval,
    ULONG authenticationPackage,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& output
) noexcept;

} // namespace unlock_windows::credential_provider
