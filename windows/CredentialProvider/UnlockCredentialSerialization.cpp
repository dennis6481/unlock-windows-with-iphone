// Created by Rui MA on 27 Sep 2026

#include "UnlockCredentialSerialization.h"

#include <cstring>

namespace unlock_windows::credential_provider {

SerializationResult buildCredentialSerialization(
    const protocol::UnlockLogonBuffer& buffer,
    const ULONG authenticationPackage,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& output
) noexcept {
    output = {};

    const auto bufferResult = protocol::validateUnlockLogonBuffer(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(&buffer),
            sizeof(buffer)
        )
    );
    if (!bufferResult.succeeded()) {
        return {
            SerializationCode::invalid_logon_buffer,
            bufferResult.code,
        };
    }

    auto* serialization = static_cast<BYTE*>(CoTaskMemAlloc(sizeof(buffer)));
    if (serialization == nullptr) {
        return {
            SerializationCode::allocation_failure,
            bufferResult.code,
        };
    }

    std::memcpy(serialization, &buffer, sizeof(buffer));
    output.ulAuthenticationPackage = authenticationPackage;
    output.clsidCredentialProvider = kUnlockCredentialProviderClsid;
    output.cbSerialization = static_cast<ULONG>(sizeof(buffer));
    output.rgbSerialization = serialization;
    return {
        SerializationCode::valid,
        bufferResult.code,
    };
}

SerializationResult buildCredentialSerialization(
    const ApprovedUnlock& approval,
    const ULONG authenticationPackage,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& output
) noexcept {
    protocol::UnlockLogonBuffer buffer{};
    const auto bufferResult = protocol::buildUnlockLogonBuffer(
        approval.challenge,
        approval.keyId,
        approval.sid,
        approval.signature,
        buffer
    );
    if (!bufferResult.succeeded()) {
        output = {};
        return {
            SerializationCode::invalid_logon_buffer,
            bufferResult.code,
        };
    }

    return buildCredentialSerialization(buffer, authenticationPackage, output);
}

} // namespace unlock_windows::credential_provider
