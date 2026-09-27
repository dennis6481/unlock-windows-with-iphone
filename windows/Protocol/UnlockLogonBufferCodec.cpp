// Created by Rui MA on 27 Sep 2026

#include "UnlockLogonBufferCodec.h"

#include <algorithm>
#include <cstring>

namespace unlock_windows::protocol {
namespace {

[[nodiscard]] bool allZero(
    const std::uint8_t* bytes,
    const std::size_t size
) noexcept {
    return std::all_of(bytes, bytes + size, [](const std::uint8_t byte) {
        return byte == 0;
    });
}

[[nodiscard]] UnlockLogonBufferResult validateFields(
    const UnlockLogonBuffer& buffer
) noexcept {
    if (buffer.magic != kUnlockLogonMagic) {
        return {UnlockLogonBufferCode::invalid_magic};
    }
    if (buffer.version != kUnlockLogonVersion) {
        return {UnlockLogonBufferCode::unsupported_version};
    }
    if (buffer.totalSize != sizeof(UnlockLogonBuffer)) {
        return {UnlockLogonBufferCode::invalid_total_size};
    }
    if (allZero(buffer.keyId, kKeyIdSize)) {
        return {UnlockLogonBufferCode::invalid_key_id};
    }
    if (buffer.audienceLength == 0 ||
        buffer.audienceLength > kAudienceMaxUtf8Bytes) {
        return {UnlockLogonBufferCode::invalid_audience};
    }
    if (buffer.sidLength == 0 ||
        buffer.sidLength > sizeof(buffer.sid)) {
        return {UnlockLogonBufferCode::invalid_sid};
    }

    auto* sid = reinterpret_cast<PSID>(
        const_cast<std::uint8_t*>(buffer.sid)
    );
    if (!IsValidSid(sid) || GetLengthSid(sid) != buffer.sidLength) {
        return {UnlockLogonBufferCode::invalid_sid};
    }
    if (allZero(buffer.signatureRaw, kRawSignatureSize)) {
        return {UnlockLogonBufferCode::invalid_signature};
    }
    return {UnlockLogonBufferCode::valid};
}

} // namespace

UnlockLogonBufferResult buildUnlockLogonBuffer(
    const FixedChallenge& challenge,
    const std::span<const std::uint8_t> keyId,
    const std::span<const std::uint8_t> sid,
    const std::span<const std::uint8_t> signature,
    UnlockLogonBuffer& output
) noexcept {
    output = {};

    if (challenge.version != kUnlockLogonVersion) {
        return {UnlockLogonBufferCode::unsupported_version};
    }
    if (challenge.audience.empty() ||
        challenge.audience.size() > kAudienceMaxUtf8Bytes) {
        return {UnlockLogonBufferCode::invalid_audience};
    }
    if (keyId.size() != kKeyIdSize || allZero(keyId.data(), keyId.size())) {
        return {UnlockLogonBufferCode::invalid_key_id};
    }
    if (signature.size() != kRawSignatureSize ||
        allZero(signature.data(), signature.size())) {
        return {UnlockLogonBufferCode::invalid_signature};
    }
    if (sid.empty() || sid.size() > sizeof(output.sid)) {
        return {UnlockLogonBufferCode::invalid_sid};
    }

    auto* sidPointer = reinterpret_cast<PSID>(
        const_cast<std::uint8_t*>(sid.data())
    );
    if (!IsValidSid(sidPointer) || GetLengthSid(sidPointer) != sid.size()) {
        return {UnlockLogonBufferCode::invalid_sid};
    }

    output.magic = kUnlockLogonMagic;
    output.version = kUnlockLogonVersion;
    output.totalSize = static_cast<std::uint32_t>(sizeof(output));
    std::copy(keyId.begin(), keyId.end(), output.keyId);
    std::copy(
        challenge.requestId.begin(),
        challenge.requestId.end(),
        output.requestId
    );
    std::copy(challenge.nonce.begin(), challenge.nonce.end(), output.nonce);
    output.issuedAtMilliseconds = challenge.issuedAtMilliseconds;
    output.audienceLength = static_cast<std::uint16_t>(challenge.audience.size());
    std::copy(
        challenge.audience.begin(),
        challenge.audience.end(),
        output.audienceUtf8
    );
    output.sidLength = static_cast<std::uint16_t>(sid.size());
    std::copy(sid.begin(), sid.end(), output.sid);
    std::copy(signature.begin(), signature.end(), output.signatureRaw);

    return validateUnlockLogonBuffer(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&output),
        sizeof(output)
    ));
}

UnlockLogonBufferResult validateUnlockLogonBuffer(
    const std::span<const std::uint8_t> bytes
) noexcept {
    if (bytes.data() == nullptr) {
        return {UnlockLogonBufferCode::null_buffer};
    }
    if (bytes.size() != sizeof(UnlockLogonBuffer)) {
        return {UnlockLogonBufferCode::invalid_size};
    }

    UnlockLogonBuffer buffer{};
    std::memcpy(&buffer, bytes.data(), sizeof(buffer));
    return validateFields(buffer);
}

} // namespace unlock_windows::protocol
