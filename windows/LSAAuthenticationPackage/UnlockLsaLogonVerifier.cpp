// Created by Rui MA on 27 Sep 2026

#include "UnlockLsaLogonVerifier.h"

#include "EnrollmentStore.h"
#include "SigningPayload.h"

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <sddl.h>

#include <algorithm>
#include <cstring>
#include <utility>

namespace unlock_windows::lsa {
namespace {

[[nodiscard]] std::string keyIdHex(
    const std::uint8_t* bytes,
    const std::size_t size
) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for (std::size_t index = 0; index < size; ++index) {
        result.push_back(alphabet[bytes[index] >> 4]);
        result.push_back(alphabet[bytes[index] & 0x0f]);
    }
    return result;
}

[[nodiscard]] protocol::FixedChallenge challengeFromBuffer(
    const protocol::UnlockLogonBuffer& buffer
) {
    protocol::FixedChallenge challenge;
    challenge.version = buffer.version;
    std::copy_n(
        std::begin(buffer.requestId),
        challenge.requestId.size(),
        challenge.requestId.begin()
    );
    std::copy_n(
        std::begin(buffer.nonce),
        challenge.nonce.size(),
        challenge.nonce.begin()
    );
    challenge.issuedAtMilliseconds = buffer.issuedAtMilliseconds;
    challenge.audience.assign(
        reinterpret_cast<const char*>(buffer.audienceUtf8),
        buffer.audienceLength
    );
    return challenge;
}

[[nodiscard]] bool sameSid(
    const std::wstring& enrolledSid,
    const std::uint8_t* submittedSid
) noexcept {
    PSID parsed = nullptr;
    if (!ConvertStringSidToSidW(enrolledSid.c_str(), &parsed)) {
        return false;
    }
    const bool matches = EqualSid(parsed, const_cast<std::uint8_t*>(submittedSid)) != FALSE;
    LocalFree(parsed);
    return matches;
}

} // namespace

UnlockLsaLogonVerifier::UnlockLsaLogonVerifier(
    std::wstring enrollmentPath,
    const std::int64_t challengeLifetimeMilliseconds,
    std::string expectedAudience
)
    : enrollmentPath_(std::move(enrollmentPath)),
      challengeLifetimeMilliseconds_(challengeLifetimeMilliseconds),
      expectedAudience_(std::move(expectedAudience)) {}

LogonVerificationResult UnlockLsaLogonVerifier::verify(
    const std::span<const std::uint8_t> bufferBytes,
    const std::int64_t nowMilliseconds
) const noexcept {
    try {
        if (challengeLifetimeMilliseconds_ <= 0 || expectedAudience_.empty()) {
            return {LogonVerificationCode::invalid_buffer, {}};
        }

        const auto structure = protocol::validateUnlockLogonBuffer(bufferBytes);
        if (!structure.succeeded()) {
            return {LogonVerificationCode::invalid_buffer, {}};
        }

        protocol::UnlockLogonBuffer buffer{};
        std::memcpy(&buffer, bufferBytes.data(), sizeof(buffer));
        if (buffer.audienceLength != expectedAudience_.size() ||
            std::memcmp(
                buffer.audienceUtf8,
                expectedAudience_.data(),
                expectedAudience_.size()
            ) != 0) {
            return {LogonVerificationCode::audience_mismatch, {}};
        }

        if (nowMilliseconds < buffer.issuedAtMilliseconds) {
            return {LogonVerificationCode::challenge_not_yet_valid, {}};
        }
        if (nowMilliseconds - buffer.issuedAtMilliseconds >
            challengeLifetimeMilliseconds_) {
            return {LogonVerificationCode::challenge_expired, {}};
        }

        service::EnrollmentStore store(enrollmentPath_);
        const auto enrolled = store.load();
        if (!enrolled) {
            return {LogonVerificationCode::enrollment_missing, {}};
        }

        const auto enrolledKeyId = service::EnrollmentStore::fingerprint(
            enrolled->publicKey
        );
        if (enrolledKeyId != keyIdHex(buffer.keyId, protocol::kKeyIdSize)) {
            return {LogonVerificationCode::key_id_mismatch, {}};
        }
        if (!sameSid(enrolled->accountSid, buffer.sid)) {
            return {LogonVerificationCode::sid_mismatch, {}};
        }

        const auto challenge = challengeFromBuffer(buffer);
        const auto payload = protocol::buildSigningPayload(challenge);
        if (!payload.succeeded()) {
            return {LogonVerificationCode::invalid_buffer, {}};
        }

        const auto signature = protocol::verifyP256Signature(
            enrolled->publicKey.data(),
            enrolled->publicKey.size(),
            payload.bytes.data(),
            payload.bytes.size(),
            buffer.signatureRaw,
            protocol::kRawSignatureSize
        );
        if (signature.code == protocol::VerificationCode::invalid_signature) {
            return {LogonVerificationCode::invalid_signature, {}};
        }
        if (!signature.isValid()) {
            return {LogonVerificationCode::cryptographic_failure, {}};
        }
        return {LogonVerificationCode::valid, enrolled->accountSid};
    } catch (...) {
        return {LogonVerificationCode::enrollment_invalid, {}};
    }
}

} // namespace unlock_windows::lsa
