#pragma once

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>

#include <cstddef>
#include <cstdint>

namespace unlock_windows::protocol {

inline constexpr std::size_t kP256RawPublicKeySize = 65; // SEC1 uncompressed: 0x04 || X || Y
inline constexpr std::size_t kP256CoordinateSize = 32;
inline constexpr std::size_t kP256RawSignatureSize = 64; // fixed-width r || s

enum class VerificationCode {
    valid,
    invalid_argument,
    invalid_signature,
    cryptographic_api_failure,
};

struct VerificationResult {
    VerificationCode code;
    NTSTATUS status;

    [[nodiscard]] bool isValid() const noexcept {
        return code == VerificationCode::valid;
    }
};

// Verifies an iOS CryptoKit P-256 signature.
//
// message is the fixed binary signing payload defined in protocol/README.md.
// The function hashes message with SHA-256 before calling BCryptVerifySignature,
// because the Windows CNG ECDSA verifier consumes the pre-hash.
//
// The public key and signature must be the raw formats emitted by CryptoKit;
// no DER parser or software-key fallback is used here.
[[nodiscard]] VerificationResult verifyP256Signature(
    const std::uint8_t* publicKeyRaw,
    std::size_t publicKeyRawSize,
    const std::uint8_t* message,
    std::size_t messageSize,
    const std::uint8_t* signatureRaw,
    std::size_t signatureRawSize
) noexcept;

} // namespace unlock_windows::protocol
