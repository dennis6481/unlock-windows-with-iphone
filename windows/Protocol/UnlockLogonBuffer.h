// Modified by Rui MA on 27 Sep 2026

#pragma once

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <cstddef>
#include <cstdint>

namespace unlock_windows::protocol {

inline constexpr std::uint32_t kUnlockLogonMagic = 0x31505755; // "UWP1" in little-endian memory
inline constexpr std::uint32_t kUnlockLogonVersion = 1;
inline constexpr std::size_t kKeyIdSize = 32; // SHA-256(publicKeyRaw)
inline constexpr std::size_t kRequestIdSize = 16;
inline constexpr std::size_t kNonceSize = 32;
inline constexpr std::size_t kAudienceMaxUtf8Bytes = 64;
inline constexpr std::size_t kRawSignatureSize = 64;
inline constexpr char kUnlockLsaAuthenticationPackageName[] =
    "UnlockWindowsWithIPhone";

// This is the package-defined ProtocolSubmitBuffer used by the Credential
// Provider and the LSA Authentication Package. It contains no password or
// password-derived value.
#pragma pack(push, 1)
struct UnlockLogonBuffer final {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t totalSize;
    std::uint8_t keyId[kKeyIdSize];
    std::uint8_t requestId[kRequestIdSize];
    std::uint8_t nonce[kNonceSize];
    std::int64_t issuedAtMilliseconds;
    std::uint16_t audienceLength;
    std::uint8_t audienceUtf8[kAudienceMaxUtf8Bytes];
    std::uint16_t sidLength;
    std::uint8_t sid[SECURITY_MAX_SID_SIZE];
    std::uint8_t signatureRaw[kRawSignatureSize];
};
#pragma pack(pop)

static_assert(offsetof(UnlockLogonBuffer, signatureRaw) + kRawSignatureSize == sizeof(UnlockLogonBuffer));

} // namespace unlock_windows::protocol
