// Created by Rui MA on 26 Sep 2026

#include "SigningPayload.h"
#include "UnlockCrypto.h"

#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using unlock_windows::protocol::FixedChallenge;

void require(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void requireStatus(const NTSTATUS status, const char* operation) {
    if (status < 0) {
        throw std::runtime_error(
            std::string(operation) + " failed with NTSTATUS=" +
            std::to_string(static_cast<long>(status))
        );
    }
}

class ScopedAlgorithm final {
public:
    ScopedAlgorithm() = default;

    ~ScopedAlgorithm() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    ScopedAlgorithm(const ScopedAlgorithm&) = delete;
    ScopedAlgorithm& operator=(const ScopedAlgorithm&) = delete;

    [[nodiscard]] BCRYPT_ALG_HANDLE* receive() noexcept {
        return &handle_;
    }

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept {
        return handle_;
    }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class ScopedHash final {
public:
    ScopedHash() = default;

    ~ScopedHash() {
        if (handle_ != nullptr) {
            BCryptDestroyHash(handle_);
        }
    }

    ScopedHash(const ScopedHash&) = delete;
    ScopedHash& operator=(const ScopedHash&) = delete;

    [[nodiscard]] BCRYPT_HASH_HANDLE* receive() noexcept {
        return &handle_;
    }

    [[nodiscard]] BCRYPT_HASH_HANDLE get() const noexcept {
        return handle_;
    }

private:
    BCRYPT_HASH_HANDLE handle_ = nullptr;
};

class ScopedKey final {
public:
    ScopedKey() = default;

    ~ScopedKey() {
        if (handle_ != nullptr) {
            BCryptDestroyKey(handle_);
        }
    }

    ScopedKey(const ScopedKey&) = delete;
    ScopedKey& operator=(const ScopedKey&) = delete;

    [[nodiscard]] BCRYPT_KEY_HANDLE* receive() noexcept {
        return &handle_;
    }

    [[nodiscard]] BCRYPT_KEY_HANDLE get() const noexcept {
        return handle_;
    }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

std::vector<std::uint8_t> decodeHex(const std::string_view input) {
    require(input.size() % 2 == 0, "hex fixture has an odd length");

    auto nibble = [](const char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') {
            return static_cast<std::uint8_t>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<std::uint8_t>(value - 'a' + 10);
        }
        if (value >= 'A' && value <= 'F') {
            return static_cast<std::uint8_t>(value - 'A' + 10);
        }
        throw std::runtime_error("hex fixture contains an invalid character");
    };

    std::vector<std::uint8_t> result;
    result.reserve(input.size() / 2);
    for (std::size_t index = 0; index < input.size(); index += 2) {
        result.push_back(static_cast<std::uint8_t>(
            (nibble(input[index]) << 4) | nibble(input[index + 1])
        ));
    }
    return result;
}

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    ScopedAlgorithm algorithm;
    requireStatus(
        BCryptOpenAlgorithmProvider(
            algorithm.receive(),
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0
        ),
        "BCryptOpenAlgorithmProvider(SHA-256)"
    );

    ULONG objectSize = 0;
    ULONG resultSize = 0;
    requireStatus(
        BCryptGetProperty(
            algorithm.get(),
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize),
            &resultSize,
            0
        ),
        "BCryptGetProperty(BCRYPT_OBJECT_LENGTH)"
    );
    require(objectSize != 0, "SHA-256 object size is zero");

    std::vector<std::uint8_t> object(objectSize);
    ScopedHash hash;
    requireStatus(
        BCryptCreateHash(
            algorithm.get(),
            hash.receive(),
            object.data(),
            static_cast<ULONG>(object.size()),
            nullptr,
            0,
            0
        ),
        "BCryptCreateHash"
    );
    requireStatus(
        BCryptHashData(
            hash.get(),
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data())),
            static_cast<ULONG>(data.size()),
            0
        ),
        "BCryptHashData"
    );

    std::array<std::uint8_t, 32> digest{};
    requireStatus(
        BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0),
        "BCryptFinishHash"
    );
    return digest;
}

struct GeneratedSignature final {
    std::vector<std::uint8_t> publicKeyRaw;
    std::vector<std::uint8_t> signatureRaw;
};

GeneratedSignature signForTest(const std::vector<std::uint8_t>& payload) {
    // Test-only ephemeral key. Product code never falls back to a software key.
    ScopedAlgorithm algorithm;
    requireStatus(
        BCryptOpenAlgorithmProvider(
            algorithm.receive(),
            BCRYPT_ECDSA_P256_ALGORITHM,
            nullptr,
            0
        ),
        "BCryptOpenAlgorithmProvider(ECDSA P-256)"
    );

    ScopedKey key;
    requireStatus(
        BCryptGenerateKeyPair(algorithm.get(), key.receive(), 256, 0),
        "BCryptGenerateKeyPair"
    );
    requireStatus(BCryptFinalizeKeyPair(key.get(), 0), "BCryptFinalizeKeyPair");

    ULONG blobSize = 0;
    requireStatus(
        BCryptExportKey(
            key.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            0,
            &blobSize,
            0
        ),
        "BCryptExportKey(size)"
    );
    std::vector<std::uint8_t> blob(blobSize);
    ULONG exportedSize = 0;
    requireStatus(
        BCryptExportKey(
            key.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            blob.data(),
            static_cast<ULONG>(blob.size()),
            &exportedSize,
            0
        ),
        "BCryptExportKey"
    );
    require(exportedSize >= sizeof(BCRYPT_ECCKEY_BLOB), "ECC public blob is truncated");

    const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
    require(header->cbKey == 32, "ECC public blob is not P-256");
    require(
        exportedSize >= sizeof(BCRYPT_ECCKEY_BLOB) + (2 * header->cbKey),
        "ECC public coordinates are truncated"
    );

    GeneratedSignature result;
    result.publicKeyRaw.resize(1 + (2 * header->cbKey));
    result.publicKeyRaw[0] = 0x04;
    std::memcpy(
        result.publicKeyRaw.data() + 1,
        blob.data() + sizeof(BCRYPT_ECCKEY_BLOB),
        2 * header->cbKey
    );

    const auto digest = sha256(payload);
    result.signatureRaw.resize(2 * header->cbKey);
    ULONG signatureSize = 0;
    requireStatus(
        BCryptSignHash(
            key.get(),
            nullptr,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(digest.data())),
            static_cast<ULONG>(digest.size()),
            result.signatureRaw.data(),
            static_cast<ULONG>(result.signatureRaw.size()),
            &signatureSize,
            0
        ),
        "BCryptSignHash"
    );
    require(signatureSize == result.signatureRaw.size(), "unexpected ECDSA signature size");
    return result;
}

FixedChallenge makeFixture() {
    FixedChallenge challenge;
    challenge.version = 1;
    for (std::size_t index = 0; index < challenge.requestId.size(); ++index) {
        challenge.requestId[index] = static_cast<std::uint8_t>(0x10 + index);
    }
    for (std::size_t index = 0; index < challenge.nonce.size(); ++index) {
        challenge.nonce[index] = static_cast<std::uint8_t>(index);
    }
    challenge.issuedAtMilliseconds = 0x0102030405060708LL;
    challenge.audience = "windows-unlock";
    return challenge;
}

void testSigningPayload() {
    const auto challenge = makeFixture();
    const auto result = unlock_windows::protocol::buildSigningPayload(challenge);
    require(result.succeeded(), "fixed challenge payload should build");

    const auto expected = decodeHex(
        "756e6c6f636b2d77696e646f77732d776974682d6970686f6e652f7631"
        "00"
        "00000001"
        "101112131415161718191a1b1c1d1e1f"
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "0102030405060708"
        "000e"
        "77696e646f77732d756e6c6f636b"
    );
    require(result.bytes == expected, "fixed challenge payload does not match the protocol fixture");

    auto invalidVersion = challenge;
    invalidVersion.version = 2;
    require(
        unlock_windows::protocol::buildSigningPayload(invalidVersion).code ==
            unlock_windows::protocol::PayloadBuildCode::invalid_version,
        "unsupported protocol version should be rejected"
    );

    auto invalidAudience = challenge;
    invalidAudience.audience.clear();
    require(
        unlock_windows::protocol::buildSigningPayload(invalidAudience).code ==
            unlock_windows::protocol::PayloadBuildCode::invalid_audience,
        "empty audience should be rejected"
    );
}

void testCngVerifier() {
    const auto challenge = makeFixture();
    const auto payloadResult = unlock_windows::protocol::buildSigningPayload(challenge);
    require(payloadResult.succeeded(), "CNG test payload should build");

    auto signature = signForTest(payloadResult.bytes);
    auto verification = unlock_windows::protocol::verifyP256Signature(
        signature.publicKeyRaw.data(),
        signature.publicKeyRaw.size(),
        payloadResult.bytes.data(),
        payloadResult.bytes.size(),
        signature.signatureRaw.data(),
        signature.signatureRaw.size()
    );
    require(verification.isValid(), "CNG verifier rejected a freshly generated signature");

    signature.signatureRaw[0] ^= 0x01;
    verification = unlock_windows::protocol::verifyP256Signature(
        signature.publicKeyRaw.data(),
        signature.publicKeyRaw.size(),
        payloadResult.bytes.data(),
        payloadResult.bytes.size(),
        signature.signatureRaw.data(),
        signature.signatureRaw.size()
    );
    require(
        verification.code == unlock_windows::protocol::VerificationCode::invalid_signature,
        "CNG verifier accepted a tampered signature"
    );
}

} // namespace

int main() {
    try {
        testSigningPayload();
        testCngVerifier();
        std::cout << "unlock_protocol_tests: passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "unlock_protocol_tests: failed: " << error.what() << '\n';
        return 1;
    }
}
