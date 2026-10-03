#include "UnlockCrypto.h"

#include <cstring>
#include <limits>
#include <vector>
#include <utility>

namespace unlock_windows::protocol {
namespace {

class AlgorithmHandle final {
public:
    AlgorithmHandle() = default;
    ~AlgorithmHandle() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;

    [[nodiscard]] BCRYPT_ALG_HANDLE* receive() noexcept {
        return &handle_;
    }

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept {
        return handle_;
    }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class HashHandle final {
public:
    HashHandle() = default;
    ~HashHandle() {
        if (handle_ != nullptr) {
            BCryptDestroyHash(handle_);
        }
    }

    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;

    [[nodiscard]] BCRYPT_HASH_HANDLE* receive() noexcept {
        return &handle_;
    }

    [[nodiscard]] BCRYPT_HASH_HANDLE get() const noexcept {
        return handle_;
    }

private:
    BCRYPT_HASH_HANDLE handle_ = nullptr;
};

class KeyHandle final {
public:
    KeyHandle() = default;
    ~KeyHandle() {
        if (handle_ != nullptr) {
            BCryptDestroyKey(handle_);
        }
    }

    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;

    [[nodiscard]] BCRYPT_KEY_HANDLE* receive() noexcept {
        return &handle_;
    }

    [[nodiscard]] BCRYPT_KEY_HANDLE get() const noexcept {
        return handle_;
    }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

[[nodiscard]] VerificationResult failure(
    VerificationCode code,
    NTSTATUS status
) noexcept {
    return VerificationResult{code, status};
}

} // namespace

NTSTATUS sha256(const std::uint8_t* bytes, const std::size_t size, Sha256Digest& output) noexcept {
    output.fill(0);
    if ((bytes == nullptr && size != 0) || size > std::numeric_limits<ULONG>::max())
        return STATUS_INVALID_PARAMETER;
    try {
        AlgorithmHandle algorithm;
        NTSTATUS status = BCryptOpenAlgorithmProvider(algorithm.receive(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status < 0) return status;
        ULONG objectSize = 0;
        ULONG resultSize = 0;
        status = BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &resultSize, 0);
        if (status < 0) return status;
        if (objectSize == 0 || resultSize != sizeof(objectSize)) return STATUS_INVALID_PARAMETER;
        std::vector<std::uint8_t> object(objectSize);
        HashHandle hash;
        status = BCryptCreateHash(algorithm.get(), hash.receive(), object.data(), objectSize, nullptr, 0, 0);
        if (status < 0) return status;
        if (size != 0) {
            status = BCryptHashData(hash.get(), const_cast<PUCHAR>(bytes), static_cast<ULONG>(size), 0);
            if (status < 0) return status;
        }
        Sha256Digest digest{};
        status = BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
        if (status >= 0) output = digest;
        return status;
    } catch (...) { return STATUS_NO_MEMORY; }
}

NTSTATUS publicKeyFingerprint(const std::uint8_t* publicKey, const std::size_t size,
    std::string& output) noexcept {
    output.clear();
    if (publicKey == nullptr || size != kP256RawPublicKeySize || publicKey[0] != 0x04)
        return STATUS_INVALID_PARAMETER;
    Sha256Digest digest{};
    const auto status = sha256(publicKey, size, digest);
    if (status < 0) return status;
    try {
        constexpr char alphabet[] = "0123456789abcdef";
        std::string result;
        result.reserve(digest.size() * 2);
        for (const auto value : digest) {
            result.push_back(alphabet[value >> 4]);
            result.push_back(alphabet[value & 0x0f]);
        }
        output = std::move(result);
        return STATUS_SUCCESS;
    } catch (...) { return STATUS_NO_MEMORY; }
}

VerificationResult verifyP256Signature(
    const std::uint8_t* publicKeyRaw,
    const std::size_t publicKeyRawSize,
    const std::uint8_t* message,
    const std::size_t messageSize,
    const std::uint8_t* signatureRaw,
    const std::size_t signatureRawSize
) noexcept {
    if (publicKeyRaw == nullptr || message == nullptr || signatureRaw == nullptr ||
        publicKeyRawSize != kP256RawPublicKeySize ||
        signatureRawSize != kP256RawSignatureSize ||
        messageSize == 0 || publicKeyRaw[0] != 0x04) {
        return failure(VerificationCode::invalid_argument, STATUS_INVALID_PARAMETER);
    }

    try {
        Sha256Digest digest{};
        NTSTATUS status = sha256(message, messageSize, digest);
        if (status < 0) {
            return failure(status == STATUS_INVALID_PARAMETER ? VerificationCode::invalid_argument
                : VerificationCode::cryptographic_api_failure, status);
        }

        AlgorithmHandle ecdsaAlgorithm;
        status = BCryptOpenAlgorithmProvider(
        ecdsaAlgorithm.receive(),
        BCRYPT_ECDSA_P256_ALGORITHM,
        nullptr,
        0
        );
        if (status < 0) {
            return failure(VerificationCode::cryptographic_api_failure, status);
        }

        alignas(BCRYPT_ECCKEY_BLOB) std::uint8_t keyBlob[sizeof(BCRYPT_ECCKEY_BLOB) + (2 * kP256CoordinateSize)]{};
        auto* keyHeader = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(keyBlob);
        keyHeader->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        keyHeader->cbKey = static_cast<ULONG>(kP256CoordinateSize);
        std::memcpy(keyBlob + sizeof(BCRYPT_ECCKEY_BLOB), publicKeyRaw + 1, 2 * kP256CoordinateSize);

        KeyHandle publicKey;
        status = BCryptImportKeyPair(
        ecdsaAlgorithm.get(),
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        publicKey.receive(),
        keyBlob,
        static_cast<ULONG>(sizeof(keyBlob)),
        0
        );
        if (status < 0) {
            return failure(VerificationCode::cryptographic_api_failure, status);
        }

        status = BCryptVerifySignature(
        publicKey.get(),
        nullptr,
        digest.data(),
        static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(signatureRaw)),
        static_cast<ULONG>(signatureRawSize),
        0
        );
        if (status == STATUS_SUCCESS) {
            return VerificationResult{VerificationCode::valid, status};
        }
        if (status == STATUS_INVALID_SIGNATURE) {
            return failure(VerificationCode::invalid_signature, status);
        }
        return failure(VerificationCode::cryptographic_api_failure, status);
    } catch (...) {
        return failure(VerificationCode::cryptographic_api_failure, STATUS_NO_MEMORY);
    }
}

} // namespace unlock_windows::protocol
