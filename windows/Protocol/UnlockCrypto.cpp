// Created by Rui MA on 26 Sep 2026

#include "UnlockCrypto.h"
#include <ntstatus.h>

#include <limits>
#include <vector>

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

} // namespace unlock_windows::protocol
