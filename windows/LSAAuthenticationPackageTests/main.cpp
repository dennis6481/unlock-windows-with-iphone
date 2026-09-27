// Created by Rui MA on 27 Sep 2026

#include "EnrollmentStore.h"
#include "UnlockLsaAuthenticationPackage.h"
#include "UnlockLsaLogonVerifier.h"
#include "SigningPayload.h"
#include "UnlockLogonBufferCodec.h"

#define WIN32_NO_STATUS
#include <Windows.h>
#include <sddl.h>
#undef WIN32_NO_STATUS

#include <bcrypt.h>

#include <array>
#include <cstring>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using unlock_windows::protocol::FixedChallenge;
using unlock_windows::protocol::UnlockLogonBuffer;
using unlock_windows::service::EnrollmentStore;

void require(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void requireStatus(const NTSTATUS status, const char* operation) {
    if (status < 0) {
        throw std::runtime_error(operation);
    }
}

class Algorithm final {
public:
    ~Algorithm() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    BCRYPT_ALG_HANDLE* receive() noexcept { return &handle_; }
    BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class Hash final {
public:
    ~Hash() {
        if (handle_ != nullptr) {
            BCryptDestroyHash(handle_);
        }
    }

    BCRYPT_HASH_HANDLE* receive() noexcept { return &handle_; }
    BCRYPT_HASH_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_HASH_HANDLE handle_ = nullptr;
};

class Key final {
public:
    ~Key() {
        if (handle_ != nullptr) {
            BCryptDestroyKey(handle_);
        }
    }

    BCRYPT_KEY_HANDLE* receive() noexcept { return &handle_; }
    BCRYPT_KEY_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& bytes) {
    Algorithm algorithm;
    requireStatus(
        BCryptOpenAlgorithmProvider(
            algorithm.receive(),
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0
        ),
        "open SHA-256"
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
        "get SHA-256 object size"
    );
    std::vector<std::uint8_t> object(objectSize);
    Hash hash;
    requireStatus(
        BCryptCreateHash(
            algorithm.get(),
            hash.receive(),
            object.data(),
            objectSize,
            nullptr,
            0,
            0
        ),
        "create SHA-256 hash"
    );
    requireStatus(
        BCryptHashData(
            hash.get(),
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(bytes.data())),
            static_cast<ULONG>(bytes.size()),
            0
        ),
        "hash data"
    );

    std::array<std::uint8_t, 32> digest{};
    requireStatus(
        BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0),
        "finish hash"
    );
    return digest;
}

struct SigningKey final {
    Algorithm algorithm;
    Key key;
    std::vector<std::uint8_t> publicKey;
    std::array<std::uint8_t, 32> keyId{};
};

SigningKey makeSigningKey() {
    SigningKey result;
    requireStatus(
        BCryptOpenAlgorithmProvider(
            result.algorithm.receive(),
            BCRYPT_ECDSA_P256_ALGORITHM,
            nullptr,
            0
        ),
        "open ECDSA P-256"
    );
    requireStatus(
        BCryptGenerateKeyPair(result.algorithm.get(), result.key.receive(), 256, 0),
        "generate ECDSA key"
    );
    requireStatus(BCryptFinalizeKeyPair(result.key.get(), 0), "finalize ECDSA key");

    ULONG blobSize = 0;
    requireStatus(
        BCryptExportKey(
            result.key.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            0,
            &blobSize,
            0
        ),
        "get ECDSA public key size"
    );
    std::vector<std::uint8_t> blob(blobSize);
    ULONG exportedSize = 0;
    requireStatus(
        BCryptExportKey(
            result.key.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            blob.data(),
            blobSize,
            &exportedSize,
            0
        ),
        "export ECDSA public key"
    );
    const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
    require(header->cbKey == 32, "test key is not P-256");
    result.publicKey.resize(65);
    result.publicKey[0] = 0x04;
    std::memcpy(
        result.publicKey.data() + 1,
        blob.data() + sizeof(BCRYPT_ECCKEY_BLOB),
        64
    );
    result.keyId = sha256(result.publicKey);
    return result;
}

std::array<std::uint8_t, 64> sign(
    const SigningKey& key,
    const std::vector<std::uint8_t>& payload
) {
    const auto digest = sha256(payload);
    std::array<std::uint8_t, 64> signature{};
    ULONG signatureSize = 0;
    requireStatus(
        BCryptSignHash(
            key.key.get(),
            nullptr,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(digest.data())),
            static_cast<ULONG>(digest.size()),
            signature.data(),
            static_cast<ULONG>(signature.size()),
            &signatureSize,
            0
        ),
        "sign test payload"
    );
    require(signatureSize == signature.size(), "test signature has an unexpected size");
    return signature;
}

std::wstring testPath() {
    wchar_t directory[MAX_PATH]{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(directory)), directory);
    require(length != 0 && length < std::size(directory), "GetTempPathW failed");
    return std::wstring(directory) +
        L"unlock-windows-with-iphone-lsa-test-" +
        std::to_wstring(GetCurrentProcessId()) + L".dat";
}

std::vector<std::uint8_t> sidBytes(const std::wstring& sidText) {
    PSID sid = nullptr;
    require(
        ConvertStringSidToSidW(sidText.c_str(), &sid) != FALSE,
        "ConvertStringSidToSidW failed in test"
    );
    const auto length = GetLengthSid(sid);
    std::vector<std::uint8_t> result(length);
    std::memcpy(result.data(), sid, length);
    LocalFree(sid);
    return result;
}

UnlockLogonBuffer makeBuffer(
    const SigningKey& key,
    const std::vector<std::uint8_t>& sid,
    const std::int64_t issuedAt
) {
    FixedChallenge challenge;
    challenge.version = 1;
    challenge.issuedAtMilliseconds = issuedAt;
    challenge.audience = unlock_windows::protocol::kUnlockAudience;
    for (std::size_t index = 0; index < challenge.requestId.size(); ++index) {
        challenge.requestId[index] = static_cast<std::uint8_t>(0x10 + index);
    }
    for (std::size_t index = 0; index < challenge.nonce.size(); ++index) {
        challenge.nonce[index] = static_cast<std::uint8_t>(0x40 + index);
    }

    const auto payload = unlock_windows::protocol::buildSigningPayload(challenge);
    require(payload.succeeded(), "LSA test payload did not build");
    const auto signature = sign(key, payload.bytes);

    UnlockLogonBuffer result{};
    const auto built = unlock_windows::protocol::buildUnlockLogonBuffer(
        challenge,
        key.keyId,
        sid,
        signature,
        result
    );
    require(built.succeeded(), "LSA test logon buffer did not build");
    return result;
}

void testVerifier() {
    const auto path = testPath();
    EnrollmentStore store(path);
    store.remove();

    const auto accountSid = EnrollmentStore::currentUserSid();
    const auto accountSidBytes = sidBytes(accountSid);
    auto signingKey = makeSigningKey();
    store.save({signingKey.publicKey, accountSid});

    const auto original = makeBuffer(signingKey, accountSidBytes, 1'000);
    const auto originalBytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&original),
        sizeof(original)
    );
    unlock_windows::lsa::UnlockLsaLogonVerifier verifier(path);
    const auto valid = verifier.verify(originalBytes, 1'001);
    require(valid.succeeded(), "independently verified LSA buffer was rejected");
    require(valid.accountSid == accountSid, "LSA verifier returned the wrong account SID");

    require(
        verifier.verify(originalBytes, 999).code ==
            unlock_windows::lsa::LogonVerificationCode::challenge_not_yet_valid,
        "future LSA challenge was accepted"
    );
    require(
        verifier.verify(originalBytes, 31'001).code ==
            unlock_windows::lsa::LogonVerificationCode::challenge_expired,
        "expired LSA challenge was accepted"
    );

    auto wrongKeyId = original;
    wrongKeyId.keyId[0] ^= 0x01;
    require(
        verifier.verify(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(&wrongKeyId),
                sizeof(wrongKeyId)
            ),
            1'001
        ).code == unlock_windows::lsa::LogonVerificationCode::key_id_mismatch,
        "wrong enrolled key ID was accepted"
    );

    auto wrongSignature = original;
    wrongSignature.signatureRaw[0] ^= 0x01;
    require(
        verifier.verify(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(&wrongSignature),
                sizeof(wrongSignature)
            ),
            1'001
        ).code == unlock_windows::lsa::LogonVerificationCode::invalid_signature,
        "tampered LSA signature was accepted"
    );

    auto wrongAudience = original;
    wrongAudience.audienceUtf8[0] = 'X';
    require(
        verifier.verify(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(&wrongAudience),
                sizeof(wrongAudience)
            ),
            1'001
        ).code == unlock_windows::lsa::LogonVerificationCode::audience_mismatch,
        "wrong LSA audience was accepted"
    );

    auto wrongSid = original;
    const auto differentSid = sidBytes(L"S-1-5-18");
    std::memset(wrongSid.sid, 0, sizeof(wrongSid.sid));
    std::memcpy(wrongSid.sid, differentSid.data(), differentSid.size());
    wrongSid.sidLength = static_cast<std::uint16_t>(differentSid.size());
    require(
        verifier.verify(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(&wrongSid),
                sizeof(wrongSid)
            ),
            1'001
        ).code == unlock_windows::lsa::LogonVerificationCode::sid_mismatch,
        "wrong enrolled SID was accepted"
    );

    store.remove();
}

PVOID NTAPI testAllocateLsaHeap(const ULONG length) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length);
}

VOID NTAPI testFreeLsaHeap(const PVOID base) {
    if (base != nullptr) {
        HeapFree(GetProcessHeap(), 0, base);
    }
}

void testPackageExports() {
    wchar_t modulePath[32'768]{};
    const DWORD length = GetModuleFileNameW(
        nullptr,
        modulePath,
        static_cast<DWORD>(std::size(modulePath))
    );
    require(length != 0 && length < std::size(modulePath), "GetModuleFileNameW failed");
    std::wstring directory(modulePath, length);
    directory.resize(directory.find_last_of(L'\\') + 1);

    const auto module = LoadLibraryW(
        (directory + L"unlock_lsa_authentication_package.dll").c_str()
    );
    require(module != nullptr, "could not load the build-only LSA package DLL");

    using InitializePackage = NTSTATUS(NTAPI*)(
        ULONG,
        PLSA_DISPATCH_TABLE,
        PLSA_STRING,
        PLSA_STRING,
        PLSA_STRING*
    );
    const auto initialize = reinterpret_cast<InitializePackage>(
        GetProcAddress(module, "LsaApInitializePackage")
    );
    const auto logon = GetProcAddress(module, "LsaApLogonUserEx2");
    const auto passthrough = GetProcAddress(module, "LsaApCallPackagePassthrough");
    require(
        initialize != nullptr && logon != nullptr && passthrough != nullptr,
        "LSA package exports are missing"
    );

    LSA_DISPATCH_TABLE dispatch{};
    dispatch.AllocateLsaHeap = testAllocateLsaHeap;
    dispatch.FreeLsaHeap = testFreeLsaHeap;
    LSA_STRING* packageName = nullptr;
    require(
        initialize(1, &dispatch, nullptr, nullptr, &packageName) == STATUS_SUCCESS,
        "LsaApInitializePackage rejected the test dispatch table"
    );
    require(packageName != nullptr, "LSA package did not return a package name");
    require(
        std::string(packageName->Buffer, packageName->Length) ==
            unlock_windows::protocol::kUnlockLsaAuthenticationPackageName,
        "LSA package returned an unexpected package name"
    );
    testFreeLsaHeap(packageName->Buffer);
    testFreeLsaHeap(packageName);
    FreeLibrary(module);
}

} // namespace

int main() {
    try {
        testVerifier();
        testPackageExports();
        std::cout << "LSA authentication package tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "LSA authentication package tests failed: "
                  << error.what() << "\n";
        return 1;
    }
}
