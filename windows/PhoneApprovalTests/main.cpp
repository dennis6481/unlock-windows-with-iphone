// Created by Rui MA on 26 Sep 2026

#include "PhoneApprovalCore.h"

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>

#include <winrt/base.h>

#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using unlock_windows::phone_approval::AssertionCode;
using unlock_windows::phone_approval::PhoneApprovalCore;

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

std::array<std::uint8_t, 32> sha256(const std::uint8_t* bytes, const std::size_t size) {
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
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(bytes)),
            static_cast<ULONG>(size),
            0
        ),
        "hash data"
    );

    std::array<std::uint8_t, 32> result{};
    requireStatus(
        BCryptFinishHash(hash.get(), result.data(), static_cast<ULONG>(result.size()), 0),
        "finish hash"
    );
    return result;
}

std::string hex(const std::array<std::uint8_t, 32>& bytes) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto value : bytes) {
        result.push_back(alphabet[value >> 4]);
        result.push_back(alphabet[value & 0x0f]);
    }
    return result;
}

std::string base64(const std::vector<std::uint8_t>& bytes) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (std::size_t index = 0; index < bytes.size(); index += 3) {
        const auto remaining = bytes.size() - index;
        const auto first = bytes[index];
        const auto second = remaining > 1 ? bytes[index + 1] : 0;
        const auto third = remaining > 2 ? bytes[index + 2] : 0;
        result.push_back(alphabet[first >> 2]);
        result.push_back(alphabet[((first & 3) << 4) | (second >> 4)]);
        result.push_back(remaining > 1 ? alphabet[((second & 15) << 2) | (third >> 6)] : '=');
        result.push_back(remaining > 2 ? alphabet[third & 63] : '=');
    }
    return result;
}

struct SignedAssertion final {
    std::vector<std::uint8_t> publicKey;
    std::vector<std::uint8_t> signature;
    std::string keyId;
};

struct SigningKey final {
    Algorithm algorithm;
    Key key;
    std::vector<std::uint8_t> publicKey;
    std::string keyId;
};

std::unique_ptr<SigningKey> makeSigningKey() {
    auto result = std::make_unique<SigningKey>();
    requireStatus(
        BCryptOpenAlgorithmProvider(
            result->algorithm.receive(),
            BCRYPT_ECDSA_P256_ALGORITHM,
            nullptr,
            0
        ),
        "open ECDSA P-256"
    );

    requireStatus(
        BCryptGenerateKeyPair(result->algorithm.get(), result->key.receive(), 256, 0),
        "generate key"
    );
    requireStatus(BCryptFinalizeKeyPair(result->key.get(), 0), "finalize key");

    ULONG blobSize = 0;
    requireStatus(
        BCryptExportKey(
            result->key.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            0,
            &blobSize,
            0
        ),
        "get public key size"
    );
    std::vector<std::uint8_t> blob(blobSize);
    ULONG exportedSize = 0;
    requireStatus(
        BCryptExportKey(
            result->key.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            blob.data(),
            blobSize,
            &exportedSize,
            0
        ),
        "export public key"
    );
    const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
    require(header->cbKey == 32, "generated key is not P-256");

    result->publicKey.resize(65);
    result->publicKey[0] = 0x04;
    std::memcpy(result->publicKey.data() + 1, blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), 64);
    result->keyId = hex(sha256(result->publicKey.data(), result->publicKey.size()));
    return result;
}

SignedAssertion sign(
    const SigningKey& key,
    const std::vector<std::uint8_t>& payload
) {
    SignedAssertion result;
    result.publicKey = key.publicKey;
    result.keyId = key.keyId;

    const auto digest = sha256(payload.data(), payload.size());
    result.signature.resize(64);
    ULONG signatureSize = 0;
    requireStatus(
        BCryptSignHash(
            key.key.get(),
            nullptr,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(digest.data())),
            static_cast<ULONG>(digest.size()),
            result.signature.data(),
            static_cast<ULONG>(result.signature.size()),
            &signatureSize,
            0
        ),
        "sign payload"
    );
    require(signatureSize == result.signature.size(), "unexpected signature size");
    return result;
}

std::string makeAssertion(
    const PhoneApprovalCore& service,
    const unlock_windows::phone_approval::IssuedChallenge& issued,
    const SignedAssertion& signedAssertion
) {
    return "{\"keyID\":\"" + signedAssertion.keyId +
        "\",\"publicKeyRawRepresentation\":\"" + base64(signedAssertion.publicKey) +
        "\",\"requestID\":\"" + service.requestIdString(issued.challenge) +
        "\",\"signatureRawRepresentation\":\"" + base64(signedAssertion.signature) +
        "\",\"version\":1}";
}

void run() {
    PhoneApprovalCore service;
    const auto issued = service.issueChallenge(1'000);
    require(issued.json.find("windows-unlock") != std::string::npos, "challenge audience missing");
    require(issued.json.find(service.requestIdString(issued.challenge)) != std::string::npos, "challenge request ID missing");

    require(
        service.verifyAssertion("not json", 1'001).code == AssertionCode::malformed_json,
        "malformed JSON was accepted"
    );
    require(
        service.verifyAssertion(
            "{\"requestID\":\"00000000-0000-0000-0000-000000000000\",\"version\":1}",
            1'001
        ).code == AssertionCode::request_mismatch,
        "mismatched request was not rejected"
    );
    require(
        service.verifyAssertion("{}", 32'000).code == AssertionCode::challenge_expired,
        "expired challenge was not rejected"
    );

    const auto boundary = service.issueChallenge(1'000);
    require(service.verifyAssertion("{}", 30'999).code != AssertionCode::challenge_expired,
        "challenge expired before the 30-second deadline");
    require(service.verifyAssertion("{}", 31'000).code == AssertionCode::challenge_expired,
        "challenge must expire exactly at the 30-second boundary");

    const auto validIssued = service.issueChallenge(2'000);
    const auto payload = unlock_windows::protocol::buildSigningPayload(validIssued.challenge);
    require(payload.succeeded(), "test payload did not build");
    const auto signingKey = makeSigningKey();
    const auto signedAssertion = sign(*signingKey, payload.bytes);
    const auto assertion = makeAssertion(service, validIssued, signedAssertion);
    require(
        service.verifyAssertion(assertion, 2'001).code == AssertionCode::key_not_enrolled,
        "un-enrolled public key was accepted"
    );
    service.setEnrolledPublicKey(signedAssertion.publicKey);
    service.setEnrolledAccountSid("S-1-5-21-111111111-222222222-333333333-1001");
    const auto valid = service.verifyAssertion(assertion, 2'001);
    require(valid.code == AssertionCode::authenticated, "valid assertion was rejected");
    require(valid.unlockApproved(), "valid assertion with an enrolled SID was not approved");
    require(
        valid.accountSid == "S-1-5-21-111111111-222222222-333333333-1001",
        "approved assertion returned the wrong account SID"
    );
    require(
        service.verifyAssertion(assertion, 2'002).code == AssertionCode::challenge_replayed,
        "replayed assertion was accepted"
    );
    const auto approval = service.consumeUnlockApproval(2'003);
    require(approval.has_value(), "approved assertion did not create a pending approval");
    require(
        approval->issuedAtMilliseconds == validIssued.challenge.issuedAtMilliseconds &&
            approval->accountSid == "S-1-5-21-111111111-222222222-333333333-1001",
        "pending approval did not preserve the verified identity"
    );
    require(
        !service.consumeUnlockApproval(2'004).has_value(),
        "pending approval could be consumed more than once"
    );

    const auto nextIssued = service.issueChallenge(2'004);
    const auto nextPayload = unlock_windows::protocol::buildSigningPayload(nextIssued.challenge);
    require(nextPayload.succeeded(), "immediate next request payload did not build");
    const auto nextSignature = sign(*signingKey, nextPayload.bytes);
    const auto nextAssertion = makeAssertion(service, nextIssued, nextSignature);
    require(
        service.verifyAssertion(assertion, 2'005).code == AssertionCode::request_mismatch,
        "the previous assertion was accepted for the next request"
    );
    const auto nextValid = service.verifyAssertion(nextAssertion, 2'005);
    require(
        nextValid.unlockApproved() && nextValid.accountSid == valid.accountSid,
        "an immediate fresh approval was rejected or returned the wrong identity"
    );
    require(
        service.verifyAssertion(nextAssertion, 2'006).code == AssertionCode::challenge_replayed,
        "the immediate fresh assertion could be replayed"
    );
    const auto nextApproval = service.consumeUnlockApproval(2'006);
    require(
        nextApproval && nextApproval->issuedAtMilliseconds == nextIssued.challenge.issuedAtMilliseconds &&
            nextApproval->accountSid == valid.accountSid,
        "the immediate fresh approval was unavailable or had the wrong identity"
    );
    require(
        !service.consumeUnlockApproval(2'007).has_value(),
        "the immediate fresh approval could be consumed more than once"
    );

    const auto expiredIssued = service.issueChallenge(13'000);
    const auto expiredPayload = unlock_windows::protocol::buildSigningPayload(expiredIssued.challenge);
    require(expiredPayload.succeeded(), "expired approval payload did not build");
    const auto expiredSignature = sign(*signingKey, expiredPayload.bytes);
    const auto expiredAssertion = makeAssertion(service, expiredIssued, expiredSignature);
    require(
        service.verifyAssertion(expiredAssertion, 13'001).unlockApproved(),
        "expired approval fixture could not be authenticated before expiry"
    );
    require(
        !service.consumeUnlockApproval(43'002).has_value(),
        "expired pending approval was returned"
    );

    std::cout << "PhoneApprovalCore tests passed\n";
}

} // namespace

int main() {
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        run();
        winrt::uninit_apartment();
        return 0;
    } catch (const winrt::hresult_error& error) {
        std::cerr << "PhoneApprovalCore test failed: "
                  << winrt::to_string(error.message()) << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "PhoneApprovalCore test failed: " << error.what() << "\n";
        return 1;
    }
}
