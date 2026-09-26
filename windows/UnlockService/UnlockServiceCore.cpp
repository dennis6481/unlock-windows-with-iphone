#include "UnlockServiceCore.h"

#include "UnlockCrypto.h"

#include <Windows.h>
#include <bcrypt.h>

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace unlock_windows::service {
namespace {

using winrt::Windows::Data::Json::JsonObject;

constexpr std::size_t kRequestIdSize = 16;
constexpr std::size_t kNonceSize = 32;
constexpr std::size_t kRawPublicKeySize = 65;
constexpr std::size_t kRawSignatureSize = 64;

struct AlgorithmHandle final {
    BCRYPT_ALG_HANDLE value = nullptr;

    ~AlgorithmHandle() {
        if (value != nullptr) {
            BCryptCloseAlgorithmProvider(value, 0);
        }
    }
};

struct HashHandle final {
    BCRYPT_HASH_HANDLE value = nullptr;

    ~HashHandle() {
        if (value != nullptr) {
            BCryptDestroyHash(value);
        }
    }
};

[[nodiscard]] bool isHex(const char value) noexcept {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

[[nodiscard]] std::uint8_t hexNibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(value - 'A' + 10);
    }
    throw std::invalid_argument("invalid hexadecimal digit");
}

[[nodiscard]] std::string lowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const char character) {
        if (character >= 'A' && character <= 'Z') {
            return static_cast<char>(character - 'A' + 'a');
        }
        return character;
    });
    return value;
}

[[nodiscard]] std::string escapeJsonString(const std::string_view value) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : value) {
        switch (byte) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (static_cast<unsigned char>(byte) < 0x20) {
                    output << "\\u" << std::setw(4)
                           << static_cast<unsigned int>(static_cast<unsigned char>(byte));
                } else {
                    output << byte;
                }
                break;
        }
    }
    return output.str();
}

[[nodiscard]] std::optional<std::array<std::uint8_t, kRequestIdSize>> parseRequestId(
    const std::string_view value
) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-') {
        return std::nullopt;
    }

    std::array<std::uint8_t, kRequestIdSize> result{};
    std::size_t outputIndex = 0;
    for (std::size_t index = 0; index < value.size(); index++) {
        if (value[index] == '-') {
            continue;
        }
        if (outputIndex >= result.size() || index + 1 >= value.size() || value[index + 1] == '-' ||
            !isHex(value[index]) || !isHex(value[index + 1])) {
            return std::nullopt;
        }
        result[outputIndex++] = static_cast<std::uint8_t>(
            (hexNibble(value[index]) << 4) | hexNibble(value[index + 1])
        );
        index++;
    }
    return outputIndex == result.size() ? std::optional{result} : std::nullopt;
}

[[nodiscard]] std::string base64Encode(const std::uint8_t* bytes, const std::size_t size) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(((size + 2) / 3) * 4);
    for (std::size_t index = 0; index < size; index += 3) {
        const auto remaining = size - index;
        const auto first = bytes[index];
        const auto second = remaining > 1 ? bytes[index + 1] : 0;
        const auto third = remaining > 2 ? bytes[index + 2] : 0;
        result.push_back(alphabet[first >> 2]);
        result.push_back(alphabet[((first & 0x03) << 4) | (second >> 4)]);
        result.push_back(remaining > 1 ? alphabet[((second & 0x0f) << 2) | (third >> 6)] : '=');
        result.push_back(remaining > 2 ? alphabet[third & 0x3f] : '=');
    }
    return result;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> base64Decode(
    const std::string_view value
) {
    if (value.empty() || value.size() % 4 != 0) {
        return std::nullopt;
    }

    auto decodeCharacter = [](const char character) -> int {
        if (character >= 'A' && character <= 'Z') return character - 'A';
        if (character >= 'a' && character <= 'z') return character - 'a' + 26;
        if (character >= '0' && character <= '9') return character - '0' + 52;
        if (character == '+') return 62;
        if (character == '/') return 63;
        return -1;
    };

    std::size_t padding = 0;
    if (value.back() == '=') padding++;
    if (value.size() > 1 && value[value.size() - 2] == '=') padding++;
    if (padding > 2 || value.substr(0, value.size() - padding).find('=') != std::string_view::npos) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> result;
    result.reserve((value.size() / 4) * 3 - padding);
    for (std::size_t index = 0; index < value.size(); index += 4) {
        const bool finalBlock = index + 4 == value.size();
        const auto a = decodeCharacter(value[index]);
        const auto b = decodeCharacter(value[index + 1]);
        const auto c = value[index + 2] == '=' ? 0 : decodeCharacter(value[index + 2]);
        const auto d = value[index + 3] == '=' ? 0 : decodeCharacter(value[index + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            (!finalBlock && (value[index + 2] == '=' || value[index + 3] == '=')) ||
            (value[index + 2] == '=' && value[index + 3] != '=')) {
            return std::nullopt;
        }

        result.push_back(static_cast<std::uint8_t>((a << 2) | (b >> 4)));
        if (value[index + 2] != '=') {
            result.push_back(static_cast<std::uint8_t>((b << 4) | (c >> 2)));
        }
        if (value[index + 3] != '=') {
            result.push_back(static_cast<std::uint8_t>((c << 6) | d));
        }
    }
    return result;
}

[[nodiscard]] bool sha256(
    const std::uint8_t* input,
    const std::size_t inputSize,
    std::array<std::uint8_t, 32>& output
) {
    AlgorithmHandle algorithm;
    if (BCryptOpenAlgorithmProvider(
            &algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0
        ) < 0) {
        return false;
    }

    ULONG objectSize = 0;
    ULONG resultSize = 0;
    if (BCryptGetProperty(
            algorithm.value,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize),
            &resultSize,
            0
        ) < 0 || objectSize == 0) {
        return false;
    }

    std::vector<std::uint8_t> object(objectSize);
    HashHandle hash;
    if (BCryptCreateHash(
            algorithm.value,
            &hash.value,
            object.data(),
            objectSize,
            nullptr,
            0,
            0
        ) < 0 || BCryptHashData(
            hash.value,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(input)),
            static_cast<ULONG>(inputSize),
            0
        ) < 0 || BCryptFinishHash(
            hash.value,
            output.data(),
            static_cast<ULONG>(output.size()),
            0
        ) < 0) {
        return false;
    }
    return true;
}

[[nodiscard]] std::string fingerprint(const std::vector<std::uint8_t>& publicKey) {
    std::array<std::uint8_t, 32> digest{};
    if (!sha256(publicKey.data(), publicKey.size(), digest)) {
        return {};
    }

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto value : digest) {
        output << std::setw(2) << static_cast<unsigned int>(value);
    }
    return output.str();
}

[[nodiscard]] std::optional<std::string> requiredString(
    const JsonObject& object,
    const wchar_t* name
) {
    if (!object.HasKey(name)) {
        return std::nullopt;
    }
    return winrt::to_string(object.GetNamedString(name));
}

[[nodiscard]] std::optional<std::int64_t> requiredInteger(
    const JsonObject& object,
    const wchar_t* name
) {
    if (!object.HasKey(name)) {
        return std::nullopt;
    }
    const auto value = object.GetNamedNumber(name);
    if (!std::isfinite(value) || std::floor(value) != value ||
        value < static_cast<double>(std::numeric_limits<std::int64_t>::min()) ||
        value > static_cast<double>(std::numeric_limits<std::int64_t>::max())) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(value);
}

} // namespace

UnlockServiceCore::UnlockServiceCore(
    std::string audience,
    const std::int64_t challengeLifetimeMilliseconds
)
    : audience_(std::move(audience)),
      challengeLifetimeMilliseconds_(challengeLifetimeMilliseconds) {
    if (audience_.empty() || audience_.size() > 64 || challengeLifetimeMilliseconds_ <= 0) {
        throw std::invalid_argument("invalid UnlockServiceCore configuration");
    }
}

IssuedChallenge UnlockServiceCore::issueChallenge(const std::int64_t issuedAtMilliseconds) {
    std::lock_guard lock(mutex_);

    protocol::FixedChallenge challenge;
    challenge.version = 1;
    challenge.issuedAtMilliseconds = issuedAtMilliseconds;
    challenge.audience = audience_;

    if (BCryptGenRandom(
            nullptr,
            challenge.requestId.data(),
            static_cast<ULONG>(challenge.requestId.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        ) < 0 || BCryptGenRandom(
            nullptr,
            challenge.nonce.data(),
            static_cast<ULONG>(challenge.nonce.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        ) < 0) {
        throw std::runtime_error("BCryptGenRandom failed while issuing challenge");
    }

    outstandingChallenge_ = challenge;
    outstandingChallengeConsumed_ = false;
    return IssuedChallenge{challenge, serializeChallenge(challenge)};
}

void UnlockServiceCore::setEnrolledPublicKey(std::vector<std::uint8_t> rawPublicKey) {
    if (rawPublicKey.size() != kRawPublicKeySize || rawPublicKey.front() != 0x04) {
        throw std::invalid_argument("enrolled public key must be a raw P-256 key");
    }
    std::lock_guard lock(mutex_);
    enrolledPublicKey_ = std::move(rawPublicKey);
}

std::string UnlockServiceCore::requestIdString(const protocol::FixedChallenge& challenge) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(36);
    for (std::size_t index = 0; index < challenge.requestId.size(); index++) {
        if (index == 4 || index == 6 || index == 8 || index == 10) {
            result.push_back('-');
        }
        result.push_back(hex[challenge.requestId[index] >> 4]);
        result.push_back(hex[challenge.requestId[index] & 0x0f]);
    }
    return result;
}

std::string UnlockServiceCore::serializeChallenge(const protocol::FixedChallenge& challenge) {
    std::ostringstream output;
    output << "{\"audience\":\"" << escapeJsonString(challenge.audience)
           << "\",\"issuedAtMilliseconds\":" << challenge.issuedAtMilliseconds
           << ",\"nonce\":\""
           << base64Encode(challenge.nonce.data(), challenge.nonce.size())
           << "\",\"requestID\":\"" << requestIdString(challenge)
           << "\",\"version\":" << challenge.version << "}";
    return output.str();
}

AssertionResult UnlockServiceCore::verifyAssertion(
    const std::string_view assertionJson,
    const std::int64_t nowMilliseconds
) {
    std::lock_guard lock(mutex_);

    if (assertionJson.empty() || assertionJson.size() > 4096) {
        return {AssertionCode::malformed_json};
    }
    if (!outstandingChallenge_) {
        return {AssertionCode::request_mismatch};
    }
    if (outstandingChallengeConsumed_) {
        return {AssertionCode::challenge_replayed};
    }
    if (nowMilliseconds < outstandingChallenge_->issuedAtMilliseconds ||
        nowMilliseconds - outstandingChallenge_->issuedAtMilliseconds > challengeLifetimeMilliseconds_) {
        return {AssertionCode::challenge_expired};
    }

    JsonObject assertion;
    try {
        assertion = JsonObject::Parse(winrt::to_hstring(std::string(assertionJson)));
    } catch (...) {
        return {AssertionCode::malformed_json};
    }

    try {
        const auto version = requiredInteger(assertion, L"version");
        if (!version) return {AssertionCode::malformed_json};
        if (*version != 1) return {AssertionCode::unsupported_version};

        const auto requestId = requiredString(assertion, L"requestID");
        if (!requestId) return {AssertionCode::malformed_json};
        const auto requestIdBytes = parseRequestId(*requestId);
        if (!requestIdBytes) return {AssertionCode::invalid_request_id};
        if (*requestIdBytes != outstandingChallenge_->requestId) {
            return {AssertionCode::request_mismatch};
        }

        const auto keyId = requiredString(assertion, L"keyID");
        const auto publicKeyEncoded = requiredString(assertion, L"publicKeyRawRepresentation");
        const auto signatureEncoded = requiredString(assertion, L"signatureRawRepresentation");
        if (!keyId || !publicKeyEncoded || !signatureEncoded) {
            return {AssertionCode::malformed_json};
        }
        if (keyId->size() != 64 || !std::all_of(keyId->begin(), keyId->end(), isHex)) {
            return {AssertionCode::invalid_key_id};
        }

        const auto publicKey = base64Decode(*publicKeyEncoded);
        const auto signature = base64Decode(*signatureEncoded);
        if (!publicKey || publicKey->size() != kRawPublicKeySize || publicKey->front() != 0x04) {
            return {AssertionCode::invalid_public_key};
        }
        if (!signature || signature->size() != kRawSignatureSize) {
            return {AssertionCode::invalid_signature_encoding};
        }

        const auto expectedKeyId = fingerprint(*publicKey);
        if (expectedKeyId.empty()) {
            return {AssertionCode::cryptographic_api_failure};
        }
        if (lowerAscii(*keyId) != expectedKeyId) {
            return {AssertionCode::key_id_mismatch};
        }
        if (!enrolledPublicKey_ || *enrolledPublicKey_ != *publicKey) {
            return {AssertionCode::key_not_enrolled};
        }

        const auto payload = protocol::buildSigningPayload(*outstandingChallenge_);
        if (!payload.succeeded()) {
            return {AssertionCode::cryptographic_api_failure};
        }
        const auto verification = protocol::verifyP256Signature(
            publicKey->data(),
            publicKey->size(),
            payload.bytes.data(),
            payload.bytes.size(),
            signature->data(),
            signature->size()
        );
        if (verification.code == protocol::VerificationCode::cryptographic_api_failure) {
            return {AssertionCode::cryptographic_api_failure};
        }
        if (!verification.isValid()) {
            return {AssertionCode::invalid_signature};
        }

        outstandingChallengeConsumed_ = true;
        return {AssertionCode::authenticated};
    } catch (...) {
        return {AssertionCode::malformed_json};
    }
}

const char* assertionCodeName(const AssertionCode code) noexcept {
    switch (code) {
        case AssertionCode::authenticated: return "authenticated";
        case AssertionCode::malformed_json: return "malformed_json";
        case AssertionCode::unsupported_version: return "unsupported_version";
        case AssertionCode::invalid_request_id: return "invalid_request_id";
        case AssertionCode::request_mismatch: return "request_mismatch";
        case AssertionCode::challenge_expired: return "challenge_expired";
        case AssertionCode::challenge_replayed: return "challenge_replayed";
        case AssertionCode::key_not_enrolled: return "key_not_enrolled";
        case AssertionCode::invalid_key_id: return "invalid_key_id";
        case AssertionCode::invalid_public_key: return "invalid_public_key";
        case AssertionCode::key_id_mismatch: return "key_id_mismatch";
        case AssertionCode::invalid_signature_encoding: return "invalid_signature_encoding";
        case AssertionCode::invalid_signature: return "invalid_signature";
        case AssertionCode::cryptographic_api_failure: return "cryptographic_api_failure";
    }
    return "unknown";
}

} // namespace unlock_windows::service
