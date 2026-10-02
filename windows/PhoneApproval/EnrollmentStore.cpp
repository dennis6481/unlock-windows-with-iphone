// Created by Rui MA on 26 Sep 2026

#include "EnrollmentStore.h"

#include <Windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wincrypt.h>

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace unlock_windows::phone_approval {
namespace {

constexpr std::uint32_t kFileMagic = 0x324B4E45; // "ENK2" in little-endian memory
constexpr std::uint16_t kFileVersion = 1;
constexpr std::size_t kRawPublicKeySize = 65;
constexpr std::uint32_t kRecordMagic = 0x31434E45; // "ENC1" in little-endian memory
constexpr std::uint16_t kRecordVersion = 1;
constexpr std::size_t kMaxAccountSidBytes = 1024;

#pragma pack(push, 1)
struct FileHeader final {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t encryptedSize;
};

struct RecordHeader final {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t publicKeySize;
    std::uint16_t accountSidBytes;
};
#pragma pack(pop)

static_assert(sizeof(FileHeader) == 8);
static_assert(sizeof(RecordHeader) == 10);

[[nodiscard]] std::string win32Error(const char* operation) {
    const DWORD error = GetLastError();
    char message[256]{};
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        message,
        static_cast<DWORD>(sizeof(message)),
        nullptr
    );
    std::string result(operation);
    result += " failed (";
    result += std::to_string(error);
    result += ")";
    if (length != 0) {
        result += ": ";
        result.append(message, length);
    }
    return result;
}

void requireWin32(const BOOL result, const char* operation) {
    if (result == FALSE) {
        throw std::runtime_error(win32Error(operation));
    }
}

void requireNtStatus(const NTSTATUS status, const char* operation) {
    if (status < 0) {
        throw std::runtime_error(std::string(operation) + " failed: NTSTATUS=" +
            std::to_string(static_cast<std::uint32_t>(status)));
    }
}

void validateEnrollmentKey(const std::vector<std::uint8_t>& rawPublicKey) {
    if (rawPublicKey.size() != kRawPublicKeySize || rawPublicKey.front() != 0x04) {
        throw std::invalid_argument(
            "enrollment key must be a 65-byte uncompressed P-256 X9.63 public key"
        );
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    requireNtStatus(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0),
        "BCryptOpenAlgorithmProvider(P-256)");
    BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
    std::array<std::uint8_t, sizeof(header) + 64> blob{};
    std::memcpy(blob.data(), &header, sizeof(header));
    std::memcpy(blob.data() + sizeof(header), rawPublicKey.data() + 1, 64);
    BCRYPT_KEY_HANDLE key = nullptr;
    const NTSTATUS status = BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key,
        blob.data(), static_cast<ULONG>(blob.size()), 0);
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    requireNtStatus(status, "BCryptImportKeyPair(P-256 public key)");
}

void ensureParentDirectory(const std::wstring& path) {
    const auto separator = path.find_last_of(L'\\');
    if (separator == std::wstring::npos) {
        throw std::invalid_argument("enrollment path must include a parent directory");
    }

    const std::wstring directory = path.substr(0, separator);
    if (CreateDirectoryW(directory.c_str(), nullptr) == FALSE &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        throw std::runtime_error(win32Error("CreateDirectoryW"));
    }
}

std::wstring currentProcessUserSid() {
    HANDLE token = nullptr;
    requireWin32(
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token),
        "OpenProcessToken"
    );

    DWORD requiredSize = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &requiredSize);
    if (requiredSize == 0) {
        CloseHandle(token);
        throw std::runtime_error(win32Error("GetTokenInformation(size)"));
    }

    std::vector<std::uint8_t> buffer(requiredSize);
    requireWin32(
        GetTokenInformation(
            token,
            TokenUser,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &requiredSize
        ),
        "GetTokenInformation"
    );
    CloseHandle(token);

    const auto tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR sidText = nullptr;
    requireWin32(ConvertSidToStringSidW(tokenUser->User.Sid, &sidText), "ConvertSidToStringSidW");
    std::wstring result(sidText);
    LocalFree(sidText);
    return result;
}

SECURITY_ATTRIBUTES protectedFileAttributes(PSECURITY_DESCRIPTOR& descriptor) {
    // SYSTEM, Administrators and the current interactive user may access the
    // file. The DPAPI blob is machine-bound so the Session 0 service can
    // decrypt it. The user SID must be explicit; OW means Owner Rights and
    // does not reliably grant the creating process read access.
    const std::wstring sddl =
        L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + currentProcessUserSid() + L")";
    requireWin32(
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(),
            SDDL_REVISION_1,
            &descriptor,
            nullptr
        ),
        "ConvertStringSecurityDescriptorToSecurityDescriptorW"
    );

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    return attributes;
}

std::vector<std::uint8_t> protect(
    const std::vector<std::uint8_t>& plaintext
) {
    DATA_BLOB input{
        static_cast<DWORD>(plaintext.size()),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(plaintext.data()))
    };
    DATA_BLOB output{};
    constexpr wchar_t description[] = L"Unlock Windows with iPhone enrollment key v1";

    requireWin32(
        CryptProtectData(
            &input,
            description,
            nullptr,
            nullptr,
            nullptr,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &output
        ),
        "CryptProtectData"
    );

    std::vector<std::uint8_t> result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
}

std::vector<std::uint8_t> unprotect(
    const std::uint8_t* encrypted,
    const std::size_t encryptedSize
) {
    DATA_BLOB input{
        static_cast<DWORD>(encryptedSize),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(encrypted))
    };
    DATA_BLOB output{};
    requireWin32(
        CryptUnprotectData(
            &input,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            CRYPTPROTECT_UI_FORBIDDEN,
            &output
        ),
        "CryptUnprotectData"
    );

    std::vector<std::uint8_t> result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
}

std::vector<std::uint8_t> serializeRecord(const EnrollmentRecord& record) {
    validateEnrollmentKey(record.publicKey);
    if (record.accountSid.empty() ||
        record.accountSid.size() * sizeof(wchar_t) > kMaxAccountSidBytes ||
        record.accountSid.size() * sizeof(wchar_t) > UINT16_MAX) {
        throw std::invalid_argument("enrollment account SID has an invalid size");
    }

    PSID parsedSid = nullptr;
    requireWin32(
        ConvertStringSidToSidW(record.accountSid.c_str(), &parsedSid),
        "ConvertStringSidToSidW"
    );
    LocalFree(parsedSid);

    const auto sidBytes = record.accountSid.size() * sizeof(wchar_t);
    RecordHeader header{
        kRecordMagic,
        kRecordVersion,
        static_cast<std::uint16_t>(record.publicKey.size()),
        static_cast<std::uint16_t>(sidBytes)
    };
    std::vector<std::uint8_t> result(sizeof(header) + record.publicKey.size() + sidBytes);
    std::memcpy(result.data(), &header, sizeof(header));
    std::memcpy(
        result.data() + sizeof(header),
        record.publicKey.data(),
        record.publicKey.size()
    );
    std::memcpy(
        result.data() + sizeof(header) + record.publicKey.size(),
        record.accountSid.data(),
        sidBytes
    );
    return result;
}

EnrollmentRecord parseRecord(const std::vector<std::uint8_t>& plaintext) {
    if (plaintext.size() < sizeof(RecordHeader)) {
        throw std::runtime_error("enrollment record is too small");
    }

    RecordHeader header{};
    std::memcpy(&header, plaintext.data(), sizeof(header));
    if (header.magic != kRecordMagic || header.version != kRecordVersion ||
        header.publicKeySize != kRawPublicKeySize ||
        header.accountSidBytes == 0 || header.accountSidBytes > kMaxAccountSidBytes ||
        header.accountSidBytes % sizeof(wchar_t) != 0 ||
        plaintext.size() != sizeof(header) + header.publicKeySize + header.accountSidBytes) {
        throw std::runtime_error("enrollment record header is invalid");
    }

    EnrollmentRecord result;
    result.publicKey.assign(
        plaintext.begin() + sizeof(header),
        plaintext.begin() + sizeof(header) + header.publicKeySize
    );
    validateEnrollmentKey(result.publicKey);
    result.accountSid.resize(header.accountSidBytes / sizeof(wchar_t));
    std::memcpy(
        result.accountSid.data(),
        plaintext.data() + sizeof(header) + header.publicKeySize,
        header.accountSidBytes
    );

    PSID parsedSid = nullptr;
    requireWin32(
        ConvertStringSidToSidW(result.accountSid.c_str(), &parsedSid),
        "ConvertStringSidToSidW"
    );
    LocalFree(parsedSid);
    return result;
}

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    requireNtStatus(
        BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0
        ),
        "BCryptOpenAlgorithmProvider"
    );

    ULONG objectSize = 0;
    ULONG resultSize = 0;
    NTSTATUS status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectSize),
        sizeof(objectSize),
        &resultSize,
        0
    );
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        requireNtStatus(status, "BCryptGetProperty");
    }

    std::vector<std::uint8_t> object(objectSize);
    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(
        algorithm,
        &hash,
        object.data(),
        objectSize,
        nullptr,
        0,
        0
    );
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        requireNtStatus(status, "BCryptCreateHash");
    }

    status = BCryptHashData(
        hash,
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(bytes.data())),
        static_cast<ULONG>(bytes.size()),
        0
    );
    if (status < 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        requireNtStatus(status, "BCryptHashData");
    }

    std::array<std::uint8_t, 32> digest{};
    status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    requireNtStatus(status, "BCryptFinishHash");
    return digest;
}

} // namespace

std::wstring EnrollmentStore::defaultPath() {
    std::wstring programData(32'768, L'\0');
    const DWORD length = GetEnvironmentVariableW(
        L"ProgramData",
        programData.data(),
        static_cast<DWORD>(programData.size())
    );
    if (length == 0 || length >= programData.size()) {
        throw std::runtime_error(win32Error("GetEnvironmentVariableW(ProgramData)"));
    }
    programData.resize(length);
    return programData + L"\\UnlockWindowsWithIPhone\\enrollment.dat";
}

EnrollmentStore::EnrollmentStore(std::wstring path) : path_(std::move(path)) {
    if (path_.empty()) {
        throw std::invalid_argument("enrollment path must not be empty");
    }
}

std::wstring EnrollmentStore::currentUserSid() {
    return currentProcessUserSid();
}

std::optional<EnrollmentRecord> EnrollmentStore::load() const {
    const HANDLE file = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND) {
            return std::nullopt;
        }
        throw std::runtime_error(win32Error("CreateFileW(enrollment read)"));
    }

    LARGE_INTEGER size{};
    requireWin32(GetFileSizeEx(file, &size), "GetFileSizeEx");
    if (size.QuadPart < static_cast<LONGLONG>(sizeof(FileHeader)) || size.QuadPart > 64 * 1024) {
        CloseHandle(file);
        throw std::runtime_error("enrollment file has an invalid size");
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const bool readOk = ReadFile(
        file,
        bytes.data(),
        static_cast<DWORD>(bytes.size()),
        &read,
        nullptr
    ) != FALSE;
    CloseHandle(file);
    requireWin32(readOk && read == bytes.size(), "ReadFile(enrollment)");

    FileHeader header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.magic != kFileMagic || header.version != kFileVersion ||
        header.encryptedSize == 0 ||
        bytes.size() != sizeof(header) + header.encryptedSize) {
        throw std::runtime_error("enrollment file header is invalid");
    }

    return parseRecord(unprotect(bytes.data() + sizeof(header), header.encryptedSize));
}

void EnrollmentStore::save(const EnrollmentRecord& record, const std::function<void()>& beforeCommit) const {
    ensureParentDirectory(path_);
    const auto encrypted = protect(serializeRecord(record));
    if (encrypted.empty() || encrypted.size() > UINT16_MAX) {
        throw std::runtime_error("protected enrollment key has an invalid size");
    }

    FileHeader header{
        kFileMagic,
        kFileVersion,
        static_cast<std::uint16_t>(encrypted.size())
    };
    std::array<std::uint8_t, 16> nonce{};
    requireNtStatus(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG), "BCryptGenRandom(enrollment temporary file)");
    std::wstring temporary = path_ + L".pending-";
    constexpr wchar_t alphabet[] = L"0123456789abcdef";
    for (const auto value : nonce) {
        temporary += alphabet[value >> 4];
        temporary += alphabet[value & 15];
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto attributes = protectedFileAttributes(descriptor);
    const HANDLE file = CreateFileW(
        temporary.c_str(),
        GENERIC_WRITE,
        0,
        &attributes,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    const DWORD creationError = GetLastError();
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) {
        SetLastError(creationError);
        throw std::runtime_error(win32Error("CreateFileW(enrollment write)"));
    }

    bool open = true;
    try {
        DWORD written = 0;
        requireWin32(WriteFile(file, &header, sizeof(header), &written, nullptr), "WriteFile(enrollment header)");
        if (written != sizeof(header)) throw std::runtime_error("Incomplete enrollment header write");
        requireWin32(WriteFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &written, nullptr),
            "WriteFile(enrollment body)");
        if (written != encrypted.size()) throw std::runtime_error("Incomplete enrollment body write");
        requireWin32(FlushFileBuffers(file), "FlushFileBuffers(enrollment)");
        requireWin32(CloseHandle(file), "CloseHandle(enrollment temporary file)");
        open = false;
        if (beforeCommit) beforeCommit();
        requireWin32(MoveFileExW(temporary.c_str(), path_.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH), "MoveFileExW(enrollment commit)");
    } catch (const std::exception& error) {
        std::string message = error.what();
        if (open && !CloseHandle(file)) message += "; " + win32Error("CloseHandle(enrollment temporary file)");
        if (!DeleteFileW(temporary.c_str())) message += "; " + win32Error("DeleteFileW(enrollment temporary file)");
        if (message != error.what()) throw std::runtime_error(message);
        throw;
    }
}

void EnrollmentStore::remove() const {
    if (DeleteFileW(path_.c_str()) == FALSE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return;
        }
        throw std::runtime_error(win32Error("DeleteFile(enrollment)"));
    }
}

std::string EnrollmentStore::fingerprint(
    const std::vector<std::uint8_t>& rawPublicKey
) {
    validateEnrollmentKey(rawPublicKey);
    const auto digest = sha256(rawPublicKey);
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (const auto value : digest) {
        result.push_back(alphabet[value >> 4]);
        result.push_back(alphabet[value & 0x0f]);
    }
    return result;
}

void EnrollmentStore::validatePublicKey(const std::vector<std::uint8_t>& rawPublicKey) {
    validateEnrollmentKey(rawPublicKey);
}

} // namespace unlock_windows::phone_approval
