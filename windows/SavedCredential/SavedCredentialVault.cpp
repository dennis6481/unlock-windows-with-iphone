// Created by Rui MA on 30 Sep 2026

#include "SavedCredentialVault.h"

#include <bcrypt.h>
#include <dpapi.h>
#include <sddl.h>
#include <Aclapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace unlock_windows::saved_credential {
namespace {

constexpr std::uint32_t kDiskMagic = 0x31564347;
constexpr std::uint32_t kPlainMagic = 0x31504347;
constexpr std::size_t kMaxFileBytes = 32 * 1024;
constexpr std::size_t kMaxPasswordChars = 1024;

#pragma pack(push, 1)
struct DiskHeader final {
    std::uint32_t magic;
    std::uint32_t blobBytes;
};
struct PlainHeader final {
    std::uint32_t magic;
    std::uint32_t identityBytes;
    std::uint32_t passwordBytes;
};
#pragma pack(pop)

void fail(const char* message) { throw std::runtime_error(message); }

void requireSystemContext() {
    HANDLE threadToken = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadToken)) {
        CloseHandle(threadToken);
        fail("saved credential DPAPI operation refused while impersonating a client");
    }
    if (GetLastError() != ERROR_NO_TOKEN) fail("saved credential thread token check failed");
    HANDLE processToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken)) fail("saved credential process token unavailable");
    DWORD length = 0;
    GetTokenInformation(processToken, TokenUser, nullptr, 0, &length);
    std::vector<std::uint8_t> buffer(length);
    const bool read = length >= sizeof(TOKEN_USER) &&
        GetTokenInformation(processToken, TokenUser, buffer.data(), length, &length);
    CloseHandle(processToken);
    PSID systemSid = nullptr;
    const bool parsed = ConvertStringSidToSidW(L"S-1-5-18", &systemSid);
    const bool isSystem = read && parsed &&
        EqualSid(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, systemSid);
    if (systemSid != nullptr) LocalFree(systemSid);
    if (!isSystem) fail("saved credential vault requires LocalSystem");
}

struct SecurityDescriptor final {
    PSECURITY_DESCRIPTOR value = nullptr;
    SecurityDescriptor() {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;FA;;;SY)", SDDL_REVISION_1, &value, nullptr)) {
            fail("saved credential SYSTEM-only security descriptor failed");
        }
    }
    ~SecurityDescriptor() { if (value != nullptr) LocalFree(value); }
    SECURITY_ATTRIBUTES attributes() const {
        SECURITY_ATTRIBUTES result{};
        result.nLength = sizeof(result);
        result.lpSecurityDescriptor = value;
        return result;
    }
};

void assertSystemOnly(const std::filesystem::path& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    const auto status = GetNamedSecurityInfoW(
        path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &dacl, nullptr, &descriptor
    );
    if (status != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr) {
        if (descriptor != nullptr) LocalFree(descriptor);
        fail("saved credential could not inspect vault ACL");
    }
    BOOL defaulted = FALSE;
    BOOL present = FALSE;
    PACL checked = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    const bool valid = GetSecurityDescriptorDacl(descriptor, &present, &checked, &defaulted) &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) != 0 &&
        present && checked == dacl && dacl->AceCount == 1;
    PSID systemSid = nullptr;
    const bool parsed = ConvertStringSidToSidW(L"S-1-5-18", &systemSid);
    void* aceValue = nullptr;
    bool onlySystem = false;
    if (valid && parsed && GetAce(dacl, 0, &aceValue)) {
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(aceValue);
        const auto* sid = reinterpret_cast<const SID*>(&ace->SidStart);
        onlySystem = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            ace->Header.AceFlags == 0 && ace->Mask == FILE_ALL_ACCESS &&
            EqualSid(const_cast<SID*>(sid), systemSid);
    }
    if (systemSid != nullptr) LocalFree(systemSid);
    LocalFree(descriptor);
    if (!onlySystem) fail("saved credential vault ACL is not SYSTEM-only");
}

void assertNotReparse(const std::filesystem::path& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        fail("saved credential vault path is unavailable or reparse point");
    }
}

std::filesystem::path programData() {
    const DWORD size = GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (size < 2 || size > 32768) fail("ProgramData path unavailable");
    std::wstring value(size, L'\0');
    if (GetEnvironmentVariableW(L"ProgramData", value.data(), size) != size - 1) {
        fail("ProgramData path changed");
    }
    value.resize(size - 1);
    return value;
}

void append(SensitiveBytes& target, const void* input, const std::size_t bytes) {
    const auto* begin = static_cast<const std::uint8_t*>(input);
    target.value.insert(target.value.end(), begin, begin + bytes);
}

SensitiveBytes readFile(const std::filesystem::path& file) {
    assertNotReparse(file);
    assertSystemOnly(file);
    const HANDLE handle = CreateFileW(file.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) fail("saved credential vault file open failed");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size) || size.QuadPart < sizeof(DiskHeader) ||
        size.QuadPart > kMaxFileBytes) {
        CloseHandle(handle);
        fail("saved credential vault file size invalid");
    }
    SensitiveBytes contents;
    contents.value.resize(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const bool okay = ReadFile(handle, contents.value.data(), static_cast<DWORD>(contents.value.size()), &read, nullptr) &&
        read == contents.value.size();
    CloseHandle(handle);
    if (!okay) fail("saved credential vault file read failed");
    return contents;
}

struct ParsedDisk final {
    const std::uint8_t* blob = nullptr;
    std::size_t blobBytes = 0;
};

ParsedDisk parseDisk(const SensitiveBytes& contents) {
    DiskHeader header{};
    std::memcpy(&header, contents.value.data(), sizeof(header));
    if (header.magic != kDiskMagic || header.blobBytes == 0 ||
        header.blobBytes != contents.value.size() - sizeof(header)) {
        fail("saved credential vault format invalid");
    }
    ParsedDisk parsed;
    parsed.blob = contents.value.data() + sizeof(header);
    parsed.blobBytes = header.blobBytes;
    return parsed;
}

struct DecryptedRecord final {
    Identity identity;
    SensitiveBytes password;
};

DecryptedRecord decryptRecord(const ParsedDisk& disk, const bool includePassword) {
    DATA_BLOB input{static_cast<DWORD>(disk.blobBytes), const_cast<BYTE*>(disk.blob)};
    DATA_BLOB plainBlob{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &plainBlob)) {
        fail("saved credential LocalSystem DPAPI unprotect failed");
    }
    DecryptedRecord result;
    try {
        if (plainBlob.cbData < sizeof(PlainHeader)) fail("saved credential protected record truncated");
        PlainHeader header{};
        std::memcpy(&header, plainBlob.pbData, sizeof(header));
        if (header.magic != kPlainMagic || header.identityBytes == 0 ||
            header.passwordBytes == 0 ||
            header.passwordBytes > kMaxPasswordChars * sizeof(wchar_t) ||
            header.passwordBytes % sizeof(wchar_t) != 0 ||
            static_cast<std::size_t>(header.identityBytes) + header.passwordBytes !=
                plainBlob.cbData - sizeof(header)) fail("saved credential protected record invalid");
        if (!decodeIdentity(plainBlob.pbData + sizeof(header), header.identityBytes,
                result.identity)) fail("saved credential protected identity invalid");
        const auto* password = plainBlob.pbData + sizeof(header) + header.identityBytes;
        for (std::size_t index = 0; index < header.passwordBytes; index += sizeof(wchar_t)) {
            wchar_t character = 0;
            std::memcpy(&character, password + index, sizeof(character));
            if (character == L'\0') fail("saved credential protected password contains NUL");
        }
        if (includePassword) {
            result.password.value.assign(password, password + header.passwordBytes);
        }
    } catch (...) {
        SecureZeroMemory(plainBlob.pbData, plainBlob.cbData);
        LocalFree(plainBlob.pbData);
        throw;
    }
    SecureZeroMemory(plainBlob.pbData, plainBlob.cbData);
    LocalFree(plainBlob.pbData);
    return result;
}

bool fileExists(const std::filesystem::path& file) {
    const DWORD attributes = GetFileAttributesW(file.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) return false;
        fail("saved credential vault file state unreadable");
    }
    if ((attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        fail("saved credential vault file path is unsafe");
    }
    return true;
}

} // namespace

bool sameIdentity(const Identity& left, const Identity& right) noexcept {
    return left.sid == right.sid && left.qualifiedUserName == right.qualifiedUserName &&
        IsEqualGUID(left.providerId, right.providerId);
}

Vault::Vault() {
    requireSystemContext();
    directory_ = programData() / L"UnlockWindowsSavedCredential";
    file_ = directory_ / L"saved-credential.dat";
    SecurityDescriptor security;
    auto attributes = security.attributes();
    if (!CreateDirectoryW(directory_.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fail("saved credential vault directory creation failed");
    }
    assertNotReparse(directory_);
    assertSystemOnly(directory_);
}

std::optional<Identity> Vault::storedIdentity() const {
    requireSystemContext();
    if (!fileExists(file_)) return std::nullopt;
    const auto contents = readFile(file_);
    return decryptRecord(parseDisk(contents), false).identity;
}

void Vault::save(const Identity& identity, const std::uint8_t* password,
                 const std::size_t passwordBytes, const bool replace) {
    requireSystemContext();
    if (password == nullptr || passwordBytes == 0 || passwordBytes % sizeof(wchar_t) != 0 ||
        passwordBytes > kMaxPasswordChars * sizeof(wchar_t) || fileExists(file_) != replace) {
        fail("saved credential set/update precondition failed");
    }
    for (std::size_t index = 0; index < passwordBytes; index += sizeof(wchar_t)) {
        wchar_t character = 0;
        std::memcpy(&character, password + index, sizeof(character));
        if (character == L'\0') fail("saved credential password contains NUL");
    }
    SensitiveBytes identityBytes;
    if (!encodeIdentity(identity, identityBytes)) fail("saved credential identity invalid");
    SensitiveBytes plain;
    const PlainHeader plainHeader{kPlainMagic, static_cast<std::uint32_t>(identityBytes.value.size()),
        static_cast<std::uint32_t>(passwordBytes)};
    append(plain, &plainHeader, sizeof(plainHeader));
    append(plain, identityBytes.value.data(), identityBytes.value.size());
    append(plain, password, passwordBytes);
    DATA_BLOB input{static_cast<DWORD>(plain.value.size()), plain.value.data()};
    DATA_BLOB protectedBlob{};
    if (!CryptProtectData(&input, L"Unlock Windows saved credential VM credential", nullptr, nullptr,
            nullptr, CRYPTPROTECT_UI_FORBIDDEN, &protectedBlob)) {
        fail("saved credential LocalSystem DPAPI protect failed");
    }
    SensitiveBytes disk;
    const DiskHeader diskHeader{kDiskMagic, protectedBlob.cbData};
    try {
        append(disk, &diskHeader, sizeof(diskHeader));
        append(disk, protectedBlob.pbData, protectedBlob.cbData);
    } catch (...) {
        LocalFree(protectedBlob.pbData);
        throw;
    }
    LocalFree(protectedBlob.pbData);
    if (disk.value.size() > kMaxFileBytes) fail("saved credential vault output too large");

    std::array<std::uint8_t, 16> nonce{};
    if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) fail("saved credential temporary file name RNG failed");
    wchar_t suffix[33]{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        constexpr wchar_t hex[] = L"0123456789abcdef";
        suffix[i * 2] = hex[nonce[i] >> 4];
        suffix[i * 2 + 1] = hex[nonce[i] & 0x0f];
    }
    const auto temporary = directory_ / (std::wstring(L"temporary-") + suffix + L".dat");
    SecurityDescriptor security;
    auto attributes = security.attributes();
    const HANDLE handle = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, &attributes,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) fail("saved credential temporary vault file creation failed");
    DWORD written = 0;
    const bool okay = WriteFile(handle, disk.value.data(), static_cast<DWORD>(disk.value.size()),
        &written, nullptr) && written == disk.value.size() && FlushFileBuffers(handle);
    const bool closed = CloseHandle(handle) != 0;
    if (!okay || !closed || !MoveFileExW(temporary.c_str(), file_.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        if (!DeleteFileW(temporary.c_str())) {
            fail("saved credential vault replacement and temporary ciphertext cleanup both failed");
        }
        fail("saved credential atomic vault replacement failed");
    }
    assertSystemOnly(file_);
}

SensitiveBytes Vault::release(const Identity& expected) const {
    requireSystemContext();
    if (!fileExists(file_)) fail("saved credential saved credential missing");
    const auto contents = readFile(file_);
    auto record = decryptRecord(parseDisk(contents), true);
    if (!sameIdentity(expected, record.identity)) fail("saved credential saved identity changed");
    return std::move(record.password);
}

void Vault::clear() {
    requireSystemContext();
    assertNotReparse(directory_);
    assertSystemOnly(directory_);
    if (fileExists(file_)) {
        assertSystemOnly(file_);
        if (!DeleteFileW(file_.c_str())) fail("saved credential saved credential deletion failed");
    }
    for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
        const auto name = entry.path().filename().wstring();
        bool temporary = name.size() == 46 && name.compare(0, 10, L"temporary-") == 0 &&
            name.compare(42, 4, L".dat") == 0;
        for (std::size_t index = 10; temporary && index < 42; ++index) {
            const auto character = name[index];
            temporary = (character >= L'0' && character <= L'9') ||
                (character >= L'a' && character <= L'f');
        }
        if (!temporary) fail("saved credential vault contains an unknown file; cleanup not confirmed");
        assertNotReparse(entry.path());
        assertSystemOnly(entry.path());
        if (!DeleteFileW(entry.path().c_str())) {
            fail("saved credential temporary ciphertext deletion failed");
        }
    }
    if (fileExists(file_)) fail("saved credential saved credential deletion unconfirmed");
}

} // namespace unlock_windows::saved_credential
