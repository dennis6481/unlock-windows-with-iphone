// Created by Rui MA on 26 Sep 2026

#include "EnrollmentStore.h"
#include "../SavedCredential/SavedCredentialIpc.h"
#include "../ProtectedStorage.h"

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

namespace unlock_windows::system_ble {
namespace {

constexpr std::uint32_t kFileMagic = 0x324B4E45; // "ENK2" in little-endian memory
constexpr std::uint16_t kFileVersion = 2;
#pragma pack(push, 1)
struct FileHeader final {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t encryptedSize;
};

#pragma pack(pop)

static_assert(sizeof(FileHeader) == 8);

struct WriterLock final {
    HANDLE value = nullptr;
    WriterLock() {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        requireSecurity(descriptor);
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        value = CreateMutexW(&attributes, FALSE, kEnrollmentWriterMutex);
        const auto error = GetLastError(); LocalFree(descriptor);
        if (!value) { SetLastError(error); winrt::throw_last_error(); }
        const auto result = WaitForSingleObject(value, 0);
        if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) {
            CloseHandle(value); value = nullptr;
            throw std::runtime_error("Binding writer is busy");
        }
    }
    static void requireSecurity(PSECURITY_DESCRIPTOR& descriptor) {
        winrt::check_bool(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr));
    }
    ~WriterLock() { if (value) { ReleaseMutex(value); CloseHandle(value); } }
};


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

void ensureParentDirectory(const std::wstring& path) {
    const auto separator = path.find_last_of(L'\\');
    if (separator == std::wstring::npos) {
        throw std::invalid_argument("enrollment path must include a parent directory");
    }

    const std::wstring directory = path.substr(0, separator);
    storage::ensureProtectedDirectory(directory, true);
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
    const std::wstring sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";
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
    constexpr wchar_t description[] = L"Unlock Windows with iPhone system binding v2";

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

std::vector<std::uint8_t> serializeRecord(const BindingRecord& record) {
    saved_credential::SensitiveBytes bytes;
    if (!saved_credential::encodeBinding(record, bytes)) throw std::invalid_argument("Invalid system binding");
    return std::move(bytes.value);
}

BindingRecord parseRecord(const std::vector<std::uint8_t>& plaintext) {
    BindingRecord record;
    if (!saved_credential::decodeBinding(plaintext.data(), plaintext.size(), record))
        throw std::runtime_error("Invalid system binding record");
    return record;
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
    return programData + L"\\" + kEnrollmentDataDirectoryName + L"\\" + kEnrollmentFileName;
}

EnrollmentStore::EnrollmentStore(std::wstring path) : path_(std::move(path)) {
    if (path_.empty()) {
        throw std::invalid_argument("enrollment path must not be empty");
    }
}

std::wstring EnrollmentStore::currentUserSid() {
    return currentProcessUserSid();
}

std::optional<BindingRecord> EnrollmentStore::load() const {
    const auto directory = std::filesystem::path(path_).parent_path();
    const DWORD attributes = GetFileAttributesW(directory.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) storage::verifyProtectedPath(directory, true);
    else if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
        throw std::runtime_error(win32Error("Inspect binding directory"));
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

    struct OwnedFile final { HANDLE value; ~OwnedFile() { CloseHandle(value); } } ownedFile{file};
    LARGE_INTEGER size{};
    requireWin32(GetFileSizeEx(file, &size), "GetFileSizeEx");
    if (size.QuadPart < static_cast<LONGLONG>(sizeof(FileHeader)) || size.QuadPart > 64 * 1024) {
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
    requireWin32(readOk && read == bytes.size(), "ReadFile(enrollment)");

    FileHeader header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.magic != kFileMagic || header.version != kFileVersion ||
        header.encryptedSize == 0 ||
        bytes.size() != sizeof(header) + header.encryptedSize) {
        throw std::runtime_error("enrollment file header is invalid");
    }

    storage::verifyProtectedPath(path_, false);
    return parseRecord(unprotect(bytes.data() + sizeof(header), header.encryptedSize));
}

void EnrollmentStore::save(const BindingRecord& record, const std::function<void()>& beforeCommit) const {
    WriterLock writer;
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
    std::wstring temporary = path_ + kEnrollmentPendingSuffix;
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
    } catch (...) {
        const auto original = winrt::to_string(winrt::to_message());
        std::string message = original;
        if (open && !CloseHandle(file)) message += "; " + win32Error("CloseHandle(enrollment temporary file)");
        if (!DeleteFileW(temporary.c_str())) message += "; " + win32Error("DeleteFileW(enrollment temporary file)");
        if (message != original) throw std::runtime_error(message);
        throw;
    }
}

void EnrollmentStore::remove() const {
    WriterLock writer;
    if (DeleteFileW(path_.c_str()) == FALSE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return;
        }
        throw std::runtime_error(win32Error("DeleteFile(enrollment)"));
    }
}

} // namespace unlock_windows::system_ble
