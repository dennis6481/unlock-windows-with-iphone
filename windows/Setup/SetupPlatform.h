// Created by Rui MA on 04 Oct 2026
// Internal Windows primitives and installation paths shared by setup modules.

#pragma once

#include "WindowsAdapter.h"
#include "../Resources/resource.h"
#include "../PhoneApproval/EnrollmentStore.h"
#include <Windows.h>
#include <shlobj.h>
#include <sddl.h>
#include <array>
#include <cstddef>
#include <optional>
#include <cstring>
#include <vector>

namespace unlock::components {
inline void fail(const std::wstring& message) { throw ComponentError(message); }
class ScopedHandle final {
public:
    HANDLE value = nullptr;
    explicit ScopedHandle(HANDLE handle = nullptr) : value(handle) {}
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ~ScopedHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    [[nodiscard]] HANDLE get() const noexcept { return value; }
};
class ScopedRegistryKey final {
public:
    HKEY value = nullptr;
    explicit ScopedRegistryKey(HKEY key = nullptr) : value(key) {}
    ScopedRegistryKey(const ScopedRegistryKey&) = delete;
    ScopedRegistryKey& operator=(const ScopedRegistryKey&) = delete;
    ~ScopedRegistryKey() { if (value) RegCloseKey(value); }
    [[nodiscard]] HKEY get() const noexcept { return value; }
};
inline void checkHresult(HRESULT value, const std::wstring& text) {
    if (FAILED(value)) throw ComponentError(text + L" (HRESULT=" +
        std::to_wstring(static_cast<unsigned long>(value)) + L")");
}
inline void checkRegistry(LSTATUS status, const std::wstring& operation) {
    if (status != ERROR_SUCCESS) throw ComponentError(operation + L" (Win32=" + std::to_wstring(status) + L")");
}
struct ScopedComApartment final {
    HRESULT value = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ScopedComApartment() {
        if (FAILED(value) && value != RPC_E_CHANGED_MODE) checkHresult(value, L"Initialize COM");
    }
    ~ScopedComApartment() { if (SUCCEEDED(value)) CoUninitialize(); }
    ScopedComApartment(const ScopedComApartment&) = delete;
    ScopedComApartment& operator=(const ScopedComApartment&) = delete;
};
inline std::wstring setupErrorText(const std::exception& error) {
    if (const auto* component = dynamic_cast<const ComponentError*>(&error)) return component->wideWhat();
    const std::string text(error.what());
    return {text.begin(), text.end()};
}
inline std::wstring win32ErrorMessage(const DWORD error) {
    LPWSTR buffer = nullptr;
    const auto length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr
    );
    std::wstring message = length == 0 ? L"Unknown Windows error" : std::wstring(buffer, length);
    LocalFree(buffer);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message;
}

inline void checkWin32(const BOOL result, const std::wstring& action) {
    if (!result) {
        fail(action + L": " + win32ErrorMessage(GetLastError()));
    }
}

inline void validateTargetSid(const std::wstring& sid) {
    PSID binary = nullptr;
    checkWin32(ConvertStringSidToSidW(sid.c_str(), &binary), L"Validate target SID");
    const bool valid = IsValidSid(binary) != FALSE;
    LocalFree(binary);
    if (!valid || sid == L"S-1-5-18") throw ComponentError(L"A real console user is required.");
}

struct RegistryValue final {
    DWORD type = 0;
    std::vector<std::byte> bytes;
};

inline std::optional<RegistryValue> readRegistryValue(
    const HKEY root,
    const wchar_t* subkey,
    const wchar_t* valueName
) {
    HKEY key = nullptr;
    const auto openResult = RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE, &key);
    if (openResult == ERROR_FILE_NOT_FOUND) {
        return std::nullopt;
    }
    if (openResult != ERROR_SUCCESS) {
        fail(L"Could not open registry key " + std::wstring(subkey) + L": " + win32ErrorMessage(openResult));
    }
    ScopedRegistryKey scopedKey(key);

    DWORD type = 0;
    DWORD byteCount = 0;
    const auto sizeResult = RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &byteCount);
    if (sizeResult == ERROR_FILE_NOT_FOUND) {
        return std::nullopt;
    }
    if (sizeResult != ERROR_SUCCESS) {
        fail(L"Could not query a registry value: " + win32ErrorMessage(sizeResult));
    }

    RegistryValue value;
    value.type = type;
    value.bytes.resize(byteCount);
    const auto readResult = RegQueryValueExW(
        key,
        valueName,
        nullptr,
        &value.type,
        reinterpret_cast<BYTE*>(value.bytes.data()),
        &byteCount
    );
    if (readResult != ERROR_SUCCESS) {
        fail(L"Could not read a registry value: " + win32ErrorMessage(readResult));
    }
    value.bytes.resize(byteCount);
    return value;
}

inline void writeRegistryValue(
    const HKEY root,
    const wchar_t* subkey,
    const wchar_t* valueName,
    const DWORD type,
    const std::vector<std::byte>& bytes
) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    const auto createResult = RegCreateKeyExW(
        root,
        subkey,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &key,
        &disposition
    );
    if (createResult != ERROR_SUCCESS) {
        fail(L"Could not create registry key " + std::wstring(subkey) + L": " + win32ErrorMessage(createResult));
    }
    ScopedRegistryKey scopedKey(key);
    const auto writeResult = RegSetValueExW(
        key,
        valueName,
        0,
        type,
        reinterpret_cast<const BYTE*>(bytes.data()),
        static_cast<DWORD>(bytes.size())
    );
    if (writeResult != ERROR_SUCCESS) {
        fail(L"Could not write registry value: " + win32ErrorMessage(writeResult));
    }
}

inline void writeRegistryString(
    const HKEY root,
    const wchar_t* subkey,
    const wchar_t* valueName,
    const std::wstring& value
) {
    const auto byteCount = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    std::vector<std::byte> bytes(byteCount);
    std::memcpy(bytes.data(), value.c_str(), byteCount);
    writeRegistryValue(root, subkey, valueName, REG_SZ, bytes);
}

inline void writeRegistryDword(const HKEY root, const wchar_t* subkey, const wchar_t* valueName, const DWORD value) {
    std::vector<std::byte> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    writeRegistryValue(root, subkey, valueName, REG_DWORD, bytes);
}

inline std::optional<DWORD> readRegistryDword(const HKEY root, const wchar_t* subkey, const wchar_t* valueName) {
    const auto value = readRegistryValue(root, subkey, valueName);
    if (!value) {
        return std::nullopt;
    }
    if (value->type != REG_DWORD || value->bytes.size() != sizeof(DWORD)) {
        fail(L"The registry DWORD has an unexpected type.");
    }
    DWORD result = 0;
    std::memcpy(&result, value->bytes.data(), sizeof(result));
    return result;
}

inline std::optional<std::wstring> readRegistryString(const HKEY root, const wchar_t* subkey, const wchar_t* valueName) {
    const auto value = readRegistryValue(root, subkey, valueName);
    if (!value) {
        return std::nullopt;
    }
    if (value->type != REG_SZ && value->type != REG_EXPAND_SZ) {
        fail(L"The registry string has an unexpected type.");
    }
    if (value->bytes.size() % sizeof(wchar_t) != 0) {
        fail(L"The registry string is malformed.");
    }
    const auto* text = reinterpret_cast<const wchar_t*>(value->bytes.data());
    const auto count = value->bytes.size() / sizeof(wchar_t);
    return std::wstring(text, count == 0 ? 0 : count - (text[count - 1] == L'\0' ? 1 : 0));
}

inline void deleteRegistryTree(const HKEY root, const wchar_t* subkey) {
    const auto result = RegDeleteTreeW(root, subkey);
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        fail(L"Could not remove registry key " + std::wstring(subkey) + L": " + win32ErrorMessage(result));
    }
}

inline bool registryKeyExists(const wchar_t* subkey) {
    HKEY key = nullptr;
    const auto result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key);
    if (result == ERROR_FILE_NOT_FOUND) {
        return false;
    }
    if (result != ERROR_SUCCESS) {
        fail(L"Could not inspect registry key " + std::wstring(subkey) + L": " + win32ErrorMessage(result));
    }
    RegCloseKey(key);
    return true;
}

inline std::filesystem::path system32Directory() {
    std::vector<wchar_t> directory(MAX_PATH);
    const auto length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    if (length == 0) {
        fail(L"Could not determine System32: " + win32ErrorMessage(GetLastError()));
    }
    if (length >= directory.size()) {
        directory.resize(length + 1);
        const auto retryLength = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
        if (retryLength == 0 || retryLength >= directory.size()) {
            fail(L"Could not determine System32.");
        }
        return std::filesystem::path(std::wstring(directory.data(), retryLength));
    }
    return std::filesystem::path(std::wstring(directory.data(), length));
}

inline bool fileExists(const std::filesystem::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        fail(L"Unsafe component reparse point: " + path.wstring());
    std::error_code error;
    const bool present = std::filesystem::exists(path, error);
    if (error) fail(L"Could not inspect component path: " + path.wstring());
    if (!present) return false;
    const bool regular = std::filesystem::is_regular_file(path, error);
    if (error || !regular) fail(L"Component path is not a regular file: " + path.wstring());
    return true;
}


[[nodiscard]] inline std::filesystem::path setupKnownFolder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    const HRESULT result = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &raw);
    if (FAILED(result)) throw ComponentError(L"Cannot resolve installation folder (HRESULT=" +
        std::to_wstring(static_cast<unsigned long>(result)) + L").");
    const std::filesystem::path path(raw);
    CoTaskMemFree(raw);
    return path;
}
[[nodiscard]] inline std::filesystem::path desktopDirectory() {
    return setupKnownFolder(FOLDERID_ProgramFiles) / kDesktopDirectoryName;
}
[[nodiscard]] inline std::filesystem::path startMenuShortcut() {
    return setupKnownFolder(FOLDERID_CommonPrograms) / (std::wstring(UNLOCK_PRODUCT_DISPLAY_NAME) + L".lnk");
}
[[nodiscard]] inline std::filesystem::path productDataDirectory() {
    return setupKnownFolder(FOLDERID_ProgramData) / unlock_windows::phone_approval::kEnrollmentDataDirectoryName;
}
[[nodiscard]] inline std::filesystem::path transactionRoot() {
    return productDataDirectory() / kSetupDirectoryName / kTransactionsDirectoryName;
}
}
