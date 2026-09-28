// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE
#define SECURITY_WIN32

#include <Windows.h>
#include <lmcons.h>
#include <ntsecapi.h>
#include <security.h>
#include <shellapi.h>
#include <taskschd.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(linker, "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")

namespace {

using Microsoft::WRL::ComPtr;

constexpr wchar_t kWindowClassName[] = L"UnlockWindowsWithIPhone.ComponentsWizard";
constexpr wchar_t kWindowTitle[] = L"Unlock Windows with iPhone Components";
constexpr wchar_t kCredentialProviderDllName[] = L"unlock_credential_provider.dll";
constexpr wchar_t kLsaDllName[] = L"unlock_lsa_authentication_package.dll";
constexpr wchar_t kLsaModuleName[] = L"unlock_lsa_authentication_package";
constexpr wchar_t kCredentialProviderClsid[] = L"{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}";
constexpr wchar_t kCredentialProviderName[] = L"Unlock Windows with iPhone";
constexpr wchar_t kCredentialProviderRegistryPath[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\"
    L"{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}";
constexpr wchar_t kCredentialProviderClsidRegistryPath[] =
    L"SOFTWARE\\Classes\\CLSID\\{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}";
constexpr wchar_t kLsaRegistryPath[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
constexpr wchar_t kLsaRegistryValueName[] = L"Authentication Packages";
constexpr wchar_t kWizardStateRegistryPath[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\ComponentsWizard";
constexpr wchar_t kFinalizeTaskName[] = L"UnlockWindowsWithIPhone-FinalizeUninstall";
constexpr wchar_t kStatePhaseValueName[] = L"Phase";
constexpr wchar_t kStateOriginalPackagesValueName[] = L"OriginalAuthenticationPackages";
constexpr DWORD kStatePhaseInstalled = 1;
constexpr DWORD kStatePhaseUninstallPending = 2;

constexpr int kPrimaryButtonId = 1002;
constexpr int kSecondaryButtonId = 1003;
constexpr int kBackButtonId = 1004;
constexpr int kCloseButtonId = 1005;
constexpr int kContentControlId = 1006;

class WizardError final : public std::exception {
public:
    explicit WizardError(std::wstring message) : message_(std::move(message)) {
        const auto size = WideCharToMultiByte(
            CP_UTF8,
            0,
            message_.c_str(),
            static_cast<int>(message_.size()),
            nullptr,
            0,
            nullptr,
            nullptr
        );
        if (size > 0) {
            narrow_.resize(static_cast<std::size_t>(size));
            WideCharToMultiByte(
                CP_UTF8,
                0,
                message_.c_str(),
                static_cast<int>(message_.size()),
                narrow_.data(),
                size,
                nullptr,
                nullptr
            );
        }
    }

    [[nodiscard]] const wchar_t* wideWhat() const noexcept {
        return message_.c_str();
    }

    [[nodiscard]] const char* what() const noexcept override {
        return narrow_.c_str();
    }

private:
    std::wstring message_;
    std::string narrow_;
};

[[noreturn]] void fail(const std::wstring& message) {
    throw WizardError(message);
}

std::wstring win32ErrorMessage(const DWORD error) {
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

void checkWin32(const BOOL result, const std::wstring& action) {
    if (!result) {
        fail(action + L": " + win32ErrorMessage(GetLastError()));
    }
}

void checkHresult(const HRESULT result, const std::wstring& action) {
    if (FAILED(result)) {
        std::wstringstream message;
        message << action << L" failed (HRESULT 0x" << std::hex << static_cast<std::uint32_t>(result) << L").";
        fail(message.str());
    }
}

class ScopedRegistryKey final {
public:
    ScopedRegistryKey() = default;
    explicit ScopedRegistryKey(HKEY key) : key_(key) {}
    ScopedRegistryKey(const ScopedRegistryKey&) = delete;
    ScopedRegistryKey& operator=(const ScopedRegistryKey&) = delete;
    ScopedRegistryKey(ScopedRegistryKey&& other) noexcept : key_(other.key_) {
        other.key_ = nullptr;
    }
    ScopedRegistryKey& operator=(ScopedRegistryKey&& other) noexcept {
        if (this != &other) {
            reset();
            key_ = other.key_;
            other.key_ = nullptr;
        }
        return *this;
    }
    ~ScopedRegistryKey() {
        reset();
    }
    [[nodiscard]] HKEY get() const noexcept { return key_; }
    void reset() noexcept {
        if (key_ != nullptr) {
            RegCloseKey(key_);
            key_ = nullptr;
        }
    }

private:
    HKEY key_ = nullptr;
};

struct RegistryValue final {
    DWORD type = 0;
    std::vector<std::byte> bytes;
};

std::optional<RegistryValue> readRegistryValue(
    const HKEY root,
    const wchar_t* subkey,
    const wchar_t* valueName
) {
    const auto displayValueName = valueName == nullptr ? L"(Default)" : valueName;
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
        fail(L"Could not query registry value " + std::wstring(valueName) + L": " + win32ErrorMessage(sizeResult));
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
        fail(L"Could not read registry value " + std::wstring(valueName) + L": " + win32ErrorMessage(readResult));
    }
    value.bytes.resize(byteCount);
    return value;
}

void writeRegistryValue(
    const HKEY root,
    const wchar_t* subkey,
    const wchar_t* valueName,
    const DWORD type,
    const std::vector<std::byte>& bytes
) {
    const auto displayValueName = valueName == nullptr ? L"(Default)" : valueName;
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
        fail(L"Could not write registry value " + std::wstring(displayValueName) + L": " + win32ErrorMessage(writeResult));
    }
}

void writeRegistryString(
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

void writeRegistryDword(
    const HKEY root,
    const wchar_t* subkey,
    const wchar_t* valueName,
    const DWORD value
) {
    std::vector<std::byte> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    writeRegistryValue(root, subkey, valueName, REG_DWORD, bytes);
}

std::size_t boundedStringLength(const wchar_t* value, const std::size_t maximum) {
    std::size_t length = 0;
    while (length < maximum && value[length] != L'\0') {
        ++length;
    }
    return length;
}

std::vector<std::wstring> parseMultiString(const std::vector<std::byte>& bytes) {
    if (bytes.size() % sizeof(wchar_t) != 0 || bytes.size() < 2 * sizeof(wchar_t)) {
        fail(L"The Authentication Packages registry value is malformed.");
    }
    const auto* values = reinterpret_cast<const wchar_t*>(bytes.data());
    const auto valueCount = bytes.size() / sizeof(wchar_t);
    std::vector<std::wstring> result;
    std::size_t offset = 0;
    while (offset < valueCount) {
        const auto* start = values + offset;
        const auto remaining = valueCount - offset;
        const auto length = boundedStringLength(start, remaining);
        if (length == remaining) {
            fail(L"The Authentication Packages registry value is not null terminated.");
        }
        if (length == 0) {
            return result;
        }
        result.emplace_back(start, length);
        offset += length + 1;
    }
    fail(L"The Authentication Packages registry value is not double-null terminated.");
}

std::vector<std::byte> serializeMultiString(const std::vector<std::wstring>& values) {
    std::size_t characterCount = 1;
    for (const auto& value : values) {
        characterCount += value.size() + 1;
    }
    std::vector<wchar_t> serialized(characterCount, L'\0');
    std::size_t offset = 0;
    for (const auto& value : values) {
        std::memcpy(serialized.data() + offset, value.c_str(), value.size() * sizeof(wchar_t));
        offset += value.size() + 1;
    }
    std::vector<std::byte> bytes(serialized.size() * sizeof(wchar_t));
    std::memcpy(bytes.data(), serialized.data(), bytes.size());
    return bytes;
}

std::vector<std::byte> readAuthenticationPackages() {
    const auto value = readRegistryValue(HKEY_LOCAL_MACHINE, kLsaRegistryPath, kLsaRegistryValueName);
    if (!value || value->type != REG_MULTI_SZ) {
        fail(L"The LSA Authentication Packages value is missing or has an unexpected type.");
    }
    (void)parseMultiString(value->bytes);
    return value->bytes;
}

void writeAuthenticationPackages(const std::vector<std::byte>& value) {
    (void)parseMultiString(value);
    writeRegistryValue(HKEY_LOCAL_MACHINE, kLsaRegistryPath, kLsaRegistryValueName, REG_MULTI_SZ, value);
}

bool multiStringContains(const std::vector<std::byte>& value, const std::wstring& expected) {
    const auto values = parseMultiString(value);
    return std::any_of(values.begin(), values.end(), [&](const std::wstring& candidate) {
        return _wcsicmp(candidate.c_str(), expected.c_str()) == 0;
    });
}

std::vector<std::byte> removeLsaModule(const std::vector<std::byte>& value) {
    auto values = parseMultiString(value);
    values.erase(
        std::remove_if(values.begin(), values.end(), [](const std::wstring& candidate) {
            return _wcsicmp(candidate.c_str(), kLsaModuleName) == 0;
        }),
        values.end()
    );
    if (values.empty()) {
        fail(L"Refusing to clear the system Authentication Packages value.");
    }
    return serializeMultiString(values);
}

std::vector<std::byte> addLsaModule(const std::vector<std::byte>& value) {
    auto values = parseMultiString(value);
    if (!std::any_of(values.begin(), values.end(), [](const std::wstring& candidate) {
        return _wcsicmp(candidate.c_str(), kLsaModuleName) == 0;
    })) {
        values.emplace_back(kLsaModuleName);
    }
    return serializeMultiString(values);
}

std::optional<DWORD> readRegistryDword(
    const HKEY root,
    const wchar_t* subkey,
    const wchar_t* valueName
) {
    const auto value = readRegistryValue(root, subkey, valueName);
    if (!value) {
        return std::nullopt;
    }
    if (value->type != REG_DWORD || value->bytes.size() != sizeof(DWORD)) {
        fail(L"The registry value " + std::wstring(valueName) + L" has an unexpected type.");
    }
    DWORD result = 0;
    std::memcpy(&result, value->bytes.data(), sizeof(result));
    return result;
}

void deleteRegistryTree(const HKEY root, const wchar_t* subkey) {
    const auto result = RegDeleteTreeW(root, subkey);
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        fail(L"Could not remove registry key " + std::wstring(subkey) + L": " + win32ErrorMessage(result));
    }
}

enum class Architecture {
    x64,
    arm64,
    unknown,
};

std::wstring architectureName(const Architecture architecture) {
    switch (architecture) {
        case Architecture::x64:
            return L"x64";
        case Architecture::arm64:
            return L"arm64";
        default:
            return L"unknown";
    }
}

Architecture nativeArchitecture() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return Architecture::x64;
        case PROCESSOR_ARCHITECTURE_ARM64:
            return Architecture::arm64;
        default:
            return Architecture::unknown;
    }
}

Architecture executableArchitecture(const std::filesystem::path& path) {
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
        fail(L"Could not read " + path.wstring() + L": " + win32ErrorMessage(GetLastError()));
    }

    std::array<std::byte, 64> dosHeader{};
    DWORD bytesRead = 0;
    const auto readDosHeader = ReadFile(file, dosHeader.data(), static_cast<DWORD>(dosHeader.size()), &bytesRead, nullptr);
    if (!readDosHeader || bytesRead != dosHeader.size()) {
        const auto error = GetLastError();
        CloseHandle(file);
        fail(L"Could not read the PE header from " + path.wstring() + L": " + win32ErrorMessage(error));
    }

    std::uint16_t magic = 0;
    std::uint32_t peOffset = 0;
    std::memcpy(&magic, dosHeader.data(), sizeof(magic));
    std::memcpy(&peOffset, dosHeader.data() + 0x3c, sizeof(peOffset));
    if (magic != 0x5a4d) {
        CloseHandle(file);
        fail(path.wstring() + L" does not have an MZ header.");
    }
    if (SetFilePointer(file, static_cast<LONG>(peOffset), nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        GetLastError() != ERROR_SUCCESS) {
        const auto error = GetLastError();
        CloseHandle(file);
        fail(L"Could not seek the PE header in " + path.wstring() + L": " + win32ErrorMessage(error));
    }

    std::array<std::byte, 6> peHeader{};
    bytesRead = 0;
    const auto readPeHeader = ReadFile(file, peHeader.data(), static_cast<DWORD>(peHeader.size()), &bytesRead, nullptr);
    CloseHandle(file);
    if (!readPeHeader || bytesRead != peHeader.size()) {
        fail(L"Could not read the PE signature from " + path.wstring() + L".");
    }

    std::uint32_t signature = 0;
    std::uint16_t machine = 0;
    std::memcpy(&signature, peHeader.data(), sizeof(signature));
    std::memcpy(&machine, peHeader.data() + 4, sizeof(machine));
    if (signature != 0x00004550) {
        fail(path.wstring() + L" does not have a PE signature.");
    }
    if (machine == 0x8664) {
        return Architecture::x64;
    }
    if (machine == 0xaa64) {
        return Architecture::arm64;
    }
    return Architecture::unknown;
}

bool fileExists(const std::filesystem::path& path) {
    std::error_code error;
    return std::filesystem::is_regular_file(path, error);
}

std::filesystem::path modulePath() {
    std::vector<wchar_t> path(MAX_PATH);
    while (true) {
        const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            fail(L"Could not determine the wizard executable path: " + win32ErrorMessage(GetLastError()));
        }
        if (length < path.size() - 1) {
            return std::filesystem::path(std::wstring(path.data(), length));
        }
        path.resize(path.size() * 2);
    }
}

std::filesystem::path sourceDirectory() {
    return modulePath().parent_path();
}

std::filesystem::path system32Directory() {
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

std::filesystem::path credentialProviderSource() {
    return sourceDirectory() / kCredentialProviderDllName;
}

std::filesystem::path lsaSource() {
    return sourceDirectory() / kLsaDllName;
}

std::filesystem::path credentialProviderTarget() {
    return system32Directory() / kCredentialProviderDllName;
}

std::filesystem::path lsaTarget() {
    return system32Directory() / kLsaDllName;
}

bool registryKeyExists(const wchar_t* subkey) {
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

bool isAdministrator() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administratorsSid = nullptr;
    if (!AllocateAndInitializeSid(
            &authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &administratorsSid
        )) {
        fail(L"Could not create the Administrators SID: " + win32ErrorMessage(GetLastError()));
    }
    BOOL member = FALSE;
    const auto result = CheckTokenMembership(nullptr, administratorsSid, &member);
    FreeSid(administratorsSid);
    checkWin32(result, L"Could not check administrator permissions");
    return member == TRUE;
}

void assertSupportedAdministratorEnvironment() {
    if (!isAdministrator()) {
        fail(L"Run the Components Wizard as an administrator.");
    }
    const auto architecture = nativeArchitecture();
    if (architecture != Architecture::x64 && architecture != Architecture::arm64) {
        fail(L"Only x64 and ARM64 Windows are supported.");
    }
    const auto wizardArchitecture = executableArchitecture(modulePath());
    if (wizardArchitecture != architecture) {
        fail(
            L"This wizard is " + architectureName(wizardArchitecture) +
            L", but Windows is " + architectureName(architecture) + L". Rebuild the wizard for the native architecture."
        );
    }
}

struct WizardState final {
    DWORD phase = 0;
    std::vector<std::byte> originalAuthenticationPackages;
};

std::optional<WizardState> readWizardState() {
    const auto phase = readRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStatePhaseValueName);
    if (!phase) {
        return std::nullopt;
    }
    const auto original = readRegistryValue(
        HKEY_LOCAL_MACHINE,
        kWizardStateRegistryPath,
        kStateOriginalPackagesValueName
    );
    if (!original || original->type != REG_MULTI_SZ) {
        fail(L"The Components Wizard state is missing its LSA backup.");
    }
    (void)parseMultiString(original->bytes);
    return WizardState{*phase, original->bytes};
}

void writeWizardState(const WizardState& state) {
    (void)parseMultiString(state.originalAuthenticationPackages);
    writeRegistryValue(
        HKEY_LOCAL_MACHINE,
        kWizardStateRegistryPath,
        kStateOriginalPackagesValueName,
        REG_MULTI_SZ,
        state.originalAuthenticationPackages
    );
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStatePhaseValueName, state.phase);
}

void removeWizardState() {
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath);
}

std::wstring currentUserName() {
    ULONG length = 0;
    GetUserNameExW(NameSamCompatible, nullptr, &length);
    const auto initialError = GetLastError();
    if ((initialError != ERROR_INSUFFICIENT_BUFFER && initialError != ERROR_MORE_DATA) || length == 0) {
        fail(L"Could not determine the current user name: " + win32ErrorMessage(initialError));
    }
    std::vector<wchar_t> user(length);
    checkWin32(GetUserNameExW(NameSamCompatible, user.data(), &length), L"Could not determine the current user name");
    return std::wstring(user.data());
}

class ScopedBstr final {
public:
    explicit ScopedBstr(const std::wstring& value) : value_(SysAllocStringLen(value.data(), static_cast<UINT>(value.size()))) {
        if (value_ == nullptr && !value.empty()) {
            fail(L"Could not allocate a COM string.");
        }
    }
    ~ScopedBstr() { SysFreeString(value_); }
    [[nodiscard]] BSTR get() const noexcept { return value_; }

private:
    BSTR value_ = nullptr;
};

class ScopedVariant final {
public:
    ScopedVariant() { VariantInit(&value_); }
    explicit ScopedVariant(const std::wstring& text) : ScopedVariant() {
        value_.vt = VT_BSTR;
        value_.bstrVal = SysAllocStringLen(text.data(), static_cast<UINT>(text.size()));
        if (value_.bstrVal == nullptr && !text.empty()) {
            fail(L"Could not allocate a COM variant string.");
        }
    }
    ~ScopedVariant() { VariantClear(&value_); }
    [[nodiscard]] VARIANT& get() noexcept { return value_; }

private:
    VARIANT value_{};
};

ComPtr<ITaskService> taskSchedulerService() {
    ComPtr<ITaskService> service;
    checkHresult(
        CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&service)),
        L"Could not create the Task Scheduler service"
    );
    ScopedVariant empty;
    checkHresult(service->Connect(empty.get(), empty.get(), empty.get(), empty.get()), L"Could not connect to Task Scheduler");
    return service;
}

ComPtr<ITaskFolder> taskRootFolder(ITaskService* service) {
    ScopedBstr rootPath(L"\\");
    ComPtr<ITaskFolder> root;
    checkHresult(service->GetFolder(rootPath.get(), &root), L"Could not open the Task Scheduler root folder");
    return root;
}

bool continuationTaskExists() {
    auto service = taskSchedulerService();
    auto root = taskRootFolder(service.Get());
    ScopedBstr taskName(kFinalizeTaskName);
    ComPtr<IRegisteredTask> task;
    const auto result = root->GetTask(taskName.get(), &task);
    if (result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        return false;
    }
    checkHresult(result, L"Could not inspect the uninstall continuation task");
    return true;
}

void registerContinuationTask() {
    if (continuationTaskExists()) {
        fail(L"An uninstall continuation task is already pending.");
    }

    auto service = taskSchedulerService();
    auto root = taskRootFolder(service.Get());
    ComPtr<ITaskDefinition> definition;
    checkHresult(service->NewTask(0, &definition), L"Could not create the uninstall continuation task");

    ComPtr<IRegistrationInfo> registration;
    checkHresult(definition->get_RegistrationInfo(&registration), L"Could not configure the continuation task");
    ScopedBstr description(L"Completes one pending Unlock Windows with iPhone component uninstall after reboot.");
    checkHresult(registration->put_Description(description.get()), L"Could not set the continuation task description");

    const auto userName = currentUserName();
    ComPtr<IPrincipal> principal;
    checkHresult(definition->get_Principal(&principal), L"Could not configure the continuation task principal");
    ScopedBstr userId(userName);
    checkHresult(principal->put_UserId(userId.get()), L"Could not set the continuation task user");
    checkHresult(principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN), L"Could not set the continuation task logon type");
    checkHresult(principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST), L"Could not set the continuation task privilege level");

    ComPtr<ITriggerCollection> triggers;
    checkHresult(definition->get_Triggers(&triggers), L"Could not configure the continuation task trigger");
    ComPtr<ITrigger> trigger;
    checkHresult(triggers->Create(TASK_TRIGGER_LOGON, &trigger), L"Could not create the continuation logon trigger");
    ComPtr<ILogonTrigger> logonTrigger;
    checkHresult(trigger.As(&logonTrigger), L"Could not configure the continuation logon trigger");
    // The task principal remains the specific user who initiated uninstall.
    // Do not also filter the logon trigger by its display name: on Microsoft,
    // Entra, and local accounts, that name can differ from the scheduler's
    // logon identity and prevent the trigger from firing altogether.
    checkHresult(trigger->put_Enabled(VARIANT_TRUE), L"Could not enable the continuation logon trigger");

    ComPtr<IActionCollection> actions;
    checkHresult(definition->get_Actions(&actions), L"Could not configure the continuation task action");
    ComPtr<IAction> action;
    checkHresult(actions->Create(TASK_ACTION_EXEC, &action), L"Could not create the continuation task action");
    ComPtr<IExecAction> execution;
    checkHresult(action.As(&execution), L"Could not configure the continuation executable action");
    ScopedBstr executablePath(modulePath().wstring());
    ScopedBstr arguments(L"--resume-uninstall");
    checkHresult(execution->put_Path(executablePath.get()), L"Could not set the continuation executable path");
    checkHresult(execution->put_Arguments(arguments.get()), L"Could not set the continuation executable arguments");

    ComPtr<ITaskSettings> settings;
    checkHresult(definition->get_Settings(&settings), L"Could not configure the continuation task settings");
    checkHresult(settings->put_StartWhenAvailable(VARIANT_TRUE), L"Could not set continuation task availability");

    ScopedBstr taskName(kFinalizeTaskName);
    ScopedVariant user(userName);
    ScopedVariant empty;
    ComPtr<IRegisteredTask> registeredTask;
    checkHresult(
        root->RegisterTaskDefinition(
            taskName.get(),
            definition.Get(),
            TASK_CREATE,
            user.get(),
            empty.get(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            empty.get(),
            &registeredTask
        ),
        L"Could not register the uninstall continuation task"
    );
}

void removeContinuationTask() {
    auto service = taskSchedulerService();
    auto root = taskRootFolder(service.Get());
    ScopedBstr taskName(kFinalizeTaskName);
    const auto result = root->DeleteTask(taskName.get(), 0);
    if (FAILED(result) && result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        checkHresult(result, L"Could not remove the uninstall continuation task");
    }
}

void createCredentialProviderRegistration(const std::filesystem::path& target) {
    writeRegistryString(HKEY_LOCAL_MACHINE, kCredentialProviderRegistryPath, nullptr, kCredentialProviderName);
    writeRegistryString(HKEY_LOCAL_MACHINE, kCredentialProviderClsidRegistryPath, nullptr, kCredentialProviderName);
    const auto inprocPath = std::wstring(kCredentialProviderClsidRegistryPath) + L"\\InprocServer32";
    writeRegistryString(HKEY_LOCAL_MACHINE, inprocPath.c_str(), nullptr, target.wstring());
    writeRegistryString(HKEY_LOCAL_MACHINE, inprocPath.c_str(), L"ThreadingModel", L"Apartment");
}

void removeCredentialProviderRegistration() {
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kCredentialProviderRegistryPath);
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kCredentialProviderClsidRegistryPath);
}

void copyNativeDll(const std::filesystem::path& source, const std::filesystem::path& target) {
    if (!fileExists(source)) {
        fail(L"Required build output is missing: " + source.wstring());
    }
    const auto systemArchitecture = nativeArchitecture();
    const auto sourceArchitecture = executableArchitecture(source);
    if (sourceArchitecture != systemArchitecture) {
        fail(
            source.filename().wstring() + L" is " + architectureName(sourceArchitecture) +
            L", but Windows is " + architectureName(systemArchitecture) + L". Rebuild before installing."
        );
    }
    if (fileExists(target)) {
        fail(L"Refusing to overwrite an existing system DLL: " + target.wstring());
    }
    checkWin32(CopyFileW(source.c_str(), target.c_str(), TRUE), L"Could not copy " + source.filename().wstring());
}

void deleteDllIfPresent(const std::filesystem::path& target) {
    if (!fileExists(target)) {
        return;
    }
    checkWin32(DeleteFileW(target.c_str()), L"Could not remove " + target.wstring());
}

bool componentFilesOrRegistrationsPresent() {
    const auto packages = readAuthenticationPackages();
    return fileExists(credentialProviderTarget()) ||
        fileExists(lsaTarget()) ||
        registryKeyExists(kCredentialProviderRegistryPath) ||
        registryKeyExists(kCredentialProviderClsidRegistryPath) ||
        multiStringContains(packages, kLsaModuleName);
}

void removeLegacyScriptBackups() {
    const auto buildDirectory = sourceDirectory();
    const auto repositoryRoot = buildDirectory.parent_path().parent_path();
    const auto credentialBackup = repositoryRoot / L".tmp" / L"credential-provider-backup" / L"credential-provider.json";
    const auto lsaBackup = repositoryRoot / L".tmp" / L"lsa-package-backup" / L"authentication-packages.json";
    for (const auto& backup : {credentialBackup, lsaBackup}) {
        std::error_code error;
        std::filesystem::remove(backup, error);
        if (error) {
            const auto detail = error.message();
            fail(
                L"Could not remove legacy rollback backup " + backup.wstring() + L": " +
                std::wstring(detail.begin(), detail.end())
            );
        }
    }
}

void installAllComponents() {
    assertSupportedAdministratorEnvironment();
    if (readWizardState()) {
        fail(L"The Components Wizard already has installation state. Uninstall the existing components before installing again.");
    }
    if (componentFilesOrRegistrationsPresent()) {
        fail(L"Existing Credential Provider or LSA components were found. Use Uninstall all before a new installation.");
    }

    const auto originalPackages = readAuthenticationPackages();
    writeWizardState({kStatePhaseInstalled, originalPackages});

    try {
        copyNativeDll(lsaSource(), lsaTarget());
        writeAuthenticationPackages(addLsaModule(originalPackages));
        copyNativeDll(credentialProviderSource(), credentialProviderTarget());
        createCredentialProviderRegistration(credentialProviderTarget());
    } catch (...) {
        removeCredentialProviderRegistration();
        writeAuthenticationPackages(originalPackages);
        deleteDllIfPresent(credentialProviderTarget());
        deleteDllIfPresent(lsaTarget());
        removeWizardState();
        throw;
    }
}

void startAllComponentsUninstall() {
    assertSupportedAdministratorEnvironment();
    if (continuationTaskExists()) {
        fail(L"An uninstall continuation task is already pending. Restart and sign in to let it finish.");
    }

    const auto existingState = readWizardState();
    if (existingState && existingState->phase == kStatePhaseUninstallPending) {
        fail(L"Uninstall is already waiting for a reboot. Restart and sign in to finish it.");
    }

    const auto currentPackages = readAuthenticationPackages();
    const auto originalPackages = existingState
        ? existingState->originalAuthenticationPackages
        : (multiStringContains(currentPackages, kLsaModuleName) ? removeLsaModule(currentPackages) : currentPackages);
    writeWizardState({kStatePhaseUninstallPending, originalPackages});

    removeCredentialProviderRegistration();
    writeAuthenticationPackages(originalPackages);

    try {
        registerContinuationTask();
    } catch (const WizardError& error) {
        fail(
            L"Registrations were removed, but the automatic continuation task could not be created. "
            L"Restart, then run this EXE with --resume-uninstall from an elevated session. Details: " +
            std::wstring(error.wideWhat())
        );
    } catch (...) {
        fail(
            L"Registrations were removed, but the automatic continuation task could not be created. "
            L"Restart, then run this EXE with --resume-uninstall from an elevated session."
        );
    }
}

void completeAllComponentsUninstall() {
    assertSupportedAdministratorEnvironment();
    const auto state = readWizardState();
    if (!state || state->phase != kStatePhaseUninstallPending) {
        fail(L"No valid uninstall continuation is pending.");
    }

    deleteDllIfPresent(credentialProviderTarget());
    deleteDllIfPresent(lsaTarget());

    const auto packages = readAuthenticationPackages();
    if (registryKeyExists(kCredentialProviderRegistryPath) ||
        registryKeyExists(kCredentialProviderClsidRegistryPath) ||
        multiStringContains(packages, kLsaModuleName) ||
        fileExists(credentialProviderTarget()) ||
        fileExists(lsaTarget())) {
        fail(L"Uninstall verification failed. The continuation state was preserved for retry.");
    }

    removeContinuationTask();
    removeLegacyScriptBackups();
    removeWizardState();
}

std::wstring queryLsaPackage() {
    LSA_HANDLE lsa = nullptr;
    const auto connectStatus = LsaConnectUntrusted(&lsa);
    if (connectStatus < 0) {
        std::wstringstream message;
        message << L"Could not connect to LSA (NTSTATUS 0x" << std::hex << static_cast<std::uint32_t>(connectStatus) << L").";
        fail(message.str());
    }

    LSA_STRING packageName{};
    packageName.Buffer = const_cast<PCHAR>("UnlockWindowsWithIPhone");
    packageName.Length = static_cast<USHORT>(std::strlen(packageName.Buffer));
    packageName.MaximumLength = packageName.Length;
    ULONG packageId = 0;
    const auto lookupStatus = LsaLookupAuthenticationPackage(lsa, &packageName, &packageId);
    LsaDeregisterLogonProcess(lsa);
    if (lookupStatus < 0) {
        std::wstringstream message;
        message << L"LSA did not load UnlockWindowsWithIPhone (NTSTATUS 0x" << std::hex << static_cast<std::uint32_t>(lookupStatus) << L").";
        fail(message.str());
    }

    return L"UnlockWindowsWithIPhone is loaded by LSA; package id=" + std::to_wstring(packageId);
}

std::wstring buildStatusText() {
    const auto native = nativeArchitecture();
    const auto wizard = executableArchitecture(modulePath());
    const auto cpSource = credentialProviderSource();
    const auto lsaSourcePath = lsaSource();
    const auto cpTarget = credentialProviderTarget();
    const auto lsaTargetPath = lsaTarget();
    const auto packages = readAuthenticationPackages();
    const auto state = readWizardState();
    const auto runAsPpl = readRegistryDword(HKEY_LOCAL_MACHINE, kLsaRegistryPath, L"RunAsPPL");

    const auto describeFile = [](const std::filesystem::path& path) {
        if (!fileExists(path)) {
            return std::wstring(L"NotPresent");
        }
        return architectureName(executableArchitecture(path));
    };

    std::wstringstream status;
    status << L"Administrator: " << (isAdministrator() ? L"True" : L"False") << L"\r\n";
    status << L"Native Windows architecture: " << architectureName(native) << L"\r\n";
    status << L"Wizard architecture: " << architectureName(wizard) << L"\r\n";
    status << L"Credential Provider source: " << describeFile(cpSource) << L"\r\n";
    status << L"Credential Provider System32: " << describeFile(cpTarget) << L"\r\n";
    status << L"LSA package source: " << describeFile(lsaSourcePath) << L"\r\n";
    status << L"LSA package System32: " << describeFile(lsaTargetPath) << L"\r\n";
    status << L"Credential Provider registered: " << (registryKeyExists(kCredentialProviderRegistryPath) ? L"True" : L"False") << L"\r\n";
    status << L"Credential Provider CLSID registered: " << (registryKeyExists(kCredentialProviderClsidRegistryPath) ? L"True" : L"False") << L"\r\n";
    status << L"LSA package registered: " << (multiStringContains(packages, kLsaModuleName) ? L"True" : L"False") << L"\r\n";
    status << L"LSA Protection registry value: " << (runAsPpl ? std::to_wstring(*runAsPpl) : L"NotPresent") << L"\r\n";
    status << L"Wizard state: ";
    if (!state) {
        status << L"NotPresent\r\n";
    } else if (state->phase == kStatePhaseInstalled) {
        status << L"Installed\r\n";
    } else if (state->phase == kStatePhaseUninstallPending) {
        status << L"UninstallPendingReboot\r\n";
    } else {
        status << L"Unknown\r\n";
    }
    status << L"Automatic uninstall task: " << (continuationTaskExists() ? L"Present" : L"NotPresent") << L"\r\n";
    return status.str();
}

void restartWindows() {
    const auto result = ShellExecuteW(nullptr, L"open", L"shutdown.exe", L"/r /t 0", nullptr, SW_HIDE);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        fail(L"Could not request a restart.");
    }
}

enum class Page {
    welcome,
    status,
    installed,
    uninstallPending,
    uninstallComplete,
};

class ComponentsWizard final {
public:
    explicit ComponentsWizard(const bool resumeUninstall) : resumeUninstall_(resumeUninstall) {}

    int run(const HINSTANCE instance) {
        WNDCLASSW windowClass{};
        windowClass.lpfnWndProc = windowProcedure;
        windowClass.hInstance = instance;
        windowClass.lpszClassName = kWindowClassName;
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        RegisterClassW(&windowClass);

        window_ = CreateWindowExW(
            0,
            kWindowClassName,
            kWindowTitle,
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            760,
            560,
            nullptr,
            nullptr,
            instance,
            this
        );
        if (window_ == nullptr) {
            fail(L"Could not create the Components Wizard window: " + win32ErrorMessage(GetLastError()));
        }

        ShowWindow(window_, SW_SHOW);
        UpdateWindow(window_);

        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        return static_cast<int>(message.wParam);
    }

private:
    static LRESULT CALLBACK windowProcedure(HWND window, UINT message, WPARAM wordParam, LPARAM longParam) {
        auto* wizard = reinterpret_cast<ComponentsWizard*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(longParam);
            wizard = static_cast<ComponentsWizard*>(create->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(wizard));
            wizard->window_ = window;
        }
        if (wizard != nullptr) {
            return wizard->handleMessage(message, wordParam, longParam);
        }
        return DefWindowProcW(window, message, wordParam, longParam);
    }

    LRESULT handleMessage(UINT message, WPARAM wordParam, LPARAM longParam) {
        switch (message) {
            case WM_CREATE:
                createControls();
                if (resumeUninstall_) {
                    resumeUninstall();
                } else {
                    showWelcome();
                }
                return 0;
            case WM_COMMAND:
                if (HIWORD(wordParam) == BN_CLICKED) {
                    handleButton(LOWORD(wordParam));
                }
                return 0;
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
            default:
                return DefWindowProcW(window_, message, wordParam, longParam);
        }
    }

    void createControls() {
        title_ = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 24, 20, 700, 30, window_, nullptr, nullptr, nullptr);
        SendMessageW(title_, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        content_ = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            24,
            62,
            696,
            340,
            window_,
            reinterpret_cast<HMENU>(kContentControlId),
            nullptr,
            nullptr
        );
        primary_ = createButton(kPrimaryButtonId, 24, 430, 210);
        secondary_ = createButton(kSecondaryButtonId, 248, 430, 210);
        back_ = createButton(kBackButtonId, 472, 430, 110);
        close_ = createButton(kCloseButtonId, 596, 430, 124);
    }

    HWND createButton(const int identifier, const int x, const int y, const int width) {
        return CreateWindowW(
            L"BUTTON",
            L"",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x,
            y,
            width,
            36,
            window_,
            reinterpret_cast<HMENU>(identifier),
            nullptr,
            nullptr
        );
    }

    void setPage(const Page page, const std::wstring& title, const std::wstring& content) {
        page_ = page;
        SetWindowTextW(title_, title.c_str());
        SetWindowTextW(content_, content.c_str());
        ShowWindow(content_, SW_SHOW);
    }

    void setButton(HWND button, const std::wstring& text, const bool visible, const bool enabled = true) {
        SetWindowTextW(button, text.c_str());
        EnableWindow(button, enabled ? TRUE : FALSE);
        ShowWindow(button, visible ? SW_SHOW : SW_HIDE);
    }

    void showWelcome() {
        setPage(
            Page::welcome,
            L"Unlock Windows with iPhone Components",
            L"This native installer manages the test Credential Provider and LSA Authentication Package.\r\n\r\n"
            L"It requires an elevated native-architecture build. Installation and LSA updates require a restart.\r\n\r\n"
            L"Uninstall first removes the CP and LSA registrations, then after the restart automatically reopens this EXE to remove both System32 DLLs and show the final result."
        );
        setButton(primary_, L"Next", true);
        setButton(secondary_, L"", false);
        setButton(back_, L"", false);
        setButton(close_, L"Cancel", true);
    }

    void showStatus() {
        try {
            const auto status = buildStatusText();
            setPage(Page::status, L"Component status", status);
            const auto state = readWizardState();
            const auto hasComponents = componentFilesOrRegistrationsPresent();
            if (state && state->phase == kStatePhaseUninstallPending) {
                setButton(primary_, L"Restart to finish", true);
            } else if (state || hasComponents) {
                setButton(primary_, state ? L"Recover and uninstall" : L"Uninstall all", true);
            } else {
                setButton(primary_, L"Install all", true);
            }
            setButton(secondary_, L"Verify LSA", true);
            setButton(back_, L"Back", true);
            setButton(close_, L"Close", true);
        } catch (const WizardError& error) {
            showError(error.wideWhat());
        }
    }

    void showInstalled() {
        setPage(
            Page::installed,
            L"Components installed",
            L"Credential Provider and LSA package registrations were created.\r\n\r\n"
            L"Restart Windows, then return to this EXE and choose Verify LSA. The lock-screen tile is available after the restart."
        );
        setButton(primary_, L"Restart now", true);
        setButton(secondary_, L"Close", true);
        setButton(back_, L"", false);
        setButton(close_, L"Close", false);
    }

    void showUninstallPending() {
        setPage(
            Page::uninstallPending,
            L"Restart required",
            L"Credential Provider registration was removed and the original LSA package list was restored.\r\n\r\n"
            L"Restart Windows. After you sign in with PIN, password, or another remaining provider, this EXE will open automatically, remove both DLLs, clear its backup state, and show the completion result."
        );
        setButton(primary_, L"Restart now", true);
        setButton(secondary_, L"Close", true);
        setButton(back_, L"", false);
        setButton(close_, L"Close", false);
    }

    void showUninstallComplete() {
        setPage(
            Page::uninstallComplete,
            L"Uninstall complete",
            L"Credential Provider registration is absent.\r\n"
            L"The original LSA Authentication Packages registry value is restored.\r\n"
            L"Both System32 DLLs and wizard state were removed.\r\n\r\n"
            L"No PowerShell continuation is running."
        );
        setButton(primary_, L"Close", true);
        setButton(secondary_, L"", false);
        setButton(back_, L"", false);
        setButton(close_, L"Close", false);
    }

    void resumeUninstall() {
        try {
            completeAllComponentsUninstall();
            showUninstallComplete();
        } catch (const WizardError& error) {
            showError(error.wideWhat());
            showStatus();
        }
    }

    void handleButton(const int identifier) {
        try {
            switch (identifier) {
                case kPrimaryButtonId:
                    if (page_ == Page::welcome) {
                        showStatus();
                    } else if (page_ == Page::status) {
                        const auto state = readWizardState();
                        if (state && state->phase == kStatePhaseUninstallPending) {
                            restartWindows();
                        } else if (componentFilesOrRegistrationsPresent()) {
                            startAllComponentsUninstall();
                            showUninstallPending();
                        } else {
                            installAllComponents();
                            showInstalled();
                        }
                    } else if (page_ == Page::installed || page_ == Page::uninstallPending) {
                        restartWindows();
                    } else if (page_ == Page::uninstallComplete) {
                        DestroyWindow(window_);
                    }
                    break;
                case kSecondaryButtonId:
                    if (page_ == Page::status) {
                        MessageBoxW(window_, queryLsaPackage().c_str(), kWindowTitle, MB_OK | MB_ICONINFORMATION);
                    } else if (page_ == Page::installed || page_ == Page::uninstallPending) {
                        DestroyWindow(window_);
                    }
                    break;
                case kBackButtonId:
                    if (page_ == Page::status) {
                        showWelcome();
                    }
                    break;
                case kCloseButtonId:
                    DestroyWindow(window_);
                    break;
                default:
                    break;
            }
        } catch (const WizardError& error) {
            showError(error.wideWhat());
            if (page_ != Page::status) {
                showStatus();
            }
        }
    }

    void showError(const wchar_t* message) const {
        MessageBoxW(window_, message, kWindowTitle, MB_OK | MB_ICONERROR);
    }

    HWND window_ = nullptr;
    HWND title_ = nullptr;
    HWND content_ = nullptr;
    HWND primary_ = nullptr;
    HWND secondary_ = nullptr;
    HWND back_ = nullptr;
    HWND close_ = nullptr;
    Page page_ = Page::welcome;
    bool resumeUninstall_ = false;
};

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, PWSTR commandLine, int) {
    const auto comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE) {
        MessageBoxW(nullptr, L"Could not initialize COM for the Components Wizard.", kWindowTitle, MB_OK | MB_ICONERROR);
        return 1;
    }

    try {
        ComponentsWizard wizard(std::wstring(commandLine).find(L"--resume-uninstall") != std::wstring::npos);
        const auto result = wizard.run(instance);
        if (SUCCEEDED(comResult)) {
            CoUninitialize();
        }
        return result;
    } catch (const WizardError& error) {
        MessageBoxW(nullptr, error.wideWhat(), kWindowTitle, MB_OK | MB_ICONERROR);
    } catch (...) {
        MessageBoxW(nullptr, L"The Components Wizard encountered an unexpected error.", kWindowTitle, MB_OK | MB_ICONERROR);
    }

    if (SUCCEEDED(comResult)) {
        CoUninitialize();
    }
    return 1;
}
