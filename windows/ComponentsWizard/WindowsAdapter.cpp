// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE
#define SECURITY_WIN32

#include "WindowsAdapter.h"

#include <Windows.h>
#include <lmcons.h>
#include <ntsecapi.h>
#include <security.h>
#include <shellapi.h>
#include <taskschd.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <sstream>
#include <utility>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "taskschd.lib")

namespace unlock::components {
namespace {

using Microsoft::WRL::ComPtr;

constexpr wchar_t kCredentialProviderDllName[] = L"unlock_credential_provider.dll";
constexpr wchar_t kLsaDllName[] = L"unlock_lsa_authentication_package.dll";
constexpr wchar_t kLsaModuleName[] = L"unlock_lsa_authentication_package";
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
constexpr wchar_t kSchemaVersionValueName[] = L"SchemaVersion";
constexpr wchar_t kStatePhaseValueName[] = L"Phase";
constexpr wchar_t kStateTransactionIdValueName[] = L"TransactionId";
constexpr wchar_t kStateWizardPathValueName[] = L"WizardPath";
constexpr wchar_t kStateCreatedAtValueName[] = L"CreatedAtUtc";
constexpr wchar_t kStateLastErrorValueName[] = L"LastError";

[[noreturn]] void fail(const std::wstring& message) {
    throw ComponentError(message);
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

class ScopedHandle final {
public:
    explicit ScopedHandle(const HANDLE handle) : handle_(handle) {}
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ~ScopedHandle() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            CloseHandle(handle_);
        }
    }
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

class ScopedRegistryKey final {
public:
    explicit ScopedRegistryKey(const HKEY key) : key_(key) {}
    ScopedRegistryKey(const ScopedRegistryKey&) = delete;
    ScopedRegistryKey& operator=(const ScopedRegistryKey&) = delete;
    ~ScopedRegistryKey() {
        if (key_ != nullptr) {
            RegCloseKey(key_);
        }
    }
    [[nodiscard]] HKEY get() const noexcept { return key_; }

private:
    HKEY key_ = nullptr;
};

class ScopedBstr final {
public:
    explicit ScopedBstr(const std::wstring& value)
        : value_(SysAllocStringLen(value.data(), static_cast<UINT>(value.size()))) {
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

struct RegistryValue final {
    DWORD type = 0;
    std::vector<std::byte> bytes;
};

std::optional<RegistryValue> readRegistryValue(
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

void writeRegistryValue(
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

void writeRegistryDword(const HKEY root, const wchar_t* subkey, const wchar_t* valueName, const DWORD value) {
    std::vector<std::byte> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    writeRegistryValue(root, subkey, valueName, REG_DWORD, bytes);
}

std::optional<DWORD> readRegistryDword(const HKEY root, const wchar_t* subkey, const wchar_t* valueName) {
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

std::optional<std::wstring> readRegistryString(const HKEY root, const wchar_t* subkey, const wchar_t* valueName) {
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

void deleteRegistryTree(const HKEY root, const wchar_t* subkey) {
    const auto result = RegDeleteTreeW(root, subkey);
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        fail(L"Could not remove registry key " + std::wstring(subkey) + L": " + win32ErrorMessage(result));
    }
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

bool containsMultiString(const std::vector<std::byte>& value, const std::wstring& expected) {
    const auto values = parseMultiString(value);
    return std::any_of(values.begin(), values.end(), [&](const std::wstring& candidate) {
        return _wcsicmp(candidate.c_str(), expected.c_str()) == 0;
    });
}

bool isKnownPhase(const DWORD phase) {
    return phase <= static_cast<DWORD>(WizardPhase::recoveryRequired);
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

bool fileExists(const std::filesystem::path& path) {
    std::error_code error;
    return std::filesystem::is_regular_file(path, error);
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
    const auto handle = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        fail(L"Could not read " + path.wstring() + L": " + win32ErrorMessage(GetLastError()));
    }
    ScopedHandle file(handle);

    std::array<std::byte, 64> dosHeader{};
    DWORD bytesRead = 0;
    checkWin32(ReadFile(file.get(), dosHeader.data(), static_cast<DWORD>(dosHeader.size()), &bytesRead, nullptr),
        L"Could not read the PE header from " + path.wstring());
    if (bytesRead != dosHeader.size()) {
        fail(L"The PE header is incomplete in " + path.wstring() + L".");
    }

    std::uint16_t magic = 0;
    std::uint32_t peOffset = 0;
    std::memcpy(&magic, dosHeader.data(), sizeof(magic));
    std::memcpy(&peOffset, dosHeader.data() + 0x3c, sizeof(peOffset));
    if (magic != 0x5a4d) {
        fail(path.wstring() + L" does not have an MZ header.");
    }
    if (SetFilePointer(file.get(), static_cast<LONG>(peOffset), nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        GetLastError() != ERROR_SUCCESS) {
        fail(L"Could not seek the PE header in " + path.wstring() + L": " + win32ErrorMessage(GetLastError()));
    }

    std::array<std::byte, 6> peHeader{};
    bytesRead = 0;
    checkWin32(ReadFile(file.get(), peHeader.data(), static_cast<DWORD>(peHeader.size()), &bytesRead, nullptr),
        L"Could not read the PE signature from " + path.wstring());
    if (bytesRead != peHeader.size()) {
        fail(L"The PE signature is incomplete in " + path.wstring() + L".");
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

bool isElevated() {
    HANDLE token = nullptr;
    checkWin32(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), L"Could not open the process token");
    ScopedHandle scopedToken(token);
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    checkWin32(
        GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size),
        L"Could not query token elevation"
    );
    return elevation.TokenIsElevated != 0;
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

std::wstring transactionId() {
    return std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(GetCurrentProcessId());
}

std::wstring utcTimestamp() {
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return std::to_wstring(value.QuadPart);
}

class ScopedCom final {
public:
    ScopedCom() : result_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
    ~ScopedCom() {
        if (SUCCEEDED(result_)) {
            CoUninitialize();
        }
    }
    [[nodiscard]] HRESULT result() const noexcept { return result_; }

private:
    HRESULT result_;
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

} // namespace

ComponentError::ComponentError(std::wstring message) : message_(std::move(message)) {
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

const wchar_t* ComponentError::wideWhat() const noexcept {
    return message_.c_str();
}

const char* ComponentError::what() const noexcept {
    return narrow_.c_str();
}

const wchar_t* architectureName(const Architecture architecture) noexcept {
    switch (architecture) {
        case Architecture::x64:
            return L"x64";
        case Architecture::arm64:
            return L"arm64";
        default:
            return L"unknown";
    }
}

WindowsAdapter::WindowsAdapter(std::filesystem::path wizardPath) : wizardPath_(std::move(wizardPath)) {}

const std::filesystem::path& WindowsAdapter::wizardPath() const noexcept {
    return wizardPath_;
}

std::filesystem::path WindowsAdapter::credentialProviderSource() const {
    return wizardPath_.parent_path() / kCredentialProviderDllName;
}

std::filesystem::path WindowsAdapter::lsaSource() const {
    return wizardPath_.parent_path() / kLsaDllName;
}

std::filesystem::path WindowsAdapter::credentialProviderTarget() const {
    return system32Directory() / kCredentialProviderDllName;
}

std::filesystem::path WindowsAdapter::lsaTarget() const {
    return system32Directory() / kLsaDllName;
}

EnvironmentStatus WindowsAdapter::environment() const {
    EnvironmentStatus result;
    result.elevated = isElevated();
    result.nativeArchitecture = nativeArchitecture();
    result.wizardArchitecture = executableArchitecture(wizardPath_);
    if (fileExists(credentialProviderSource())) {
        result.credentialProviderSourceArchitecture = executableArchitecture(credentialProviderSource());
    }
    if (fileExists(lsaSource())) {
        result.lsaSourceArchitecture = executableArchitecture(lsaSource());
    }
    if (fileExists(credentialProviderTarget())) {
        result.credentialProviderTargetArchitecture = executableArchitecture(credentialProviderTarget());
    }
    if (fileExists(lsaTarget())) {
        result.lsaTargetArchitecture = executableArchitecture(lsaTarget());
    }
    return result;
}

void WindowsAdapter::assertSupportedAdministratorEnvironment() const {
    const auto status = environment();
    if (!status.elevated) {
        fail(L"Run the Components Wizard as an administrator.");
    }
    if (status.nativeArchitecture != Architecture::x64 && status.nativeArchitecture != Architecture::arm64) {
        fail(L"Only x64 and ARM64 Windows are supported.");
    }
    if (status.wizardArchitecture != status.nativeArchitecture) {
        fail(
            L"This wizard is " + std::wstring(architectureName(status.wizardArchitecture)) +
            L", but Windows is " + architectureName(status.nativeArchitecture) + L". Rebuild the wizard for the native architecture."
        );
    }
}

std::optional<WizardState> WindowsAdapter::readState() const {
    const auto phase = readRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStatePhaseValueName);
    if (!phase) {
        if (registryKeyExists(kWizardStateRegistryPath)) {
            fail(L"The Components Wizard state key exists but has no phase value.");
        }
        return std::nullopt;
    }
    WizardState state;
    state.schemaVersion = readRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kSchemaVersionValueName).value_or(0);
    state.phase = static_cast<WizardPhase>(*phase);
    state.transactionId = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateTransactionIdValueName).value_or(L"");
    state.wizardPath = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateWizardPathValueName).value_or(L"");
    state.createdAtUtc = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateCreatedAtValueName).value_or(L"");
    state.lastError = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateLastErrorValueName).value_or(L"");
    return state;
}

void WindowsAdapter::writeState(const WizardState& state) const {
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kSchemaVersionValueName, state.schemaVersion);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStatePhaseValueName, static_cast<DWORD>(state.phase));
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateTransactionIdValueName, state.transactionId);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateWizardPathValueName, state.wizardPath);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateCreatedAtValueName, state.createdAtUtc);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateLastErrorValueName, state.lastError);
}

void WindowsAdapter::clearState() const {
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath);
}

std::vector<std::byte> WindowsAdapter::readAuthenticationPackages() const {
    const auto value = readRegistryValue(HKEY_LOCAL_MACHINE, kLsaRegistryPath, kLsaRegistryValueName);
    if (!value || value->type != REG_MULTI_SZ) {
        fail(L"The LSA Authentication Packages value is missing or has an unexpected type.");
    }
    (void)parseMultiString(value->bytes);
    return value->bytes;
}

void WindowsAdapter::writeAuthenticationPackages(const std::vector<std::byte>& value) const {
    (void)parseMultiString(value);
    writeRegistryValue(HKEY_LOCAL_MACHINE, kLsaRegistryPath, kLsaRegistryValueName, REG_MULTI_SZ, value);
}

std::vector<std::byte> WindowsAdapter::addLsaModule(const std::vector<std::byte>& value) const {
    auto values = parseMultiString(value);
    if (!containsMultiString(value, kLsaModuleName)) {
        values.emplace_back(kLsaModuleName);
    }
    return serializeMultiString(values);
}

void WindowsAdapter::copyNativeDll(const std::filesystem::path& source, const std::filesystem::path& target) const {
    if (!fileExists(source)) {
        fail(L"Required build output is missing: " + source.wstring());
    }
    const auto status = environment();
    const auto sourceArchitecture = executableArchitecture(source);
    if (sourceArchitecture != status.nativeArchitecture) {
        fail(
            source.filename().wstring() + L" is " + architectureName(sourceArchitecture) +
            L", but Windows is " + architectureName(status.nativeArchitecture) + L". Rebuild before installing."
        );
    }
    if (fileExists(target)) {
        fail(L"Refusing to overwrite an existing system DLL: " + target.wstring());
    }

    const auto sourceHandle = CreateFileW(
        source.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    if (sourceHandle == INVALID_HANDLE_VALUE) {
        fail(L"Could not open " + source.wstring() + L": " + win32ErrorMessage(GetLastError()));
    }
    ScopedHandle sourceFile(sourceHandle);

    const auto targetHandle = CreateFileW(
        target.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    if (targetHandle == INVALID_HANDLE_VALUE) {
        fail(L"Could not create " + target.wstring() + L": " + win32ErrorMessage(GetLastError()));
    }
    ScopedHandle targetFile(targetHandle);

    std::vector<std::byte> buffer(1024 * 1024);
    while (true) {
        DWORD bytesRead = 0;
        checkWin32(ReadFile(sourceFile.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr),
            L"Could not read " + source.wstring());
        if (bytesRead == 0) {
            break;
        }
        DWORD bytesWrittenTotal = 0;
        while (bytesWrittenTotal < bytesRead) {
            DWORD bytesWritten = 0;
            checkWin32(
                WriteFile(
                    targetFile.get(),
                    buffer.data() + bytesWrittenTotal,
                    bytesRead - bytesWrittenTotal,
                    &bytesWritten,
                    nullptr
                ),
                L"Could not write " + target.wstring()
            );
            if (bytesWritten == 0) {
                fail(L"Could not write " + target.wstring() + L": no bytes were written.");
            }
            bytesWrittenTotal += bytesWritten;
        }
    }
    checkWin32(FlushFileBuffers(targetFile.get()), L"Could not flush " + target.wstring());
}

void WindowsAdapter::deleteDllIfPresent(const std::filesystem::path& target) const {
    if (!fileExists(target)) {
        return;
    }
    checkWin32(DeleteFileW(target.c_str()), L"Could not remove " + target.wstring());
}

void WindowsAdapter::createCredentialProviderRegistration(const std::filesystem::path& target) const {
    writeRegistryString(HKEY_LOCAL_MACHINE, kCredentialProviderRegistryPath, nullptr, kCredentialProviderName);
    writeRegistryString(HKEY_LOCAL_MACHINE, kCredentialProviderClsidRegistryPath, nullptr, kCredentialProviderName);
    const auto inprocPath = std::wstring(kCredentialProviderClsidRegistryPath) + L"\\InprocServer32";
    writeRegistryString(HKEY_LOCAL_MACHINE, inprocPath.c_str(), nullptr, target.wstring());
    writeRegistryString(HKEY_LOCAL_MACHINE, inprocPath.c_str(), L"ThreadingModel", L"Apartment");
}

void WindowsAdapter::removeCredentialProviderRegistration() const {
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kCredentialProviderRegistryPath);
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kCredentialProviderClsidRegistryPath);
}

bool WindowsAdapter::continuationTaskExists() const {
    ScopedCom com;
    if (FAILED(com.result()) && com.result() != RPC_E_CHANGED_MODE) {
        fail(L"Could not initialize COM for Task Scheduler.");
    }
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

void WindowsAdapter::registerContinuationTask(const WizardState& state) const {
    ScopedCom com;
    if (FAILED(com.result()) && com.result() != RPC_E_CHANGED_MODE) {
        fail(L"Could not initialize COM for Task Scheduler.");
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
    checkHresult(trigger->put_Enabled(VARIANT_TRUE), L"Could not enable the continuation logon trigger");

    ComPtr<IActionCollection> actions;
    checkHresult(definition->get_Actions(&actions), L"Could not configure the continuation task action");
    ComPtr<IAction> action;
    checkHresult(actions->Create(TASK_ACTION_EXEC, &action), L"Could not create the continuation task action");
    ComPtr<IExecAction> execution;
    checkHresult(action.As(&execution), L"Could not configure the continuation executable action");
    const auto executablePath = state.wizardPath.empty() ? wizardPath_ : std::filesystem::path(state.wizardPath);
    ScopedBstr path(executablePath.wstring());
    ScopedBstr arguments(L"--resume-uninstall");
    checkHresult(execution->put_Path(path.get()), L"Could not set the continuation executable path");
    checkHresult(execution->put_Arguments(arguments.get()), L"Could not set the continuation executable arguments");

    ComPtr<ITaskSettings> settings;
    checkHresult(definition->get_Settings(&settings), L"Could not configure the continuation task settings");
    checkHresult(settings->put_StartWhenAvailable(VARIANT_TRUE), L"Could not set continuation task availability");
    checkHresult(
        settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE),
        L"Could not allow the continuation task to start on battery power"
    );
    checkHresult(
        settings->put_StopIfGoingOnBatteries(VARIANT_FALSE),
        L"Could not keep the continuation task running on battery power"
    );

    ScopedBstr taskName(kFinalizeTaskName);
    ScopedVariant user(userName);
    ScopedVariant empty;
    ComPtr<IRegisteredTask> registeredTask;
    checkHresult(
        root->RegisterTaskDefinition(
            taskName.get(),
            definition.Get(),
            TASK_CREATE_OR_UPDATE,
            user.get(),
            empty.get(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            empty.get(),
            &registeredTask
        ),
        L"Could not register the uninstall continuation task"
    );
}

void WindowsAdapter::removeContinuationTask() const {
    ScopedCom com;
    if (FAILED(com.result()) && com.result() != RPC_E_CHANGED_MODE) {
        fail(L"Could not initialize COM for Task Scheduler.");
    }
    auto service = taskSchedulerService();
    auto root = taskRootFolder(service.Get());
    ScopedBstr taskName(kFinalizeTaskName);
    const auto result = root->DeleteTask(taskName.get(), 0);
    if (FAILED(result) && result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        checkHresult(result, L"Could not remove the uninstall continuation task");
    }
}

ComponentSnapshot WindowsAdapter::inspect() const {
    ComponentSnapshot snapshot;
    try {
        const auto state = readState();
        snapshot.statePresent = state.has_value();
        if (state) {
            snapshot.statePhase = state->phase;
            snapshot.stateLastError = state->lastError;
            snapshot.stateValid = isKnownPhase(static_cast<DWORD>(state->phase)) &&
                state->schemaVersion == 2;
            if (!snapshot.stateValid) {
                snapshot.stateError = L"The saved transaction state has an unsupported schema or phase.";
            }
        }
    } catch (const ComponentError& error) {
        snapshot.statePresent = true;
        snapshot.stateValid = false;
        snapshot.stateError = error.wideWhat();
    }

    try {
        snapshot.credentialProviderDllPresent = fileExists(credentialProviderTarget());
        snapshot.lsaDllPresent = fileExists(lsaTarget());
        snapshot.credentialProviderRegistered = registryKeyExists(kCredentialProviderRegistryPath);
        snapshot.credentialProviderClsidRegistered = registryKeyExists(kCredentialProviderClsidRegistryPath);
        snapshot.lsaPackageRegistered = containsMultiString(readAuthenticationPackages(), kLsaModuleName);
        snapshot.continuationTaskPresent = continuationTaskExists();
    } catch (const ComponentError& error) {
        snapshot.observationValid = false;
        snapshot.observationError = error.wideWhat();
    }
    return snapshot;
}

std::wstring WindowsAdapter::queryLsaPackage() const {
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

void WindowsAdapter::restartWindows() const {
    const auto result = ShellExecuteW(nullptr, L"open", L"shutdown.exe", L"/r /t 0", nullptr, SW_HIDE);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        fail(L"Could not request a restart.");
    }
}

} // namespace unlock::components
