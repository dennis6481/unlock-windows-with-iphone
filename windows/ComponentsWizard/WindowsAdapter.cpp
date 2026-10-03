// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE
#define SECURITY_WIN32

#include "WindowsAdapter.h"
#include "SavedCredentialIpc.h"

#include <Windows.h>
#include <security.h>
#include <shellapi.h>
#include <sddl.h>

#include <array>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <utility>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace unlock::components {
namespace {

constexpr wchar_t kCredentialProviderName[] = L"Unlock Windows with iPhone\u00ae";
constexpr wchar_t kCredentialProviderRegistryPath[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\"
    L"{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}";
constexpr wchar_t kCredentialProviderClsidRegistryPath[] =
    L"SOFTWARE\\Classes\\CLSID\\{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}";
constexpr wchar_t kWizardStateRegistryPath[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\ComponentsWizard";
constexpr wchar_t kSchemaVersionValueName[] = L"SchemaVersion";
constexpr wchar_t kStatePhaseValueName[] = L"Phase";
constexpr wchar_t kStateTransactionIdValueName[] = L"TransactionId";
constexpr wchar_t kStateWizardPathValueName[] = L"WizardPath";
constexpr wchar_t kStateCreatedAtValueName[] = L"CreatedAtUtc";
constexpr wchar_t kStateLastErrorValueName[] = L"LastError";
constexpr wchar_t kCredentialCleanupValueName[] = L"CredentialCleanupConfirmed";
constexpr wchar_t kUpdateRebootGuard[] = L"SOFTWARE\\UnlockWindowsWithIPhone\\ComponentsWizard\\UpdateRebootGuard";

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

class ScopedServiceHandle final {
public:
    explicit ScopedServiceHandle(SC_HANDLE handle) : handle_(handle) {}
    ScopedServiceHandle(const ScopedServiceHandle&) = delete;
    ScopedServiceHandle& operator=(const ScopedServiceHandle&) = delete;
    ~ScopedServiceHandle() { close(); }
    [[nodiscard]] SC_HANDLE get() const noexcept { return handle_; }
    void close() noexcept {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
            handle_ = nullptr;
        }
    }
private:
    SC_HANDLE handle_ = nullptr;
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

bool isKnownPhase(const DWORD phase) {
    return phase <= static_cast<DWORD>(WizardPhase::installPendingReboot);
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
    const bool present = std::filesystem::exists(path, error);
    if (error) fail(L"Could not inspect component path: " + path.wstring());
    if (!present) return false;
    const bool regular = std::filesystem::is_regular_file(path, error);
    if (error || !regular) fail(L"Component path is not a regular file: " + path.wstring());
    return true;
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

void WindowsAdapter::setOperationLog(std::function<void(const std::wstring&)> listener) {
    operationLog_ = std::move(listener);
}
void WindowsAdapter::logOperation(const std::wstring& message) const {
    if (operationLog_) operationLog_(message);
}

const std::filesystem::path& WindowsAdapter::wizardPath() const noexcept {
    return wizardPath_;
}

std::filesystem::path WindowsAdapter::credentialProviderTarget() const {
    return system32Directory() / kCredentialProviderFile;
}

std::filesystem::path WindowsAdapter::savedCredentialServiceTarget() const {
    return system32Directory() / kSavedCredentialServiceFile;
}

EnvironmentStatus WindowsAdapter::environment() const {
    EnvironmentStatus result;
    result.elevated = isElevated();
    result.nativeArchitecture = nativeArchitecture();
    result.wizardArchitecture = executableArchitecture(wizardPath_);
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
    state.targetSid = readRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, L"TargetSid").value_or(L"");
    state.credentialCleanupConfirmed = readRegistryDword(
        HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kCredentialCleanupValueName).value_or(0) == 1;
    if (state.schemaVersion != kWizardStateSchemaVersion || !isKnownPhase(*phase) || state.targetSid.empty())
        fail(L"Unsupported or incomplete installation record. No migration will run.");
    PSID target = nullptr;
    if (!ConvertStringSidToSidW(state.targetSid.c_str(), &target))
        fail(L"The recorded startup account SID is invalid.");
    const bool valid = IsValidSid(target) != FALSE;
    LocalFree(target);
    if (!valid) fail(L"The recorded startup account SID is invalid.");
    return state;
}

void WindowsAdapter::writeState(const WizardState& state) const {
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, L"TargetSid", state.targetSid);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kSchemaVersionValueName, state.schemaVersion);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateTransactionIdValueName, state.transactionId);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateWizardPathValueName, state.wizardPath);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateCreatedAtValueName, state.createdAtUtc);
    writeRegistryString(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStateLastErrorValueName, state.lastError);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath,
        kCredentialCleanupValueName, state.credentialCleanupConfirmed ? 1 : 0);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath, kStatePhaseValueName, static_cast<DWORD>(state.phase));
}

void WindowsAdapter::clearState() const {
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kWizardStateRegistryPath);
}

void WindowsAdapter::copyNativeBinary(const std::filesystem::path& source, const std::filesystem::path& target,
    const bool replace) const {
    logOperation(L"Copy: " + source.wstring() + L" -> " + target.wstring());
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
    if (!replace && fileExists(target)) {
        fail(L"Refusing to overwrite an existing system binary: " + target.wstring());
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
        replace ? CREATE_ALWAYS : CREATE_NEW,
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

std::filesystem::path WindowsAdapter::updateDirectory(const WizardState& state) const {
    if (state.transactionId.empty() || state.transactionId.find_first_not_of(L"0123456789-") != std::wstring::npos) {
        fail(L"The update transaction identifier is invalid.");
    }
    return system32Directory() / (L"UnlockWindowsUpdate-" + state.transactionId);
}

bool WindowsAdapter::updateRebootRequired() const {
    return registryKeyExists(kUpdateRebootGuard);
}

void WindowsAdapter::markUpdateRequiresReboot() const {
    HKEY key = nullptr;
    const auto result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kUpdateRebootGuard, 0, nullptr,
        REG_OPTION_VOLATILE, KEY_READ | KEY_WOW64_64KEY, nullptr, &key, nullptr);
    if (result != ERROR_SUCCESS) fail(L"Could not establish update reboot boundary: " + win32ErrorMessage(result));
    ScopedRegistryKey guard(key);
}

void WindowsAdapter::stageUpdate(WizardState& state) const {
    const auto native = environment().nativeArchitecture;
    for (const auto& component : kComponentFiles) {
        const auto source = wcscmp(component.name, kInstallerFile) == 0 ? wizardPath_ : wizardPath_.parent_path() / component.buildName;
        if (!fileExists(source) || executableArchitecture(source) != native)
            fail(L"Missing or wrong-architecture precompiled component: " + source.wstring());
    }
    const auto directory = updateDirectory(state);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    checkWin32(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1,
        &descriptor, nullptr), L"Could not configure protected staging ACL");
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    const BOOL created = CreateDirectoryW(directory.c_str(), &security);
    const DWORD error = GetLastError(); LocalFree(descriptor); SetLastError(error);
    checkWin32(created, L"Could not create protected update staging directory");
    logOperation(L"Create protected staging directory: " + directory.wstring());
    for (const auto& component : kComponentFiles) {
        const auto source = wcscmp(component.name, kInstallerFile) == 0 ? wizardPath_ : wizardPath_.parent_path() / component.buildName;
        copyNativeBinary(source, directory / component.name);
    }
    state.wizardPath = (directory / kInstallerFile).wstring();
}

void WindowsAdapter::stageContinuation(WizardState& state) const {
    const auto directory = updateDirectory(state);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    checkWin32(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1,
        &descriptor, nullptr), L"Could not configure continuation ACL");
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    const BOOL created = CreateDirectoryW(directory.c_str(), &security);
    const DWORD error = GetLastError(); LocalFree(descriptor); SetLastError(error);
    checkWin32(created, L"Could not create protected continuation directory");
    logOperation(L"Create protected continuation directory: " + directory.wstring());
    const auto wizard = directory / kInstallerFile;
    copyNativeBinary(wizardPath_, wizard);
    state.wizardPath = wizard.wstring();
}

void WindowsAdapter::applyStagedUpdate(const WizardState& state) const {
    const auto directory = updateDirectory(state);
    const auto attributes = GetFileAttributesW(directory.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        std::filesystem::path(state.wizardPath) != directory / kInstallerFile) {
        fail(L"The protected update staging location is invalid.");
    }
    for (const auto& component : kComponentFiles) {
        const auto source = directory / component.name;
        const auto target = system32Directory() / component.name;
        auto temporary = target;
        temporary += L".update";
        copyNativeBinary(source, temporary, true);
        checkWin32(MoveFileExW(temporary.c_str(), target.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH), L"Could not replace " + target.wstring());
        logOperation(L"Replace and verify: " + target.wstring());
        std::ifstream expected(source, std::ios::binary), actual(target, std::ios::binary);
        if (!expected || !actual) fail(L"Could not verify updated binary " + target.wstring());
        std::array<char, 65536> left{}, right{};
        do {
            expected.read(left.data(), static_cast<std::streamsize>(left.size()));
            actual.read(right.data(), static_cast<std::streamsize>(right.size()));
            if (expected.bad() || actual.bad() || (expected.fail() && !expected.eof()) ||
                (actual.fail() && !actual.eof()) || expected.gcount() != actual.gcount() ||
                std::memcmp(left.data(), right.data(), static_cast<size_t>(expected.gcount())) != 0) {
                fail(L"Updated binary verification failed: " + target.wstring());
            }
        } while (expected.gcount() != 0);
    }
}

void WindowsAdapter::configureSavedCredentialServiceForUpdate(const bool suspend) const {
    ScopedServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) fail(L"Could not open the Service Control Manager: " + win32ErrorMessage(GetLastError()));
    ScopedServiceHandle service(OpenServiceW(manager.get(), unlock_windows::saved_credential::kServiceName,
        SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START));
    if (!service.get()) fail(L"Could not open the installed service: " + win32ErrorMessage(GetLastError()));
    DWORD bytes = 0;
    QueryServiceConfigW(service.get(), nullptr, 0, &bytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(QUERY_SERVICE_CONFIGW)) {
        fail(L"Could not inspect the service before updating.");
    }
    std::vector<std::byte> configuration(bytes);
    checkWin32(QueryServiceConfigW(service.get(), reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configuration.data()),
        bytes, &bytes), L"Could not read installed service configuration");
    const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(configuration.data());
    const auto command = L"\"" + savedCredentialServiceTarget().wstring() + L"\"";
    if (!config->lpBinaryPathName || _wcsicmp(config->lpBinaryPathName, command.c_str()) != 0 ||
        !config->lpServiceStartName || _wcsicmp(config->lpServiceStartName, L"LocalSystem") != 0 ||
        config->dwServiceType != SERVICE_WIN32_OWN_PROCESS) {
        fail(L"Refusing to update a service not owned by this installation.");
    }
    checkWin32(ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE,
        suspend ? SERVICE_DISABLED : SERVICE_AUTO_START, SERVICE_NO_CHANGE,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr), L"Could not configure service startup for update");
    SERVICE_STATUS_PROCESS status{};
    checkWin32(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes), L"Could not query installed service");
    if (suspend && status.dwCurrentState != SERVICE_STOPPED) {
        SERVICE_STATUS ignored{};
        if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &ignored) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            fail(L"Could not stop installed service: " + win32ErrorMessage(GetLastError()));
        }
    } else if (!suspend && status.dwCurrentState == SERVICE_STOPPED) {
        checkWin32(StartServiceW(service.get(), 0, nullptr), L"Could not start updated service");
    }
    for (int attempt = 0; attempt < 100; ++attempt) {
        checkWin32(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes), L"Could not verify installed service state");
        if (status.dwCurrentState == (suspend ? SERVICE_STOPPED : SERVICE_RUNNING)) return;
        Sleep(100);
    }
    fail(L"Installed service did not reach the expected state within 10 seconds.");
}

void WindowsAdapter::deleteBinaryIfPresent(const std::filesystem::path& target) const {
    logOperation(L"Delete: " + target.wstring());
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

void WindowsAdapter::createSavedCredentialService() const {
    ScopedServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (manager.get() == nullptr) fail(L"Could not open the Service Control Manager: " + win32ErrorMessage(GetLastError()));
    const auto target = savedCredentialServiceTarget();
    const auto command = L"\"" + target.wstring() + L"\"";
    ScopedServiceHandle service(CreateServiceW(manager.get(),
        unlock_windows::saved_credential::kServiceName,
        L"Unlock Windows saved credential",
        SERVICE_START | SERVICE_QUERY_STATUS | DELETE,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        command.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr));
    if (service.get() == nullptr) fail(L"Could not register the saved credential service: " + win32ErrorMessage(GetLastError()));
    checkWin32(StartServiceW(service.get(), 0, nullptr), L"Could not start the saved credential service");
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    for (int attempt = 0; attempt < 100; ++attempt) {
        checkWin32(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes),
            L"Could not query the saved credential service");
        if (status.dwCurrentState == SERVICE_RUNNING) return;
        if (status.dwCurrentState == SERVICE_STOPPED) {
            fail(L"The saved credential service stopped before reaching Running.");
        }
        Sleep(100);
    }
    fail(L"The saved credential service did not reach Running within 10 seconds.");
}

void WindowsAdapter::removeSavedCredentialService() const {
    ScopedServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (manager.get() == nullptr) fail(L"Could not open the Service Control Manager: " + win32ErrorMessage(GetLastError()));
    ScopedServiceHandle service(OpenServiceW(manager.get(), unlock_windows::saved_credential::kServiceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | DELETE));
    if (service.get() == nullptr) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) return;
        fail(L"Could not open the saved credential service: " + win32ErrorMessage(GetLastError()));
    }
    DWORD configurationBytes = 0;
    QueryServiceConfigW(service.get(), nullptr, 0, &configurationBytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || configurationBytes < sizeof(QUERY_SERVICE_CONFIGW)) {
        fail(L"Could not inspect the saved credential service configuration.");
    }
    std::vector<std::byte> configuration(configurationBytes);
    if (!QueryServiceConfigW(service.get(),
            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configuration.data()),
            configurationBytes, &configurationBytes)) {
        fail(L"Could not read the saved credential service configuration.");
    }
    const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(configuration.data());
    const auto expectedCommand = L"\"" + savedCredentialServiceTarget().wstring() + L"\"";
    if (config->lpBinaryPathName == nullptr || _wcsicmp(config->lpBinaryPathName, expectedCommand.c_str()) != 0 ||
        config->lpServiceStartName == nullptr || _wcsicmp(config->lpServiceStartName, L"LocalSystem") != 0 ||
        config->dwServiceType != SERVICE_WIN32_OWN_PROCESS) {
        fail(L"Refusing to remove a service whose executable, account, or type differs from this installation.");
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    checkWin32(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes),
        L"Could not query the saved credential service");
    if (status.dwCurrentState != SERVICE_STOPPED) {
        SERVICE_STATUS ignored{};
        if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &ignored) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            fail(L"Could not stop the saved credential service: " + win32ErrorMessage(GetLastError()));
        }
        for (int attempt = 0; attempt < 100; ++attempt) {
            checkWin32(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes),
                L"Could not query the saved credential service after stop");
            if (status.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(100);
        }
        if (status.dwCurrentState != SERVICE_STOPPED) fail(L"The saved credential service did not stop within 10 seconds.");
    }
    checkWin32(DeleteService(service.get()), L"Could not remove the saved credential service registration");
    service.close();
    for (int attempt = 0; attempt < 100; ++attempt) {
        ScopedServiceHandle remainingService(OpenServiceW(manager.get(),
            unlock_windows::saved_credential::kServiceName, SERVICE_QUERY_STATUS));
        if (remainingService.get() == nullptr && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) return;
        Sleep(100);
    }
    fail(L"The saved credential service registration was not removed within 10 seconds.");
}

void WindowsAdapter::clearSavedCredential() const {
    unlock_windows::saved_credential::Packet reply;
    if (!unlock_windows::saved_credential::call(
            unlock_windows::saved_credential::Operation::clearForRemoval,
            unlock_windows::saved_credential::SensitiveBytes{}, reply) ||
        reply.result != unlock_windows::saved_credential::Result::success) {
        fail(L"The saved credential service did not confirm deletion. Component removal is paused.");
    }
}

ComponentSnapshot WindowsAdapter::inspect() const {
    ComponentSnapshot snapshot;
    try {
        const auto state = readState();
        snapshot.statePresent = state.has_value();
        if (state) {
            snapshot.targetSid = state->targetSid;
            snapshot.stateValid = true;
        }
    } catch (const ComponentError& error) {
        snapshot.statePresent = true;
        snapshot.stateValid = false;
        snapshot.stateError = error.wideWhat();
    }

    try {
        snapshot.credentialProviderDllPresent = fileExists(credentialProviderTarget());
        snapshot.savedCredentialServiceExePresent = fileExists(savedCredentialServiceTarget());
        snapshot.credentialProviderRegistered = registryKeyExists(kCredentialProviderRegistryPath);
        snapshot.credentialProviderClsidRegistered = registryKeyExists(kCredentialProviderClsidRegistryPath);
        ScopedServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (manager.get() == nullptr) fail(L"Could not inspect the Service Control Manager.");
        ScopedServiceHandle service(OpenServiceW(manager.get(),
            unlock_windows::saved_credential::kServiceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
        if (service.get() != nullptr) {
            snapshot.savedCredentialServiceRegistered = true;
            DWORD configurationBytes = 0;
            QueryServiceConfigW(service.get(), nullptr, 0, &configurationBytes);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
                configurationBytes < sizeof(QUERY_SERVICE_CONFIGW)) {
                fail(L"Could not inspect the saved credential service configuration.");
            }
            std::vector<std::byte> configuration(configurationBytes);
            checkWin32(QueryServiceConfigW(service.get(),
                reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configuration.data()),
                configurationBytes, &configurationBytes),
                L"Could not read the saved credential service configuration");
            const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(configuration.data());
            const auto expectedCommand = L"\"" + savedCredentialServiceTarget().wstring() + L"\"";
            snapshot.savedCredentialServiceMatchesInstallation =
                config->lpBinaryPathName != nullptr &&
                _wcsicmp(config->lpBinaryPathName, expectedCommand.c_str()) == 0 &&
                config->lpServiceStartName != nullptr &&
                _wcsicmp(config->lpServiceStartName, L"LocalSystem") == 0 &&
                config->dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
                config->dwStartType == SERVICE_AUTO_START;
            SERVICE_STATUS_PROCESS status{};
            DWORD bytes = 0;
            checkWin32(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes),
                L"Could not inspect the saved credential service state");
            snapshot.savedCredentialServiceRunning = status.dwCurrentState == SERVICE_RUNNING;
        } else if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
            fail(L"Could not inspect the saved credential service registration.");
        }
        snapshot.continuationTaskPresent = continuationTaskExists();
        snapshot.userStartupPresent = userStartupPresent();
        snapshot.toolsPresent = toolsPresent();
        snapshot.desktopArtifactsPresent = desktopArtifactsPresent();
        snapshot.shortcutsPresent = shortcutsPresent();
        snapshot.trayRunning = trayRunning();
    } catch (const ComponentError& error) {
        snapshot.observationValid = false;
        snapshot.observationError = error.wideWhat();
    }
    return snapshot;
}

void WindowsAdapter::restartWindows() const {
    const auto result = ShellExecuteW(nullptr, L"open", L"shutdown.exe", L"/r /t 0", nullptr, SW_HIDE);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        fail(L"Could not request a restart.");
    }
}

} // namespace unlock::components
