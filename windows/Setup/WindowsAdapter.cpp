// Created by Rui MA on 28 Sep 2026
// Native Windows mechanisms; package/state/task ownership belongs to their dedicated modules.

#define UNICODE
#define _UNICODE
#define SECURITY_WIN32

#include "../Resources/resource.h"
#include "WindowsAdapter.h"
#include "SetupPlatform.h"
#include "SavedCredentialIpc.h"
#include "../GattHost/GattController.h"
#include "../CredentialProvider/UnlockCredentialProvider.h"
#include "../Protocol/UnlockCrypto.h"

#include <Windows.h>
#include "PackageManifest.h"
#include <aclapi.h>
#include <shlobj.h>
#include <winver.h>
#include <security.h>
#include <shellapi.h>
#include <sddl.h>

#include <array>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <span>
#include <set>
#include <utility>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace unlock::components {
namespace {
const std::wstring kCredentialProviderClsidText = [] {
    std::array<wchar_t, 39> text{};
    if (!StringFromGUID2(unlock_windows::credential_provider::kUnlockCredentialProviderClsid,
            text.data(), static_cast<int>(text.size())))
        throw ComponentError(L"Cannot format Credential Provider CLSID.");
    return std::wstring(text.data());
}();
const std::wstring kCredentialProviderRegistryPath =
    std::wstring(kCredentialProviderRegistryRoot) + L"\\" + kCredentialProviderClsidText;
const std::wstring kCredentialProviderClsidRegistryPath =
    std::wstring(kClsidRegistryRoot) + L"\\" + kCredentialProviderClsidText;

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

}
void WindowsAdapter::ensureProtectedDirectory(const std::filesystem::path& path, bool create) const {
    if (create) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        checkWin32(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1,
            &descriptor, nullptr), L"Create deployment directory security");
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        const BOOL made = CreateDirectoryW(path.c_str(), &security);
        const DWORD error = GetLastError(); LocalFree(descriptor);
        if (!made && error != ERROR_ALREADY_EXISTS) fail(L"Could not create " + path.wstring() + L": " + win32ErrorMessage(error));
    }
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) fail(L"Unsafe deployment directory: " + path.wstring());
    PSECURITY_DESCRIPTOR raw = nullptr; PACL acl = nullptr; PSID owner = nullptr;
    const DWORD result = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &raw);
    if (result != ERROR_SUCCESS) fail(L"Cannot inspect deployment ACL: " + win32ErrorMessage(result));
    struct Descriptor { PSECURITY_DESCRIPTOR p; ~Descriptor() { LocalFree(p); } } descriptor{raw};
    BYTE system[SECURITY_MAX_SID_SIZE]{}, administrators[SECURITY_MAX_SID_SIZE]{};
    DWORD systemSize = sizeof(system), adminSize = sizeof(administrators);
    checkWin32(CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemSize), L"Resolve SYSTEM SID");
    checkWin32(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &adminSize), L"Resolve administrator SID");
    if (!acl || !owner || (!EqualSid(owner, system) && !EqualSid(owner, administrators)))
        fail(L"Deployment directory is not administrator-owned: " + path.wstring());
    constexpr DWORD writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        LPVOID entry = nullptr; checkWin32(GetAce(acl, i, &entry), L"Read deployment ACL entry");
        const auto header = static_cast<ACE_HEADER*>(entry);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) fail(L"Unsupported deployment ACL entry.");
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
        if ((ace->Mask & writes) && !EqualSid(&ace->SidStart, system) && !EqualSid(&ace->SidStart, administrators))
            fail(L"Deployment directory is writable by another identity: " + path.wstring());
    }
}

namespace {
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

}
Architecture WindowsAdapter::executableArchitecture(const std::filesystem::path& path) const {
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

namespace {
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

std::filesystem::path WindowsAdapter::componentTarget(const ComponentFile& component) const {
    const std::filesystem::path relative(component.name);
    if (!isPackageRelativePath(component.name))
        fail(L"Invalid package relative path.");
    if (!component.desktopTool && relative.has_parent_path()) fail(L"System component must have a simple filename.");
    if (component.desktopTool && std::filesystem::exists(desktopDirectory())) {
        auto parent = desktopDirectory();
        ensureProtectedDirectory(parent, false);
        for (const auto& part : relative.parent_path()) {
            parent /= part;
            if (!std::filesystem::exists(parent)) break;
            ensureProtectedDirectory(parent, false);
        }
    }
    return (component.desktopTool ? desktopDirectory() : system32Directory()) / component.name;
}
ProductVersion WindowsAdapter::binaryVersion(const std::filesystem::path& file) const {
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(file.c_str(), &ignored);
    if (!size) fail(L"Missing product version: " + file.wstring());
    std::vector<BYTE> data(size);
    checkWin32(GetFileVersionInfoW(file.c_str(), 0, size, data.data()), L"Read component product version");
    VS_FIXEDFILEINFO* info = nullptr; UINT bytes = 0;
    checkWin32(VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &bytes), L"Read fixed product version");
    if (bytes < sizeof(*info) || info->dwSignature != 0xFEEF04BD || LOWORD(info->dwProductVersionLS) != 0 ||
        info->dwProductVersionMS != info->dwFileVersionMS || info->dwProductVersionLS != info->dwFileVersionLS)
        fail(L"Invalid or inconsistent component version: " + file.wstring());
    return {HIWORD(info->dwProductVersionMS), LOWORD(info->dwProductVersionMS), HIWORD(info->dwProductVersionLS)};
}
void WindowsAdapter::ensureDeploymentDirectories() const {
    ensureProtectedDirectory(desktopDirectory(), true);
    for (const auto& path : {productDataDirectory(), productDataDirectory() / kSetupDirectoryName, transactionRoot()})
        ensureProtectedDirectory(path, true);
}

EnvironmentStatus WindowsAdapter::environment() const {
    EnvironmentStatus result;
    result.elevated = isElevated();
    result.nativeArchitecture = nativeArchitecture();
    result.wizardArchitecture = executableArchitecture(wizardPath_);
    return result;
}

void WindowsAdapter::assertSupportedAdministratorEnvironment() const {
    OSVERSIONINFOEXW version{sizeof(version)};
    version.dwMajorVersion = 10;
    version.dwBuildNumber = kMinimumWindowsBuild;
    const auto mask = VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL),
        VER_BUILDNUMBER, VER_GREATER_EQUAL);
    if (!VerifyVersionInfoW(&version, VER_MAJORVERSION | VER_BUILDNUMBER, mask)) {
        if (GetLastError() != ERROR_OLD_WIN_VERSION) fail(L"Could not verify the minimum Windows version.");
        fail(L"Windows 10 version 1809 or later is required.");
    }
    const auto status = environment();
    if (!status.elevated) {
        fail(L"Run Windows Setup as an administrator.");
    }
    if (status.nativeArchitecture != Architecture::x64 && status.nativeArchitecture != Architecture::arm64) {
        fail(L"Only x64 and ARM64 Windows are supported.");
    }
    if (status.wizardArchitecture != status.nativeArchitecture) {
        fail(
            L"This installer is " + std::wstring(architectureName(status.wizardArchitecture)) +
            L", but Windows is " + architectureName(status.nativeArchitecture) + L". Rebuild the installer for the native architecture."
        );
    }
}

void WindowsAdapter::registerApplicationUninstall(const std::filesystem::path& executable, const std::wstring& version) const {
    const auto command = L"\"" + executable.wstring() + L"\" --uninstall";
    const auto icon = L"\"" + executable.wstring() + L"\",0";
    const std::array<std::pair<const wchar_t*, std::wstring>, 6> values{{
        {kUninstallStringValueName, command},
        {kDisplayIconValueName, icon},
        {L"Publisher", L"Rui MA"},
        {L"InstallLocation", desktopDirectory().wstring()},
        {kDisplayVersionValueName, version},
        {L"DisplayName", UNLOCK_PRODUCT_DISPLAY_NAME},
    }};
    logOperation(L"Register Installed apps uninstall entry: " + command);
    for (const auto& value : values)
        writeRegistryString(HKEY_LOCAL_MACHINE, kApplicationUninstallRegistryPath, value.first, value.second);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kApplicationUninstallRegistryPath, L"NoModify", 1);
    writeRegistryDword(HKEY_LOCAL_MACHINE, kApplicationUninstallRegistryPath, L"NoRepair", 1);
    for (const auto& value : values) {
        if (readRegistryString(HKEY_LOCAL_MACHINE, kApplicationUninstallRegistryPath, value.first) != value.second)
            fail(L"Installed apps registration verification failed: " + std::wstring(value.first));
    }
    if (readRegistryDword(HKEY_LOCAL_MACHINE, kApplicationUninstallRegistryPath, L"NoModify") != 1 ||
        readRegistryDword(HKEY_LOCAL_MACHINE, kApplicationUninstallRegistryPath, L"NoRepair") != 1)
        fail(L"Installed apps action registration verification failed.");
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

void WindowsAdapter::deleteFileIfPresent(const std::filesystem::path& target) const {
    logOperation(L"Delete: " + target.wstring());
    if (!fileExists(target)) {
        return;
    }
    checkWin32(DeleteFileW(target.c_str()), L"Could not remove " + target.wstring());
}

void WindowsAdapter::createCredentialProviderRegistration(const std::filesystem::path& target) const {
    writeRegistryString(HKEY_LOCAL_MACHINE, kCredentialProviderRegistryPath.c_str(), nullptr, UNLOCK_PRODUCT_DISPLAY_NAME);
    writeRegistryString(HKEY_LOCAL_MACHINE, kCredentialProviderClsidRegistryPath.c_str(), nullptr, UNLOCK_PRODUCT_DISPLAY_NAME);
    const auto inprocPath = std::wstring(kCredentialProviderClsidRegistryPath.c_str()) + L"\\InprocServer32";
    writeRegistryString(HKEY_LOCAL_MACHINE, inprocPath.c_str(), nullptr, target.wstring());
    writeRegistryString(HKEY_LOCAL_MACHINE, inprocPath.c_str(), L"ThreadingModel", L"Apartment");
}

void WindowsAdapter::removeCredentialProviderRegistration() const {
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kCredentialProviderRegistryPath.c_str());
    deleteRegistryTree(HKEY_LOCAL_MACHINE, kCredentialProviderClsidRegistryPath.c_str());
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

ComponentSnapshot WindowsAdapter::inspectSystemComponents() const {
    ComponentSnapshot snapshot;
    try {
        snapshot.credentialProviderDllPresent = fileExists(credentialProviderTarget());
        snapshot.savedCredentialServiceExePresent = fileExists(savedCredentialServiceTarget());
        snapshot.credentialProviderRegistered = registryKeyExists(kCredentialProviderRegistryPath.c_str());
        snapshot.credentialProviderClsidRegistered = registryKeyExists(kCredentialProviderClsidRegistryPath.c_str());
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
        snapshot.applicationUninstallPresent = registryKeyExists(kApplicationUninstallRegistryPath);
    } catch (const ComponentError& error) {
        snapshot.observationValid = false;
        snapshot.observationError = error.wideWhat();
    }
    return snapshot;
}
void WindowsAdapter::removeProductData(const std::wstring& targetSid) const {
    ensureDeploymentDirectories();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    checkWin32(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1, &descriptor, nullptr), L"Protect enrollment removal lock");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    const HANDLE raw = CreateMutexW(&attributes, FALSE, unlock_windows::phone_approval::kEnrollmentWriterMutex);
    const DWORD error = GetLastError(); LocalFree(descriptor); SetLastError(error);
    ScopedHandle writer(raw); checkWin32(raw != nullptr, L"Open enrollment writer lock");
    const DWORD waited = WaitForSingleObject(raw, 0);
    if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED) throw ComponentError(L"Phone enrollment is being modified. Uninstall paused.");
    struct Lock { HANDLE h; ~Lock() { ReleaseMutex(h); } } lock{raw};
    const auto directory = productDataDirectory();
    if (std::filesystem::exists(directory)) {
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            const auto name = entry.path().filename().wstring();
            const std::wstring prefix = std::wstring(unlock_windows::phone_approval::kEnrollmentFileName) +
                unlock_windows::phone_approval::kEnrollmentPendingSuffix;
            const bool temporary = name.size() == prefix.size() + 32 && name.starts_with(prefix) &&
                name.find_first_not_of(L"0123456789abcdef", prefix.size()) == std::wstring::npos;
            if (name != unlock_windows::phone_approval::kEnrollmentFileName && !temporary) continue;
            const DWORD flags = GetFileAttributesW(entry.path().c_str());
            if (flags == INVALID_FILE_ATTRIBUTES || (flags & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                throw ComponentError(L"Unsafe enrollment file; removal paused.");
            deleteFileIfPresent(entry.path());
        }
    }
    withUserHive(targetSid, [](HKEY hive) {
        auto status = RegDeleteTreeW(hive, unlock_windows::desktop_app::kComputerIdentityRegistryPath);
        if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) checkRegistry(status, L"Remove target-user ComputerId");
        ScopedRegistryKey key;
        status = RegOpenKeyExW(hive, kProductRegistryPath, 0, KEY_READ, &key.value);
        if (status == ERROR_FILE_NOT_FOUND) return;
        checkRegistry(status, L"Inspect target-user product registry");
        DWORD subkeys = 0, values = 0;
        checkRegistry(RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
            &values, nullptr, nullptr, nullptr, nullptr), L"Inspect target-user remaining data");
        if (subkeys || values) throw ComponentError(L"Unknown target-user product registry data remains.");
        RegCloseKey(key.value); key.value = nullptr;
        checkRegistry(RegDeleteKeyW(hive, kProductRegistryPath), L"Remove empty target-user product key");
        checkRegistry(RegFlushKey(hive), L"Flush target-user data removal");
    });
}
void WindowsAdapter::restartWindows() const {
    const auto result = ShellExecuteW(nullptr, L"open", L"shutdown.exe", L"/r /t 0", nullptr, SW_HIDE);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        fail(L"Could not request a restart.");
    }
}

} // namespace unlock::components
