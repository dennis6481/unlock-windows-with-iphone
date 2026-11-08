// Read-only schema 5 recognition. No legacy deployment or continuation engine.
#include "LegacySchema5.h"
#include "../CredentialProvider/UnlockCredentialProvider.h"
#include "../SavedCredential/SavedCredentialIpc.h"
#include "../ProtectedStorage.h"
#include <fstream>
#include <winver.h>
#include <taskschd.h>
#include <wrl/client.h>

namespace unlock::components::msi {
std::wstring providerClsid() {
    wchar_t text[39]{};
    if (!StringFromGUID2(unlock_windows::credential_provider::kUnlockCredentialProviderClsid, text, 39))
        fail(L"Cannot format Credential Provider CLSID.");
    return text;
}
std::vector<std::wstring> deploymentRegistryKeys() {
    return {kInstalledProductRegistryPath, kLegacyUninstall, kLegacyResult,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" + providerClsid(),
        L"SOFTWARE\\Classes\\CLSID\\" + providerClsid()};
}
ProductVersion binaryVersion(const std::filesystem::path& path) {
    DWORD ignored = 0;
    const auto size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!size) fail(L"Missing binary version: " + path.wstring());
    std::vector<BYTE> data(size);
    checkWin32(GetFileVersionInfoW(path.c_str(), 0, size, data.data()), L"Read binary version");
    VS_FIXEDFILEINFO* info = nullptr; UINT bytes = 0;
    checkWin32(VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &bytes), L"Read fixed version");
    if (bytes < sizeof(*info) || info->dwSignature != 0xfeef04bd ||
        info->dwFileVersionMS != info->dwProductVersionMS || info->dwFileVersionLS != info->dwProductVersionLS)
        fail(L"Inconsistent product/file version: " + path.wstring());
    return {HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS),
        HIWORD(info->dwFileVersionLS), LOWORD(info->dwFileVersionLS)};
}
namespace {
std::vector<std::uint8_t> bytes(const std::filesystem::path& path) {
    if (!fileExists(path)) fail(L"Missing legacy deployment file: " + path.wstring());
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    const auto size = input.tellg();
    if (!input || size <= 0 || static_cast<std::uint64_t>(size) > MAXDWORD)
        fail(L"Cannot read legacy deployment file: " + path.wstring());
    std::vector<std::uint8_t> result(static_cast<size_t>(size));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(result.data()), size)) fail(L"Incomplete legacy file read.");
    return result;
}
WORD machine(std::span<const std::uint8_t> data) {
    if (data.size() < 2 || data[0] != 'M' || data[1] != 'Z') return 0;
    if (data.size() < 64) fail(L"Truncated PE header.");
    DWORD offset = 0, signature = 0; WORD result = 0;
    std::memcpy(&offset, data.data() + 60, 4);
    if (offset < 64 || offset > data.size() - 6) fail(L"Invalid PE offset.");
    std::memcpy(&signature, data.data() + offset, 4);
    std::memcpy(&result, data.data() + offset + 4, 2);
    if (signature != IMAGE_NT_SIGNATURE) fail(L"Invalid PE signature.");
    return result;
}
void rejectTasks() {
    ScopedComApartment apartment;
    Microsoft::WRL::ComPtr<ITaskService> scheduler;
    checkHresult(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&scheduler)), L"Inspect legacy continuation tasks");
    VARIANT empty{};
    checkHresult(scheduler->Connect(empty, empty, empty, empty), L"Connect scheduler");
    Microsoft::WRL::ComPtr<ITaskFolder> folder;
    auto root = SysAllocString(L"\\");
    const auto opened = scheduler->GetFolder(root, &folder); SysFreeString(root);
    checkHresult(opened, L"Open task folder");
    for (const auto name : {L"UnlockWindowsWithIPhone-CompleteOperation", L"UnlockWindowsWithIPhone-FinalizeOperation",
        L"UnlockWindowsWithIPhone-ComponentResult"}) {
        Microsoft::WRL::ComPtr<IRegisteredTask> task;
        auto text = SysAllocString(name); const auto result = folder->GetTask(text, &task); SysFreeString(text);
        if (SUCCEEDED(result)) fail(L"Legacy continuation or result delivery is pending. Use the original installer.");
        if (result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) checkHresult(result, L"Inspect legacy task");
    }
}
}
WORD binaryMachine(const std::filesystem::path& path) { return machine(bytes(path)); }
std::filesystem::path legacyTarget(const PackageFile& file) {
    return (file.desktopTool ? desktopDirectory() : system32Directory()) / file.name;
}
std::optional<LegacyInstallation> readLegacyInstallation() {
    if (registryKeyExists(kLegacyTransaction)) fail(L"An EXE installation transaction exists. Complete it with the original installer.");
    const bool record = registryKeyExists(kInstalledProductRegistryPath);
    const bool uninstall = registryKeyExists(kLegacyUninstall);
    const auto kind = record ? readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kDeploymentKindValueName) : std::nullopt;
    if (kind == L"MSI") {
        if (uninstall) fail(L"Both MSI and EXE installation records exist. No changes were made.");
        return {};
    }
    if (kind) fail(L"Unsupported deployment ownership record. No changes were made.");
    if (!record && !uninstall) {
        const auto keys = deploymentRegistryKeys();
        if (registryKeyExists(keys[3].c_str()) || registryKeyExists(keys[4].c_str()))
            fail(L"Unowned Credential Provider registration exists. Use the original maintenance tool.");
        auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!manager) fail(L"Cannot inspect existing service registration.");
        auto service = OpenServiceW(manager, unlock_windows::saved_credential::kServiceName, SERVICE_QUERY_STATUS);
        const auto error = service ? ERROR_SUCCESS : GetLastError();
        if (service) CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if (service || error != ERROR_SERVICE_DOES_NOT_EXIST)
            fail(L"Unowned or inaccessible product service exists. Use the original maintenance tool.");
        if (fileExists(startMenuShortcut())) fail(L"Unowned product shortcut exists. Use the original maintenance tool.");
        for (const auto& component : kComponentFiles)
            if (fileExists((component.desktopTool ? desktopDirectory() : system32Directory()) / component.name))
                fail(L"Unowned product files exist. Use the original maintenance tool.");
        if (fileExists(desktopDirectory() / kInstallerFile)) fail(L"Unowned EXE installer exists.");
        return {};
    }
    if (!record || !uninstall)
        fail(L"Only complete schema 5 EXE installations can be taken over. Use the original installer.");
    LegacyInstallation result{};
    checkHresult(readSetupTargetSid(result.sid), L"Read configured user");
    const auto versionText = readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kInstalledVersionValueName).value_or(L"");
    const auto schema = readRegistryDword(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kLegacySchemaValueName).value_or(0);
    const auto version = supportedLegacyVersion(schema, versionText);
    if (!version) fail(L"Only schema 5 with four complete version fields can be taken over. Use the original installer.");
    result.version = *version;
    if (registryKeyExists(kLegacyResult)) fail(L"EXE result delivery is incomplete. Use the original installer.");
    const auto setup = desktopDirectory() / kInstallerFile;
    if (readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kLegacyWizardPathValueName) != setup.wstring() ||
        readRegistryString(HKEY_LOCAL_MACHINE, kInstalledProductRegistryPath, kLegacyLastOperationIdValueName).value_or(L"").empty() ||
        readRegistryString(HKEY_LOCAL_MACHINE, kLegacyUninstall, L"DisplayVersion") != versionText ||
        readRegistryString(HKEY_LOCAL_MACHINE, kLegacyUninstall, L"UninstallString") != L"\"" + setup.wstring() + L"\" --uninstall")
        fail(L"Incomplete or inconsistent EXE maintenance registration. Use the original installer.");
    rejectTasks();
    const auto transactions = productDataDirectory() / L"Setup" / L"Transactions";
    if (std::filesystem::exists(transactions) && !std::filesystem::is_empty(transactions))
        fail(L"Legacy staging remains. Use the original installer.");
    unlock_windows::storage::ensureProtectedDirectory(desktopDirectory(), false);
    unlock_windows::storage::verifyProtectedPath(setup, false);
    result.files = readLegacyManifest(setup);
    SYSTEM_INFO native{}; GetNativeSystemInfo(&native);
    const WORD expected = native.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? IMAGE_FILE_MACHINE_AMD64
        : native.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? IMAGE_FILE_MACHINE_ARM64 : 0;
    for (const auto& file : result.files) {
        const auto path = legacyTarget(file);
        if (file.desktopTool) {
            auto parent = desktopDirectory();
            for (const auto& part : std::filesystem::path(file.name).parent_path()) {
                parent /= part; unlock_windows::storage::ensureProtectedDirectory(parent, false);
            }
        }
        const auto content = bytes(path);
        if (file.resourceId) {
            unlock_windows::protocol::Sha256Digest digest{};
            if (unlock_windows::protocol::sha256(content.data(), content.size(), digest) < 0 ||
                content.size() != file.size || digest != file.digest || machine(content) != file.machine)
                fail(L"Legacy dependency differs from its manifest: " + file.name);
        }
        if (file.productComponent && (binaryVersion(path) != *version || machine(content) != expected))
            fail(L"Legacy component version or architecture mismatch: " + file.name);
    }
    const auto keys = deploymentRegistryKeys();
    const auto inproc = keys[4] + L"\\InprocServer32";
    if (!registryKeyExists(keys[3].c_str()) ||
        readRegistryString(HKEY_LOCAL_MACHINE, inproc.c_str(), nullptr) != (system32Directory() / kCredentialProviderFile).wstring() ||
        readRegistryString(HKEY_LOCAL_MACHINE, inproc.c_str(), L"ThreadingModel") != L"Apartment" || !fileExists(startMenuShortcut()))
        fail(L"Legacy Credential Provider or shortcut registration is incomplete.");
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) fail(L"Cannot inspect service manager.");
    SC_HANDLE service = OpenServiceW(manager, unlock_windows::saved_credential::kServiceName, SERVICE_QUERY_CONFIG);
    if (!service) { CloseServiceHandle(manager); fail(L"Legacy service is missing."); }
    DWORD size = 0; QueryServiceConfigW(service, nullptr, 0, &size);
    std::vector<BYTE> data(size);
    const bool queried = size && QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(data.data()), size, &size);
    CloseServiceHandle(service); CloseServiceHandle(manager);
    if (!queried) fail(L"Cannot inspect legacy service configuration.");
    const auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(data.data());
    if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS || config->dwStartType != SERVICE_AUTO_START ||
        _wcsicmp(config->lpServiceStartName, L"LocalSystem") ||
        config->lpBinaryPathName != L"\"" + (system32Directory() / kSavedCredentialServiceFile).wstring() + L"\"")
        fail(L"Legacy service configuration differs from the supported deployment.");
    return result;
}
}
