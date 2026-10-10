// Created by Rui MA on 09 Oct 2026

#define UNICODE
#define _UNICODE
#include "PackageDeployment.h"
#include "SetupPlatform.h"
#include <cstring>
#include <fstream>
#include <set>

namespace unlock::components {
// Package integrity, protected staging and deployment; no service or transaction decisions.
namespace {
std::uint16_t packageMachine(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 2 || bytes[0] != 'M' || bytes[1] != 'Z') return 0;
    if (bytes.size() < 64) fail(L"Incomplete package PE header.");
    std::uint32_t offset = 0, signature = 0;
    std::uint16_t machine = 0;
    std::memcpy(&offset, bytes.data() + 60, sizeof(offset));
    if (offset < 64 || offset > bytes.size() - 6) fail(L"Invalid package PE offset.");
    std::memcpy(&signature, bytes.data() + offset, sizeof(signature));
    std::memcpy(&machine, bytes.data() + offset + 4, sizeof(machine));
    if (signature != 0x4550) fail(L"Invalid package PE signature.");
    return machine;
}

void verifyPackageBytes(const PackageFile& entry, std::span<const std::uint8_t> bytes) {
    if (bytes.size() != entry.size || packageMachine(bytes) != entry.machine)
        fail(L"Package file size or PE architecture mismatch: " + entry.name);
    unlock_windows::protocol::Sha256Digest digest{};
    const auto status = unlock_windows::protocol::sha256(bytes.data(), bytes.size(), digest);
    if (status < 0) fail(L"Could not hash package file: NTSTATUS=" + std::to_wstring(status));
    if (digest != entry.digest) fail(L"Package file integrity check failed: " + entry.name);
}

std::vector<std::uint8_t> packageFileBytes(const std::filesystem::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        fail(L"Missing or unsafe package file: " + path.wstring());
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) fail(L"Could not read package file: " + path.wstring());
    const auto size = stream.tellg();
    if (size <= 0 || static_cast<std::uint64_t>(size) > MAXDWORD) fail(L"Invalid package file size: " + path.wstring());
    std::vector<std::uint8_t> bytes(static_cast<size_t>(size));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(bytes.data()), size)) fail(L"Incomplete package file read: " + path.wstring());
    return bytes;
}

void verifyPackageCopy(const std::filesystem::path& source, const std::filesystem::path& target) {
    const auto expected = packageFileBytes(source), actual = packageFileBytes(target);
    unlock_windows::protocol::Sha256Digest left{}, right{};
    const auto first = unlock_windows::protocol::sha256(expected.data(), expected.size(), left);
    const auto second = unlock_windows::protocol::sha256(actual.data(), actual.size(), right);
    if (first < 0 || second < 0) fail(L"Could not hash copied package file: " + target.wstring());
    if (expected.size() != actual.size() || left != right)
        fail(L"Copied package file integrity check failed: " + target.wstring());
}

class EmbeddedPackage final {
public:
    explicit EmbeddedPackage(const std::filesystem::path& path) {
        module_ = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE);
        if (!module_) fail(L"Could not read embedded package: " + path.wstring() + L": " + win32ErrorMessage(GetLastError()));
        try { files_ = readPackageManifest(module_); components_.resize(files_.size()); }
        catch (...) { FreeLibrary(module_); throw; }
    }
    EmbeddedPackage(const EmbeddedPackage&) = delete;
    EmbeddedPackage& operator=(const EmbeddedPackage&) = delete;
    ~EmbeddedPackage() { FreeLibrary(module_); }

    void requireComponents() const {
        for (const auto& entry : files_)
            if (entry.resourceId && !FindResourceW(module_, MAKEINTRESOURCEW(entry.resourceId), RT_RCDATA))
                fail(L"Missing embedded package file: " + entry.name);
    }

    ProductVersion validate(const WindowsAdapter& adapter, const SetupTransactionState& state);
    std::span<const PackageFile> files() const { return files_; }
    std::span<const std::uint8_t> component(size_t index) const { return components_[index]; }

private:
    std::span<const std::uint8_t> readComponent(const PackageFile& entry) const {
            const auto resource = FindResourceW(module_, MAKEINTRESOURCEW(entry.resourceId), RT_RCDATA);
            if (!resource) fail(L"Missing embedded component: " + entry.name);
            const auto size = SizeofResource(module_, resource);
            const auto loaded = LoadResource(module_, resource);
            const auto bytes = loaded ? static_cast<const std::uint8_t*>(LockResource(loaded)) : nullptr;
            if (!size || !bytes) fail(L"Could not read embedded component: " + entry.name);
            verifyPackageBytes(entry, {bytes, size});
            return {bytes, size};
    }
    HMODULE module_ = nullptr;
    std::vector<PackageFile> files_;
    std::vector<std::span<const std::uint8_t>> components_;
};

void writeEmbeddedComponent(const std::filesystem::path& path, std::span<const std::uint8_t> bytes) {
    const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) fail(L"Could not stage embedded component: " + path.wstring() +
        L": " + win32ErrorMessage(GetLastError()));
    ScopedHandle file(handle);
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    checkWin32(GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)),
        L"Inspect staged component");
    if (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) fail(L"Unsafe staged component: " + path.wstring());
    LARGE_INTEGER start{};
    checkWin32(SetFilePointerEx(file.get(), start, nullptr, FILE_BEGIN), L"Seek staged component");
    checkWin32(SetEndOfFile(file.get()), L"Truncate staged component");
    DWORD written = 0;
    checkWin32(WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr),
        L"Write embedded component " + path.wstring());
    if (written != bytes.size()) fail(L"Incomplete embedded component write: " + path.wstring());
    checkWin32(FlushFileBuffers(file.get()), L"Flush embedded component " + path.wstring());
}

ProductVersion EmbeddedPackage::validate(const WindowsAdapter& adapter, const SetupTransactionState& state) {
    const auto version = parseProductVersion(state.packageVersion);
    if (!version || *version != kProductVersion) fail(L"Invalid or mismatched recorded package version.");
    const std::filesystem::path source(state.sourcePath);
    const auto native = adapter.environment().nativeArchitecture;
    if (!fileExists(source) || adapter.executableArchitecture(source) != native || adapter.binaryVersion(source) != *version)
        fail(L"Missing, wrong-architecture or mixed-version installer: " + source.wstring());
    for (size_t index = 0; index < files_.size(); ++index) {
        const auto& entry = files_[index];
        (void)adapter.componentTarget(entry.component());
        if (entry.resourceId) components_[index] = readComponent(entry);
    }
    return *version;
}
} // namespace
void PackageDeployment::requireEmbeddedComponents(const std::filesystem::path& path) {
    EmbeddedPackage(path).requireComponents();
}
void PackageDeployment::preparePackageParent(const std::filesystem::path& root,
    const std::filesystem::path& relative) const {
    auto parent = root;
    adapter_.ensureProtectedDirectory(parent, false);
    for (const auto& part : relative.parent_path()) {
        parent /= part;
        adapter_.ensureProtectedDirectory(parent, true);
    }
}
void PackageDeployment::validatePackageFile(const PackageFile& entry, const std::filesystem::path& path,
    ProductVersion version) const {
    if (entry.resourceId) verifyPackageBytes(entry, packageFileBytes(path));
    if (entry.productComponent &&
        (adapter_.binaryVersion(path) != version || adapter_.executableArchitecture(path) != adapter_.environment().nativeArchitecture))
        fail(L"Project component version or architecture mismatch: " + path.wstring());
}
ProductVersion PackageDeployment::validatePackage(const SetupTransactionState& state) const {
    EmbeddedPackage package(state.sourcePath);
    return package.validate(adapter_, state);
}
void PackageDeployment::validateInstalledFiles(const std::wstring& installedVersion) const {
    const auto version = parseProductVersion(installedVersion);
    if (!version) fail(L"Installed product version is missing or invalid. No migration will run.");
    EmbeddedPackage installed(desktopDirectory() / kInstallerFile);
    installed.requireComponents();
    for (const auto& entry : installed.files())
        validatePackageFile(entry, adapter_.componentTarget(entry.component()), *version);
}
std::vector<PackageFile> PackageDeployment::installedPackageFiles() const {
    EmbeddedPackage installed(desktopDirectory() / kInstallerFile);
    return {installed.files().begin(), installed.files().end()};
}
void PackageDeployment::copyNativeExecutable(const std::filesystem::path& source, const std::filesystem::path& target) const {
    adapter_.logOperation(L"Copy: " + source.wstring() + L" -> " + target.wstring());
    if (!fileExists(source)) {
        fail(L"Required source component is missing: " + source.wstring());
    }
    const auto status = adapter_.environment();
    const auto sourceArchitecture = adapter_.executableArchitecture(source);
    if (sourceArchitecture != status.nativeArchitecture) {
        fail(
            source.filename().wstring() + L" is " + architectureName(sourceArchitecture) +
            L", but Windows is " + architectureName(status.nativeArchitecture) + L". Rebuild before installing."
        );
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
        CREATE_ALWAYS,
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

std::filesystem::path PackageDeployment::transactionDirectory(const SetupTransactionState& state) const {
    if (state.transactionId.empty() || state.transactionId.find_first_not_of(L"0123456789-") != std::wstring::npos) {
        fail(L"The setup transaction identifier is invalid.");
    }
    return transactionRoot() / state.transactionId;
}

void PackageDeployment::stagePackage(SetupTransactionState& state) const {
    EmbeddedPackage package(state.sourcePath);
    const auto version = package.validate(adapter_, state);
    adapter_.ensureDeploymentDirectories();
    const auto directory = transactionDirectory(state);
    adapter_.ensureProtectedDirectory(directory, true);
    adapter_.logOperation(L"Create protected staging directory: " + directory.wstring());
    for (size_t index = 0; index < package.files().size(); ++index) {
        const auto& entry = package.files()[index];
        const auto target = directory / entry.name;
        preparePackageParent(directory, entry.name);
        if (!entry.resourceId) {
            copyNativeExecutable(state.sourcePath, target);
            verifyPackageCopy(state.sourcePath, target);
        } else {
            const auto bytes = package.component(index);
            adapter_.logOperation(L"Extract embedded component: " + target.wstring());
            writeEmbeddedComponent(target, bytes);
            std::ifstream staged(target, std::ios::binary);
            if (!staged) fail(L"Could not verify staged component: " + target.wstring());
            std::array<char, 65536> buffer{};
            size_t offset = 0;
            do {
                staged.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
                const auto count = static_cast<size_t>(staged.gcount());
                if (staged.bad() || (staged.fail() && !staged.eof()) || count > bytes.size() - offset ||
                    std::memcmp(buffer.data(), bytes.data() + offset, count) != 0)
                    fail(L"Staged component integrity check failed: " + target.wstring());
                offset += count;
            } while (!staged.eof());
            if (offset != bytes.size()) fail(L"Incomplete staged component: " + target.wstring());
        }
        validatePackageFile(entry, target, version);
    }
    // The caller publishes payloadReady only after every staged file has been verified.
    state.wizardPath = (directory / kInstallerFile).wstring();
}

void PackageDeployment::stageContinuation(SetupTransactionState& state) const {
    adapter_.ensureDeploymentDirectories();
    const auto directory = transactionDirectory(state);
    adapter_.ensureProtectedDirectory(directory, true);
    adapter_.logOperation(L"Create protected continuation directory: " + directory.wstring());
    const auto wizard = directory / kInstallerFile;
    if (adapter_.binaryVersion(state.sourcePath).text() != state.packageVersion) fail(L"Maintenance installer version changed.");
    copyNativeExecutable(state.sourcePath, wizard);
    verifyPackageCopy(state.sourcePath, wizard);
    state.wizardPath = wizard.wstring();
}

void PackageDeployment::applyStagedPackage(const SetupTransactionState& state) const {
    adapter_.ensureDeploymentDirectories();
    const auto directory = transactionDirectory(state);
    adapter_.ensureProtectedDirectory(directory, false);
    if (std::filesystem::path(state.wizardPath) != directory / kInstallerFile)
        fail(L"The protected transaction staging location is invalid.");
    const auto version = parseProductVersion(state.packageVersion);
    if (!version || *version != kProductVersion) fail(L"Staged product version is invalid.");
    const auto files = packageFiles();
    std::set<std::filesystem::path> obsoleteDirectories;
    for (const auto& entry : files) {
        const auto source = directory / entry.name;
        preparePackageParent(directory, entry.name);
        validatePackageFile(entry, source, *version);
        (void)adapter_.componentTarget(entry.component());
        if (entry.desktopTool) preparePackageParent(desktopDirectory(), entry.name);
    }
    for (const auto& entry : files) {
        const auto source = directory / entry.name;
        const auto temporary = adapter_.componentTarget(entry.component()).wstring() + L".update";
        writeEmbeddedComponent(temporary, packageFileBytes(source));
        if (entry.resourceId) validatePackageFile(entry, temporary, *version);
        else verifyPackageCopy(source, temporary);
    }
    const auto installedSetup = desktopDirectory() / kInstallerFile;
    if (fileExists(installedSetup)) {
        EmbeddedPackage previous(installedSetup);
        for (const auto& entry : previous.files()) {
            bool retained = false;
            for (const auto& current : files) if (_wcsicmp(entry.name.c_str(), current.name.c_str()) == 0) retained = true;
            if (!retained) {
                const auto target = adapter_.componentTarget(entry.component());
                adapter_.deleteFileIfPresent(target);
                if (entry.desktopTool) {
                    auto parent = std::filesystem::path(entry.name).parent_path();
                    while (!parent.empty()) {
                        obsoleteDirectories.insert(desktopDirectory() / parent);
                        parent = parent.parent_path();
                    }
                }
            }
        }
    }
    for (auto path = obsoleteDirectories.rbegin(); path != obsoleteDirectories.rend(); ++path) {
        if (!std::filesystem::exists(*path)) continue;
        adapter_.ensureProtectedDirectory(*path, false);
        if (std::filesystem::is_empty(*path))
            checkWin32(RemoveDirectoryW(path->c_str()), L"Remove obsolete runtime directory " + path->wstring());
    }
    // Replace the resident installer last: until then its manifest owns obsolete dependencies.
    for (const bool installer : {false, true}) {
        for (const auto& entry : files) {
            if ((!entry.resourceId) != installer) continue;
            const auto source = directory / entry.name;
            const auto target = adapter_.componentTarget(entry.component());
            const std::filesystem::path temporary(target.wstring() + L".update");
            checkWin32(MoveFileExW(temporary.c_str(), target.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH), L"Replace " + target.wstring());
            validatePackageFile(entry, target, *version);
            if (installer) verifyPackageCopy(source, target);
            adapter_.logOperation(L"Committed package file: " + target.wstring());
        }
    }
}

bool PackageDeployment::desktopPackagePresent() const {
    if (!std::filesystem::is_regular_file(desktopDirectory() / kInstallerFile)) return false;
    for (const auto& entry : installedPackageFiles())
        if (entry.desktopTool && !std::filesystem::is_regular_file(adapter_.componentTarget(entry.component()))) return false;
    return true;
}
bool PackageDeployment::desktopArtifactsPresent() const {
    if (std::filesystem::exists(startMenuShortcut())) return true;
    for (const auto& entry : packageFiles())
        if (entry.desktopTool && std::filesystem::exists(adapter_.componentTarget(entry.component()))) return true;
    return std::filesystem::exists(desktopDirectory()) && !std::filesystem::is_empty(desktopDirectory());
}
void PackageDeployment::removeDesktopPackage() const {
    std::set<std::filesystem::path> directories;
    for (const auto& entry : packageFiles())
        if (entry.desktopTool) {
            const auto target = adapter_.componentTarget(entry.component());
            adapter_.deleteFileIfPresent(target);
            adapter_.deleteFileIfPresent(target.wstring() + L".update");
            auto parent = std::filesystem::path(entry.name).parent_path();
            while (!parent.empty()) {
                directories.insert(desktopDirectory() / parent);
                parent = parent.parent_path();
            }
        }
    for (auto directory = directories.rbegin(); directory != directories.rend(); ++directory) {
        if (!std::filesystem::exists(*directory)) continue;
        const auto attributes = GetFileAttributesW(directory->c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw ComponentError(L"Unsafe runtime directory: " + directory->wstring());
        checkWin32(RemoveDirectoryW(directory->c_str()), L"Remove runtime directory " + directory->wstring());
    }
}
}
