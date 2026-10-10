// Created by Rui MA on 09 Oct 2026
// Parses the authoritative package format and rejects unsafe or inconsistent records.

#include "PackageManifest.h"
#include "WindowsAdapter.h"
#include <cstring>
#include <set>
#include <cwctype>
#include <regex>

namespace unlock::components {
bool isPackageRelativePath(std::wstring_view name) {
    const std::filesystem::path path(name);
    if (path.empty() || path.is_absolute() || path.has_root_name()) return false;
    static const std::wregex component(kPackagePathComponentPattern, std::regex::icase);
    for (const auto& part : path)
        if (!std::regex_match(part.wstring(), component)) return false;
    return true;
}

std::vector<PackageFile> readPackageManifest(HMODULE module) {
    const auto resource = FindResourceW(module, MAKEINTRESOURCEW(kPackageManifestResourceId), RT_RCDATA);
    if (!resource) throw ComponentError(L"Package dependency manifest is missing. Complete and uninstall unsupported packages with their original installer. No migration will run.");
    const auto loaded = LoadResource(module, resource);
    const auto data = loaded ? static_cast<const std::uint8_t*>(LockResource(loaded)) : nullptr;
    const auto size = SizeofResource(module, resource);
    if (!data) throw ComponentError(L"Cannot read package dependency manifest.");
    size_t offset = 0;
    const auto read = [&](void* target, size_t count) {
        if (count > size - offset) throw ComponentError(L"Truncated package dependency manifest.");
        std::memcpy(target, data + offset, count);
        offset += count;
    };
    PackageManifestHeader header{};
    read(&header, sizeof(header));
    if (header.magic != kPackageManifestMagic || header.version != kPackageManifestVersion ||
        !header.count || header.count > kPackageManifestResourceId)
        throw ComponentError(L"Invalid package dependency manifest.");
    std::vector<PackageFile> files;
    std::set<std::wstring> names;
    std::set<std::uint16_t> ids;
    bool installer = false;
    for (std::uint32_t index = 0; index < header.count; ++index) {
        PackageRecord record{};
        read(&record, sizeof(record));
        if (!record.nameLength || record.nameLength > 32767 || record.resourceId >= kPackageManifestResourceId ||
            record.machine > 65535 || (record.flags & ~(kPackageDesktopFlag | kPackageProductFlag)))
            throw ComponentError(L"Invalid package dependency record.");
        std::wstring name(record.nameLength, L'\0');
        read(name.data(), name.size() * sizeof(wchar_t));
        if (!isPackageRelativePath(name)) throw ComponentError(L"Unsafe package dependency path.");
        auto normalized = name;
        for (auto& character : normalized) character = towlower(character == L'/' ? L'\\' : character);
        if (!names.insert(normalized).second) throw ComponentError(L"Duplicate package dependency path.");
        if (record.resourceId) {
            if (!record.size || !ids.insert(static_cast<std::uint16_t>(record.resourceId)).second)
                throw ComponentError(L"Invalid package dependency resource.");
        } else {
            if (installer || name != kInstallerFile || record.flags != (kPackageDesktopFlag | kPackageProductFlag) ||
                record.size || record.machine || record.digest != unlock_windows::protocol::Sha256Digest{})
                throw ComponentError(L"Invalid installer dependency record.");
            installer = true;
        }
        files.push_back({std::move(name), bool(record.flags & kPackageDesktopFlag),
            static_cast<std::uint16_t>(record.resourceId), record.size, static_cast<std::uint16_t>(record.machine),
            bool(record.flags & kPackageProductFlag), record.digest});
    }
    if (!installer || offset != size) throw ComponentError(L"Incomplete package dependency manifest.");
    for (const auto& component : kComponentFiles) {
        bool found = false;
        for (const auto& file : files)
            if (file.name == component.name && file.productComponent && file.desktopTool == component.desktopTool) found = true;
        if (!found) throw ComponentError(L"Required project component is missing from the package manifest.");
    }
    for (const auto& file : files) {
        bool project = false;
        for (const auto& component : kComponentFiles)
            if (file.name == component.name && file.desktopTool == component.desktopTool) project = true;
        if (file.productComponent != project || (!file.desktopTool && !project))
            throw ComponentError(L"Invalid project component ownership in package manifest.");
    }
    return files;
}

std::span<const PackageFile> packageFiles() {
    static const auto files = readPackageManifest(GetModuleHandleW(nullptr));
    return files;
}
}
