// Created by Rui MA on 09 Oct 2026

#pragma once
#include "../ComponentFiles.h"
#include "../Protocol/UnlockCrypto.h"
#include <Windows.h>
#include <bit>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace unlock::components {
inline constexpr std::uint32_t kPackageManifestResourceId = 65535;
inline constexpr std::uint32_t kPackageManifestMagic = 1431783750;
inline constexpr std::uint32_t kPackageManifestVersion = 1;
inline constexpr std::uint32_t kPackageDesktopFlag = 1;
inline constexpr std::uint32_t kPackageProductFlag = 2;
inline constexpr wchar_t kPackagePathComponentPattern[] =
    LR"regex((?!(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$))[^<>:"/\\|?*\x00-\x1F]*[^<>:"/\\|?*\x00-\x1F. ])regex";
#pragma pack(push, 1)
struct PackageManifestHeader final {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t count;
};
struct PackageRecord final {
    std::uint32_t resourceId;
    std::uint32_t flags;
    std::uint32_t machine;
    std::uint32_t size;
    std::uint32_t nameLength;
    unlock_windows::protocol::Sha256Digest digest;
};
#pragma pack(pop)
static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(wchar_t) == 2);

struct PackageFile final {
    std::wstring name;
    bool desktopTool;
    std::uint16_t resourceId;
    std::uint32_t size;
    std::uint16_t machine;
    bool productComponent;
    unlock_windows::protocol::Sha256Digest digest;
    [[nodiscard]] ComponentFile component() const { return {name.c_str(), desktopTool}; }
};
[[nodiscard]] std::vector<PackageFile> readPackageManifest(HMODULE module);
[[nodiscard]] bool isPackageRelativePath(std::wstring_view name);
[[nodiscard]] std::span<const PackageFile> packageFiles();
}
