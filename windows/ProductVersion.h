// Created by Rui MA on 04 Oct 2026

#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace unlock::components {
struct ProductVersion final {
    std::uint16_t major, minor, patch, build;
    constexpr auto operator<=>(const ProductVersion&) const = default;
    [[nodiscard]] constexpr ProductVersion release() const { return {major, minor, patch, 0}; }
    [[nodiscard]] std::wstring text() const {
        return std::to_wstring(major) + L"." + std::to_wstring(minor) + L"." + std::to_wstring(patch) + L"." + std::to_wstring(build);
    }
};
inline constexpr ProductVersion kProductVersion{1, 0, 0, 14};
inline constexpr ProductVersion kMinimumMaintenanceVersion{1, 0, 0, 0};

[[nodiscard]] inline std::optional<ProductVersion> parseProductVersion(std::wstring_view text) {
    std::array<std::uint16_t, 4> parts{};
    size_t offset = 0;
    for (size_t part = 0; part < parts.size(); ++part) {
        const auto start = offset;
        std::uint32_t number = 0;
        while (offset < text.size() && text[offset] >= L'0' && text[offset] <= L'9') {
            number = number * 10 + static_cast<unsigned>(text[offset++] - L'0');
            if (number > UINT16_MAX) return std::nullopt;
        }
        if (offset == start || (offset > start + 1 && text[start] == L'0')) return std::nullopt;
        parts[part] = static_cast<std::uint16_t>(number);
        if (part == 2 && offset == text.size()) break;
        if (part + 1 < parts.size() && (offset == text.size() || text[offset++] != L'.')) return std::nullopt;
    }
    if (offset != text.size()) return std::nullopt;
    return ProductVersion{parts[0], parts[1], parts[2], parts[3]};
}
[[nodiscard]] inline std::wstring maintenanceVersionError(std::wstring_view text) {
    const auto version = parseProductVersion(text);
    if (!version) return L"Installed or transaction product version is missing or invalid. No changes were made.";
    if (*version < kMinimumMaintenanceVersion)
        return L"Version " + std::wstring(text) + L" is installed. Uninstall the old version in Windows Settings > Apps, then run this installer again. Versions earlier than " +
            kMinimumMaintenanceVersion.text() + L" cannot be updated with this installer.";
    return {};
}

enum class PackageAction { update, reinstall, rejectDowngrade };
[[nodiscard]] constexpr PackageAction packageAction(ProductVersion incoming, ProductVersion installed) {
    return incoming > installed ? PackageAction::update : incoming == installed
        ? PackageAction::reinstall : PackageAction::rejectDowngrade;
}
}
