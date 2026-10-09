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
    std::uint16_t major, minor, patch;
    constexpr auto operator<=>(const ProductVersion&) const = default;
    [[nodiscard]] std::wstring text() const {
        return std::to_wstring(major) + L"." + std::to_wstring(minor) + L"." + std::to_wstring(patch);
    }
};
inline constexpr ProductVersion kProductVersion{0, 2, 1};

[[nodiscard]] inline std::optional<ProductVersion> parseProductVersion(std::wstring_view text) {
    std::array<std::uint16_t, 3> parts{};
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
        if (part + 1 < parts.size() && (offset == text.size() || text[offset++] != L'.')) return std::nullopt;
    }
    if (offset != text.size()) return std::nullopt;
    return ProductVersion{parts[0], parts[1], parts[2]};
}
enum class PackageAction { update, reinstall, rejectDowngrade };
[[nodiscard]] constexpr PackageAction packageAction(ProductVersion incoming, ProductVersion installed) {
    return incoming > installed ? PackageAction::update : incoming == installed
        ? PackageAction::reinstall : PackageAction::rejectDowngrade;
}
}
