// Created by Rui MA on 26 Sep 2026

#pragma once

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>

#include <array>
#include <string>
#include <cstddef>
#include <cstdint>

namespace unlock_windows::protocol {

using Sha256Digest = std::array<std::uint8_t, 32>;

[[nodiscard]] NTSTATUS sha256(const std::uint8_t* bytes, std::size_t size, Sha256Digest& output) noexcept;
} // namespace unlock_windows::protocol
