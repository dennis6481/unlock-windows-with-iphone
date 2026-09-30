// Created by Rui MA on 29 Sep 2026

#pragma once

#include <cstdint>

namespace unlock_windows::lsa_convert_probe {

inline constexpr char kPackageName[] = "UnlockWindowsWithIPhoneConvertProbe";
inline constexpr std::uint32_t kRequestMagic = 0x50574355; // "UCWP"
inline constexpr std::uint32_t kRequestVersion = 1;
inline constexpr std::uint32_t kRunInteractiveConversion = 1;
inline constexpr std::uint32_t kMaximumReportBytes = 256 * 1024;

struct Request final {
    std::uint32_t magic = kRequestMagic;
    std::uint32_t version = kRequestVersion;
    std::uint32_t operation = kRunInteractiveConversion;
    std::uint32_t reserved = 0;
};

} // namespace unlock_windows::lsa_convert_probe
