// Created by Rui MA on 30 Sep 2026

#pragma once

#include "SavedCredentialIpc.h"

#include <filesystem>
#include <optional>

namespace unlock_windows::saved_credential {

inline constexpr wchar_t kVaultDirectoryName[] = L"Credentials";

class Vault final {
public:
    Vault();
    [[nodiscard]] std::optional<Identity> storedIdentity() const;
    void save(const Identity& identity, const std::uint8_t* password,
              std::size_t passwordBytes, bool replace);
    [[nodiscard]] SensitiveBytes release(const Identity& expected) const;
    void clear();
    static void clearStored();

private:
    static void clearDirectory(const std::filesystem::path& directory);
    std::filesystem::path directory_;
    std::filesystem::path file_;
};

} // namespace unlock_windows::saved_credential
