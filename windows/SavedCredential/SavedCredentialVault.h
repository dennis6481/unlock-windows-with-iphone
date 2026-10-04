// Created by Rui MA on 30 Sep 2026

#pragma once

#include "SavedCredentialIpc.h"

#include <filesystem>
#include <optional>

namespace unlock_windows::saved_credential {

inline constexpr wchar_t kVaultDirectoryName[] = L"UnlockWindowsSavedCredential";

class Vault final {
public:
    Vault();
    [[nodiscard]] std::optional<Identity> storedIdentity() const;
    void save(const Identity& identity, const std::uint8_t* password,
              std::size_t passwordBytes, bool replace);
    [[nodiscard]] SensitiveBytes release(const Identity& expected) const;
    void clear();

private:
    std::filesystem::path directory_;
    std::filesystem::path file_;
};

[[nodiscard]] bool sameIdentity(const Identity& left, const Identity& right) noexcept;

} // namespace unlock_windows::saved_credential
