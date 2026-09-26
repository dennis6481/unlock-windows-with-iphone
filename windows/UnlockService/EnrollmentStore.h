// Created by Rui MA on 26 Sep 2026

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace unlock_windows::service {

class EnrollmentStore final {
public:
    static std::wstring defaultPath();

    explicit EnrollmentStore(std::wstring path = defaultPath());

    EnrollmentStore(const EnrollmentStore&) = delete;
    EnrollmentStore& operator=(const EnrollmentStore&) = delete;

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> load() const;
    void save(const std::vector<std::uint8_t>& rawPublicKey) const;
    void remove() const;

    [[nodiscard]] const std::wstring& path() const noexcept {
        return path_;
    }

    [[nodiscard]] static std::string fingerprint(
        const std::vector<std::uint8_t>& rawPublicKey
    );

private:
    std::wstring path_;
};

} // namespace unlock_windows::service
