// Created by Rui MA on 26 Sep 2026

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <stdexcept>
#include "../Bluetooth/SystemBleContract.h"

namespace unlock_windows::system_ble {

inline constexpr wchar_t kEnrollmentDataDirectoryName[] = L"UnlockWindowsWithIPhone";
inline constexpr wchar_t kEnrollmentFileName[] = L"enrollment.dat";
inline constexpr wchar_t kEnrollmentPendingSuffix[] = L".pending-";
inline constexpr wchar_t kEnrollmentWriterMutex[] = L"Global\\UnlockWindowsWithIPhone-EnrollmentWriter";

struct RebindRequired final : std::runtime_error {
    RebindRequired() : std::runtime_error("The previous registration requires explicit system rebinding") {}
};

class EnrollmentStore final {
public:
    static std::wstring defaultPath();
    static std::wstring currentUserSid();

    explicit EnrollmentStore(std::wstring path = defaultPath());

    EnrollmentStore(const EnrollmentStore&) = delete;
    EnrollmentStore& operator=(const EnrollmentStore&) = delete;

    [[nodiscard]] std::optional<BindingRecord> load() const;
    void save(const BindingRecord& record, const std::function<void()>& beforeCommit = {}) const;
    void remove() const;

    [[nodiscard]] const std::wstring& path() const noexcept {
        return path_;
    }

private:
    std::wstring path_;
};

} // namespace unlock_windows::system_ble
