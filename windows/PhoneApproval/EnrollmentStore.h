// Created by Rui MA on 26 Sep 2026

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace unlock_windows::phone_approval {

inline constexpr wchar_t kEnrollmentDataDirectoryName[] = L"UnlockWindowsWithIPhone";
inline constexpr wchar_t kEnrollmentFileName[] = L"enrollment.dat";
inline constexpr wchar_t kEnrollmentPendingSuffix[] = L".pending-";
inline constexpr wchar_t kEnrollmentWriterMutex[] = L"Global\\UnlockWindowsWithIPhone-EnrollmentWriter";

struct EnrollmentRecord final {
    std::vector<std::uint8_t> publicKey;
    std::wstring accountSid;
};

class EnrollmentStore final {
public:
    static std::wstring defaultPath();
    static std::wstring currentUserSid();

    explicit EnrollmentStore(std::wstring path = defaultPath());

    EnrollmentStore(const EnrollmentStore&) = delete;
    EnrollmentStore& operator=(const EnrollmentStore&) = delete;

    [[nodiscard]] std::optional<EnrollmentRecord> load() const;
    void save(const EnrollmentRecord& record, const std::function<void()>& beforeCommit = {}) const;
    void remove() const;

    [[nodiscard]] const std::wstring& path() const noexcept {
        return path_;
    }

    [[nodiscard]] static std::string fingerprint(
        const std::vector<std::uint8_t>& rawPublicKey
    );
    static void validatePublicKey(const std::vector<std::uint8_t>& rawPublicKey);

private:
    std::wstring path_;
};

} // namespace unlock_windows::phone_approval
