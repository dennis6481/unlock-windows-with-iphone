// Created by Rui MA on 27 Sep 2026

#pragma once

#include "UnlockLogonBuffer.h"

namespace unlock_windows::credential_provider {

enum class ApprovalFetchCode {
    approved,
    unavailable,
    invalid_response,
};

struct ApprovalFetchResult final {
    ApprovalFetchCode code;
    protocol::UnlockLogonBuffer buffer{};

    [[nodiscard]] bool succeeded() const noexcept {
        return code == ApprovalFetchCode::approved;
    }
};

enum class AuthenticationPackageCode {
    available,
    unavailable,
};

struct AuthenticationPackageResult final {
    AuthenticationPackageCode code;
    ULONG identifier = 0;

    [[nodiscard]] bool succeeded() const noexcept {
        return code == AuthenticationPackageCode::available;
    }
};

// Reads one already-verified, short-lived approval from UnlockService. The
// development named pipe authenticates the client process before returning it.
[[nodiscard]] ApprovalFetchResult consumePendingApproval() noexcept;

// Looks up the LSA package before consuming an approval. If the package is
// absent, GetSerialization must return no credential and leave the approval
// available for a later attempt.
[[nodiscard]] AuthenticationPackageResult lookupAuthenticationPackage() noexcept;

} // namespace unlock_windows::credential_provider
