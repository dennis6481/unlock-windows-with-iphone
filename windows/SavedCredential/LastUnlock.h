// Created by Rui MA on 11 Oct 2026

#pragma once

#include "SavedCredentialIpc.h"
#include <utility>

namespace unlock_windows::saved_credential {

struct UnlockContext final {
    Identity identity;
    DWORD session = 0xffffffff;
    LUID logonId{};
    system_ble::BindingRecord binding;
    ULONGLONG historyGeneration = 0;
    ULONGLONG identityGeneration = 0;
};

class LastUnlockHistory final {
public:
    void beginClaim(UnlockContext context, const std::array<std::uint8_t, kNonceSize>& nonce, ULONG processId, int rssi) noexcept {
        context_ = std::move(context);
        pending_ = Pending{nonce, processId, rssi};
    }

    void refreshContext(const UnlockContext& current) {
        if (!context_) return;
        auto original = context_->binding;
        original.threshold = current.binding.threshold;
        if (!sameIdentity(context_->identity, current.identity) || context_->session != current.session ||
            context_->logonId.LowPart != current.logonId.LowPart || context_->logonId.HighPart != current.logonId.HighPart ||
            context_->historyGeneration != current.historyGeneration || original != current.binding) {
            clear();
        } else if (context_->identityGeneration != current.identityGeneration) cancelPending();
    }

    [[nodiscard]] bool report(const UnlockResult& result, ULONG processId, bool logonUi,
                              bool processAlive, const Identity& identity, ULONGLONG now) noexcept {
        if (!logonUi || !pending_ || pending_->processId != processId || pending_->nonce != result.nonce)
            return false;
        if (!sameIdentity(context_->identity, identity)) { clear(); return false; }
        if (!processAlive) { cancelPending(); return false; }
        if (result.status == 0) summary_ = LastUnlockSummary{now, pending_->rssi};
        cancelPending();
        return true;
    }

    void cancelPending() noexcept {
        pending_.reset();
        if (!summary_) context_.reset();
    }
    void clear() noexcept { cancelPending(); summary_.reset(); context_.reset(); }
    [[nodiscard]] bool pending() const noexcept { return pending_.has_value(); }
    [[nodiscard]] const std::optional<LastUnlockSummary>& summary() const noexcept { return summary_; }

private:
    struct Pending final {
        std::array<std::uint8_t, kNonceSize> nonce;
        ULONG processId;
        int rssi;
    };
    std::optional<Pending> pending_;
    std::optional<LastUnlockSummary> summary_;
    std::optional<UnlockContext> context_;
};

}
