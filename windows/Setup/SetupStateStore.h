// Created by Rui MA on 09 Oct 2026
// Reads separate installation/transaction records and commits atomic completion snapshots.

#pragma once
#include "ComponentState.h"
#include <optional>

namespace unlock::components {
class SetupStateStore final {
public:
    [[nodiscard]] std::optional<InstalledProduct> readInstalledProduct() const;
    [[nodiscard]] std::optional<SetupTransactionState> readTransaction() const;
    void writeTransaction(const SetupTransactionState& state) const;
    [[nodiscard]] bool transactionRebootRequired() const;
    void markTransactionRequiresReboot() const;
    void writeCompletion(const CompletionRecord& result) const;
    [[nodiscard]] std::optional<CompletionRecord> readCompletion() const;
    void removeCompletion() const;
};
}
