// Created by Rui MA on 04 Oct 2026
// Scheduled SYSTEM continuation, exit finalization and ordinary-user result handoff.

#pragma once
#include "WindowsAdapter.h"
#include "PackageDeployment.h"
#include "SetupStateStore.h"

namespace unlock::components {
class SetupFinalization final {
public:
    SetupFinalization(WindowsAdapter& adapter, SetupStateStore& store, PackageDeployment& package)
        : adapter_(adapter), store_(store), package_(package) {}
    [[nodiscard]] bool continuationTaskExists() const;
    [[nodiscard]] bool finalizationTaskExists() const;
    void registerContinuationTask(const SetupTransactionState& state) const;
    void registerResultTask(const SetupTransactionState& state) const;
    void startFinalization(const SetupTransactionState& state) const;
    void retryFinalization(const SetupTransactionState& state) const;
    void runContinuation(const SetupTransactionState& state) const;
    void acknowledgeCompletion(const std::wstring& transactionId) const;
    void startTrayForCompletedOperation(const std::wstring& transactionId, bool setup = false) const;
private:
    void registerFinalizationUninstall(const SetupTransactionState& state) const;
    WindowsAdapter& adapter_;
    SetupStateStore& store_;
    PackageDeployment& package_;
};
}
