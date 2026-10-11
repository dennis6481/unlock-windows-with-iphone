// Created by Rui MA on 28 Sep 2026
// Owns operation sequencing and the single phase-to-continuation decision.

#pragma once
#include "SetupFinalization.h"
#include <functional>
#include <string>

namespace unlock::components {
using ProgressCallback = std::function<void(int percent, const std::wstring& message)>;
struct OperationResult final {
    bool success = false;
    bool rebootRequired = false;
    std::wstring message;
    bool finalizationPending = false;
};
class SetupTransaction final {
public:
    SetupTransaction(WindowsAdapter& adapter, SetupStateStore& store,
        PackageDeployment& package, SetupFinalization& finalization)
        : adapter_(adapter), store_(store), package_(package), finalization_(finalization) {}
    [[nodiscard]] ComponentSnapshot inspect() const;
    [[nodiscard]] MaintenancePlan maintenancePlan() const;
    [[nodiscard]] OperationResult install(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult beginUpdate(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult beginUninstall(const ProgressCallback& progress = {});
    [[nodiscard]] int completeSystemOperation(const SetupTransactionState& state);
    [[nodiscard]] OperationResult continueOperation(const ProgressCallback& progress = {});
private:
    [[nodiscard]] SetupTransactionState newState(WizardPhase phase, std::wstring targetSid) const;
    [[nodiscard]] OperationResult prepare(SetupTransactionState& state, const ProgressCallback& progress);
    [[nodiscard]] OperationResult completeInstall(const ProgressCallback& progress);
    [[nodiscard]] OperationResult completeUpdate(const ProgressCallback& progress);
    [[nodiscard]] OperationResult completeUninstall(const ProgressCallback& progress);
    [[nodiscard]] OperationResult continuePreparation(const ProgressCallback& progress);
    void finishDeployment(SetupTransactionState& state) const;
    [[nodiscard]] OperationResult failure(const std::wstring& message) const;
    void report(const ProgressCallback& progress, int percent, const std::wstring& message) const;
    WindowsAdapter& adapter_;
    SetupStateStore& store_;
    PackageDeployment& package_;
    SetupFinalization& finalization_;
};
}
