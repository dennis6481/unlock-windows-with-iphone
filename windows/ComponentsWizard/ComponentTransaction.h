// Created by Rui MA on 28 Sep 2026

#pragma once

#include "WindowsAdapter.h"

#include <functional>
#include <string>

namespace unlock::components {

using ProgressCallback = std::function<void(int percent, const std::wstring& message)>;

struct OperationResult final {
    bool success = false;
    bool rebootRequired = false;
    bool statePreserved = false;
    std::wstring message;
};

class ComponentTransaction final {
public:
    explicit ComponentTransaction(WindowsAdapter& adapter);

    [[nodiscard]] OperationResult install(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult beginUpdate(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult completeUpdate(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult beginUninstall(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult completeUninstall(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult recover(const ProgressCallback& progress = {});
    [[nodiscard]] OperationResult resetStaleState();

private:
    [[nodiscard]] WizardState newState(WizardPhase phase) const;
    [[nodiscard]] OperationResult failure(const std::wstring& message, bool statePreserved) const;
    void report(const ProgressCallback& progress, int percent, const std::wstring& message) const;
    [[nodiscard]] std::wstring errorText(const std::exception& error) const;

    WindowsAdapter& adapter_;
};

} // namespace unlock::components
