// Created by Rui MA on 04 Oct 2026

#pragma once

#include "WindowsAdapter.h"

namespace unlock::components {
[[nodiscard]] std::wstring encodedPowerShell(const std::wstring& script);
[[nodiscard]] std::wstring resultObserverScript(const WindowsAdapter& adapter, const WizardState& state);
[[nodiscard]] std::wstring finalizationScript(const WindowsAdapter& adapter, const WizardState& state);
[[nodiscard]] std::wstring finalizationRecoveryScript(const WindowsAdapter& adapter, const WizardState& state);
}
