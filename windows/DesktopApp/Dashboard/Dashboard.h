// Created by Rui MA on 08 Oct 2026

#pragma once

#include <functional>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include "../../SavedCredential/SavedCredentialIpc.h"

namespace unlock_windows::desktop_app {

enum class DashboardPage { status, password, diagnostics, about };

struct DashboardSnapshot final {
    std::optional<saved_credential::BindingSummary> binding;
    std::optional<saved_credential::LastUnlockSummary> lastUnlock;
    bool busy = false;
    std::wstring status;
    std::wstring error;
    std::wstring diagnostics;
};

inline std::wstring lastUnlockText(const std::optional<saved_credential::LastUnlockSummary>& summary,
                                 ULONGLONG now) {
    if (!summary) return L"\u2014";
    const auto seconds = (now - summary->completedAt) / 1000;
    const auto count = seconds < 60 ? seconds : seconds < 3600 ? seconds / 60 :
        seconds < 86400 ? seconds / 3600 : seconds / 86400;
    const auto unit = seconds < 60 ? L" sec" : seconds < 3600 ? L" min" :
        seconds < 86400 ? L" hr" : count == 1 ? L" day" : L" days";
    return std::to_wstring(count) + unit + L" ago / " + std::to_wstring(summary->rssi) + L" dBm";
}

class Dashboard final {
public:
    using ReportError = std::function<void(std::wstring)>;
    using RefreshAction = std::function<void()>;

    Dashboard(RefreshAction refresh, ReportError reportError, ReportError passwordReport,
              ReportError bindingReport, ReportError aboutReport);
    ~Dashboard();
    Dashboard(const Dashboard&) = delete;
    Dashboard& operator=(const Dashboard&) = delete;

    void show(std::optional<DashboardPage> page = std::nullopt);
    void update(DashboardSnapshot snapshot);
    void stop();

private:
    struct State;
    std::unique_ptr<State> state_;
};

}
