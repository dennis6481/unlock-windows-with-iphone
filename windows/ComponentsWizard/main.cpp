// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE
#include "../Resources/resource.h"
#include "ComponentTransaction.h"
#include "resource.h"
#include "../Resources/DesktopUi.h"
#include <Windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <sddl.h>
#include <algorithm>
#include <memory>
#include <thread>
#include <vector>

namespace {
using namespace unlock::components;
constexpr UINT progressMessage = WM_APP + 1;
constexpr UINT completeMessage = WM_APP + 2;
enum class Page { home, update, uninstall, progress, restart, result, failure };
int alert(HWND parent, const wchar_t* title, const wchar_t* content,
          int buttons, PCWSTR icon) {
    TASKDIALOGCONFIG config{sizeof(config)};
    config.hwndParent = parent;
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT;
    config.pszWindowTitle = title;
    config.pszContent = content;
    config.pszMainIcon = icon;
    config.dwCommonButtons = static_cast<TASKDIALOG_COMMON_BUTTON_FLAGS>(buttons);
    config.nDefaultButton = IDOK;
    int selected = 0;
    const auto result = TaskDialogIndirect(&config, &selected, nullptr, nullptr);
    if (FAILED(result)) throw ComponentError(L"Installer notification could not be displayed (HRESULT=" +
        std::to_wstring(static_cast<unsigned long>(result)) + L").");
    return selected;
}
struct Progress { int percent; std::wstring message; };
std::wstring errorText(const std::exception& error) {
    if (auto component = dynamic_cast<const ComponentError*>(&error)) return component->wideWhat();
    std::string text(error.what()); return {text.begin(), text.end()};
}
std::filesystem::path modulePath() {
    std::vector<wchar_t> text(32768);
    DWORD n = GetModuleFileNameW(nullptr, text.data(), static_cast<DWORD>(text.size()));
    if (!n || n >= text.size()) throw ComponentError(L"Cannot determine installer path.");
    return std::wstring(text.data(), n);
}
std::wstring startupAccountLabel(const std::wstring& sid, std::wstring& details) {
    if (sid.empty()) throw ComponentError(L"The installation has no recorded startup account.");
    details = L"Startup account SID: " + sid;
    PSID binary = nullptr;
    if (!ConvertStringSidToSidW(sid.c_str(), &binary))
        throw ComponentError(L"Recorded startup account SID is invalid (Win32=" + std::to_wstring(GetLastError()) + L").");
    struct SidMemory { PSID value; ~SidMemory() { LocalFree(value); } } memory{binary};
    DWORD nameSize = 0, domainSize = 0;
    SID_NAME_USE use{};
    LookupAccountSidW(nullptr, binary, nullptr, &nameSize, nullptr, &domainSize, &use);
    DWORD error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<wchar_t> name(nameSize), domain(domainSize);
        if (LookupAccountSidW(nullptr, binary, name.data(), &nameSize, domain.data(), &domainSize, &use))
            return (domain.empty() || domain[0] == L'\0' ? std::wstring{} : std::wstring(domain.data()) + L"\\") + name.data();
        error = GetLastError();
    }
    details += L"\r\nAccount name lookup failed (Win32=" + std::to_wstring(error) + L").";
    return L"Name unavailable (Win32=" + std::to_wstring(error) + L").";
}
struct OperationLock {
    HANDLE value = nullptr;
    OperationLock() {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
            throw ComponentError(L"Cannot create operation lock security.");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        value = CreateMutexW(&attributes, FALSE, kOperationMutex);
        DWORD error = GetLastError(); LocalFree(descriptor);
        if (!value) throw ComponentError(L"Cannot open operation lock (Win32=" + std::to_wstring(error) + L").");
        const DWORD wait = WaitForSingleObject(value, 0);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
            CloseHandle(value); value = nullptr;
            throw ComponentError(L"Another component operation is in progress. Close this window and wait for it to finish.");
        }
    }
    ~OperationLock() { if (value) { ReleaseMutex(value); CloseHandle(value); } }
};
OperationResult continueOperation(WindowsAdapter& adapter, const ProgressCallback& progress) {
    const auto state = adapter.readState();
    if (!state) return {false, false, false, L"No registered transaction is pending."};
    ComponentTransaction transaction(adapter);
    switch (state->phase) {
        case WizardPhase::installed:
            if (adapter.inspect().isFullInstallation())
                return {true, false, true, L"Completed installation verified after interrupted result handoff."};
            return {false, false, true, L"Installed component verification failed."};
        case WizardPhase::installPendingReboot: return transaction.completeInstall(progress);
        case WizardPhase::updatePendingReboot:
        case WizardPhase::updating: return transaction.completeUpdate(progress);
        case WizardPhase::uninstallPendingReboot:
        case WizardPhase::cleaningUp: return transaction.completeUninstall(progress);
        case WizardPhase::preparing: return transaction.continuePreparation(progress);
        case WizardPhase::finalizing:
            return {true, false, true, L"Finalization is pending.", true};
        default: return {false, false, true, L"This transaction is not eligible for reboot continuation."};
    }
}
int resume(WindowsAdapter& adapter, const std::wstring& id) {
    if (!adapter.isSystem()) return ERROR_ACCESS_DENIED;
    OperationLock operationLock;
    auto state = adapter.readState();
    if (!state || state->transactionId != id ||
        std::filesystem::path(state->wizardPath) != adapter.wizardPath() ||
        adapter.wizardPath() != adapter.updateDirectory(*state) / kInstallerFile)
        return ERROR_INVALID_STATE;
    CompletionRecord record{id, state->targetSid, L"Completing operation after restart...", L"", false, false};
    const auto previous = adapter.readCompletion();
    if (previous && previous->transactionId == id) record.log = previous->log;
    adapter.writeCompletion(record);
    try {
        const auto result = continueOperation(adapter, [&](int, const std::wstring& message) {
            record.log += message + L"\r\n"; adapter.writeCompletion(record);
        });
        adapter.setOperationLog({});
        record.message = result.message;
        record.success = result.success && !result.rebootRequired && !result.finalizationPending;
        if (result.finalizationPending) {
            record.finished = false; adapter.writeCompletion(record);
            const auto current = adapter.readState();
            if (!current) throw ComponentError(L"Finalization transaction disappeared.");
            adapter.startFinalization(*current);
            return 0;
        }
        record.finished = true;
        adapter.writeCompletion(record);
        return record.success ? 0 : ERROR_INSTALL_FAILURE;
    } catch (const std::exception& error) {
        adapter.setOperationLog({});
        record.message = errorText(error); record.finished = true; record.success = false;
        adapter.writeCompletion(record); return ERROR_INSTALL_FAILURE;
    }
}
struct Window {
    WindowsAdapter adapter;
    HWND hwnd = nullptr;
    Page page = Page::home;
    std::thread worker;
    std::wstring log, resultId;
    bool resultMode = false, uninstallMode = false, busy = false, installed = false, pending = false;
    bool reinstall = false;
    std::function<void()> releaseOperation;
    unlock_windows::desktop_ui::DialogAppearance appearance;
    HFONT contentFont = nullptr;
    int footerTop = 0;
    explicit Window(std::filesystem::path path) : adapter(std::move(path)) {}
    ~Window() { if (worker.joinable()) worker.join(); if (contentFont) DeleteObject(contentFont); }
    void applyAppearance(UINT dpi = 0) {
        if (!dpi) dpi = GetDpiForWindow(hwnd);
        appearance.apply(hwnd, IDC_MAIN_INSTRUCTION, dpi);
        NONCLIENTMETRICSW metrics{sizeof(metrics)};
        if (!SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, dpi))
            throw ComponentError(L"Could not read installer display font.");
        const auto font = CreateFontIndirectW(&metrics.lfMessageFont);
        if (!font) throw ComponentError(L"Could not create installer display font.");
        for (int id : {IDC_PAGE_DESCRIPTION, IDC_DETAILS, IDC_BACK, IDC_ACTION, IDC_CANCEL_ACTION})
            SendDlgItemMessageW(hwnd, id, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        if (contentFont) DeleteObject(contentFont);
        contentFont = font;
        const int iconId = page == Page::failure ? 32513 :
            page == Page::uninstall || page == Page::restart ? 32515 : 32516;
        const auto icon = LoadImageW(nullptr, MAKEINTRESOURCEW(iconId), IMAGE_ICON,
            MulDiv(32, dpi, 96), MulDiv(32, dpi, 96), LR_SHARED);
        if (!icon) throw ComponentError(L"Could not load installer status icon.");
        SendDlgItemMessageW(hwnd, IDC_STATUS_ICON, STM_SETICON, reinterpret_cast<WPARAM>(icon), 0);
    }
    void text(int id, const std::wstring& value) { SetDlgItemTextW(hwnd, id, value.c_str()); }
    void button(int id, const wchar_t* label, bool enabled = true, bool primary = false) {
        ShowWindow(GetDlgItem(hwnd, id), label ? SW_SHOW : SW_HIDE);
        if (!label) return;
        text(id, label); EnableWindow(GetDlgItem(hwnd, id), enabled);
        SendDlgItemMessageW(hwnd, id, BM_SETSTYLE, primary ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON, TRUE);
        if (primary) SendMessageW(hwnd, DM_SETDEFID, id, 0);
    }
    void buttons(const wchar_t* left, const wchar_t* action, const wchar_t* cancel) {
        const bool preferCancel = page == Page::uninstall || page == Page::restart || page == Page::failure || action == nullptr;
        button(IDC_BACK, left);
        button(IDC_ACTION, action);
        button(IDC_CANCEL_ACTION, cancel);
        if (cancel && preferCancel) unlock_windows::desktop_ui::defaultButton(hwnd, IDC_CANCEL_ACTION);
        else if (action) unlock_windows::desktop_ui::defaultButton(hwnd, IDC_ACTION);
        else if (cancel) unlock_windows::desktop_ui::defaultButton(hwnd, IDC_CANCEL_ACTION);
        layout();
    }
    void layout() {
        const bool progress = page == Page::progress;
        const auto dpi = GetDpiForWindow(hwnd);
        const auto scaled = [dpi](int value) { return MulDiv(value, dpi, 96); };
        MONITORINFO monitor{sizeof(monitor)};
        if (!GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &monitor))
            throw ComponentError(L"Could not find installer display bounds.");
        const int margin = scaled(24), gap = scaled(12), iconSize = scaled(32);
        const int width = std::min(scaled(600), static_cast<int>(monitor.rcWork.right - monitor.rcWork.left) - margin * 2);
        const int left = margin + iconSize + scaled(20), textWidth = width - left - margin;
        const auto place = [&](int id, int x, int y, int w, int h) {
            if (!SetWindowPos(GetDlgItem(hwnd, id), nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE))
                throw ComponentError(L"Could not lay out installer controls.");
        };
        const auto measure = [&](int id, int availableWidth) {
            const auto control = GetDlgItem(hwnd, id);
            const int length = GetWindowTextLengthW(control);
            std::vector<wchar_t> value(static_cast<size_t>(length) + 1);
            GetWindowTextW(control, value.data(), length + 1);
            const auto dc = GetDC(control);
            if (!dc) throw ComponentError(L"Could not measure installer text.");
            const auto old = SelectObject(dc, reinterpret_cast<HFONT>(SendMessageW(control, WM_GETFONT, 0, 0)));
            RECT rect{0, 0, availableWidth, 0};
            DrawTextW(dc, value.data(), length, &rect, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
            SelectObject(dc, old); ReleaseDC(control, dc);
            return std::max(scaled(20), static_cast<int>(rect.bottom));
        };
        const int titleHeight = measure(IDC_MAIN_INSTRUCTION, textWidth);
        const int footerHeight = scaled(52);
        RECT frame{0, 0, width, 0};
        if (!AdjustWindowRectExForDpi(&frame, static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_STYLE)), FALSE,
            static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)), dpi))
            throw ComponentError(L"Could not measure installer frame.");
        const int maxHeight = monitor.rcWork.bottom - monitor.rcWork.top - (frame.bottom - frame.top) - margin * 2;
        int y = margin + titleHeight + gap;
        place(IDC_STATUS_ICON, margin, margin, iconSize, iconSize);
        place(IDC_MAIN_INSTRUCTION, left, margin, textWidth, titleHeight);
        if (!progress) {
            const int height = measure(IDC_PAGE_DESCRIPTION, textWidth);
            place(IDC_PAGE_DESCRIPTION, left, y, textWidth, height); y += height + gap;
        }
        if (progress) {
            const int height = std::max(scaled(60), std::min(scaled(180), maxHeight - y - footerHeight - margin - scaled(24)));
            place(IDC_DETAILS, left, y, textWidth, height); y += height + gap;
        }
        if (progress) { place(IDC_PROGRESS, left, y, textWidth, scaled(8)); y += scaled(20); }
        footerTop = y + scaled(12);
        const int height = footerTop + footerHeight;
        int right = width - margin;
        for (int id : {IDC_CANCEL_ACTION, IDC_ACTION, IDC_BACK}) {
            if (!(GetWindowLongPtrW(GetDlgItem(hwnd, id), GWL_STYLE) & WS_VISIBLE)) continue;
            const auto dc = GetDC(GetDlgItem(hwnd, id));
            if (!dc) throw ComponentError(L"Could not measure installer button.");
            const auto old = SelectObject(dc, contentFont);
            wchar_t label[128]{}; GetDlgItemTextW(hwnd, id, label, 128);
            RECT bounds{}; DrawTextW(dc, label, -1, &bounds, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, old); ReleaseDC(GetDlgItem(hwnd, id), dc);
            const int buttonWidth = std::max(scaled(88), static_cast<int>(bounds.right) + scaled(32));
            right -= buttonWidth;
            place(id, right, footerTop + scaled(10), buttonWidth, scaled(32)); right -= scaled(8);
        }
        ShowWindow(GetDlgItem(hwnd, IDC_DETAILS), progress ? SW_SHOW : SW_HIDE);
        RECT size{0, 0, width, height}, previous{};
        if (!AdjustWindowRectExForDpi(&size,
            static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_STYLE)), FALSE,
            static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)), GetDpiForWindow(hwnd)) ||
            !GetWindowRect(hwnd, &previous)) throw ComponentError(L"Could not measure installer window.");
        const LONG outerWidth = size.right - size.left, outerHeight = size.bottom - size.top;
        const LONG x = std::max(monitor.rcWork.left, std::min(
            previous.left + ((previous.right - previous.left) - outerWidth) / 2, monitor.rcWork.right - outerWidth));
        const LONG windowY = std::max(monitor.rcWork.top, std::min(
            previous.top + ((previous.bottom - previous.top) - outerHeight) / 2, monitor.rcWork.bottom - outerHeight));
        if (!SetWindowPos(hwnd, nullptr, x, windowY, outerWidth, outerHeight, SWP_NOZORDER | SWP_NOACTIVATE))
            throw ComponentError(L"Could not resize installer window.");
        InvalidateRect(hwnd, nullptr, TRUE);
    }
    void setPage(Page next, const std::wstring& title, const std::wstring& details) {
        page = next; text(IDC_MAIN_INSTRUCTION, title); text(IDC_PAGE_DESCRIPTION, details);
        applyAppearance();
        if (!SetWindowTextW(hwnd, next == Page::home && installed ? title.c_str() : (std::wstring(UNLOCK_PRODUCT_DISPLAY_NAME) + L" Setup").c_str()))
            throw ComponentError(L"Could not set installer window title.");
        text(IDC_DETAILS, next == Page::progress ? details : L"");
        ShowWindow(GetDlgItem(hwnd, IDC_PAGE_DESCRIPTION), next == Page::progress ? SW_HIDE : SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, IDC_PROGRESS), next == Page::progress ? SW_SHOW : SW_HIDE);
        layout();
    }
    void showUninstallConfirmation() {
        setPage(Page::uninstall, L"Uninstall " + std::wstring(UNLOCK_PRODUCT_DISPLAY_NAME),
            L"Remove phone connectivity, login startup, lock-screen unlock and saved password management.\r\n\r\n"
            L"The saved Windows password copy, paired iPhone registration and computer identity will be deleted. "
            L"Remove this computer from the iPhone app separately. Reinstallation requires setup and pairing again. A restart is required.");
        buttons(L"Back", L"Uninstall", L"Cancel");
    }
    void home(bool requestUninstall = false) {
        const auto status = adapter.inspect();
        const auto state = adapter.readState();
        const auto completion = adapter.readCompletion();
        const auto plan = determineMaintenancePlan(status, state ? &*state : nullptr,
            completion ? &*completion : nullptr, adapter.updateRebootRequired());
        installed = plan.action == MaintenanceAction::maintain;
        pending = plan.pending;
        if (plan.action == MaintenanceAction::blocked) throw ComponentError(plan.explanation);
        if (pending) {
            if (plan.attentionRequired) {
                setPage(Page::failure, L"Operation needs attention", plan.explanation);
                buttons(nullptr, plan.action == MaintenanceAction::restart ? L"Restart now" : L"Continue", L"Close");
            } else {
                setPage(Page::restart, L"Restart required", plan.explanation);
                buttons(nullptr, L"Restart now", L"Later");
            }
            return;
        }
        if (requestUninstall && !installed)
            throw ComponentError(L"The application is not installed. No removal was started.");
        if (installed) {
            log.clear();
            const auto incoming = adapter.binaryVersion(adapter.wizardPath());
            const auto existing = parseProductVersion(state->installedVersion);
            if (!existing) throw ComponentError(L"Installed product version is invalid.");
            const auto action = packageAction(incoming, *existing);
            reinstall = action == PackageAction::reinstall;
            const auto account = startupAccountLabel(state->targetSid, log);
            if (requestUninstall) showUninstallConfirmation();
            else {
                setPage(Page::home, std::wstring(UNLOCK_PRODUCT_DISPLAY_NAME) + L" installed", L"Installed version: " + state->installedVersion +
                    L"\r\nPackage version: " + incoming.text() + L"\r\nStartup account: " + account +
                    L"\r\nBluetooth tray: " + (status.trayRunning ? L"running" : L"not running") +
                    L"\r\n\r\nUpdate and reinstall preserve credentials and pairing. Uninstall removes Windows product data." +
                    (action == PackageAction::rejectDowngrade ?
                        L"\r\nThis package is older than the installed product. Downgrade is refused." : L""));
                buttons(L"Uninstall", action == PackageAction::rejectDowngrade ? nullptr : reinstall ? L"Reinstall" : L"Update", L"Cancel");
            }
        } else {
            log.clear();
            setPage(Page::home, L"Install " + std::wstring(UNLOCK_PRODUCT_DISPLAY_NAME),
                L"Use your iPhone to unlock this PC after signing in normally.\r\n\r\n"
                L"Setup installs phone connectivity, lock-screen unlock and saved password management. "
                L"Phone connectivity starts automatically when you sign in. Use your usual PIN or password after restarting Windows.");
            buttons(nullptr, L"Install", L"Cancel");
        }
    }
    void append(const Progress& progress) {
        log += progress.message + L"\r\n";
        text(IDC_DETAILS, log);
        SendDlgItemMessageW(hwnd, IDC_DETAILS, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
        SendDlgItemMessageW(hwnd, IDC_DETAILS, EM_SCROLLCARET, 0, 0);
        if (progress.percent >= 0) SendDlgItemMessageW(hwnd, IDC_PROGRESS, PBM_SETPOS, progress.percent, 0);
    }
    void start(WizardAction action, bool continuation = false) {
        if (continuation) {
            const auto state = adapter.readState();
            if (state && state->phase != WizardPhase::preparing) {
                if (releaseOperation) releaseOperation();
                if (state->phase == WizardPhase::finalizing) adapter.retryFinalization(*state);
                else adapter.runContinuation(*state);
                DestroyWindow(hwnd);
                return;
            }
        }
        busy = true; log.clear();
        setPage(Page::progress, L"Working — please wait", L"");
        button(IDC_BACK, nullptr); button(IDC_ACTION, nullptr); button(IDC_CANCEL_ACTION, L"Cancel", false);
        EnableMenuItem(GetSystemMenu(hwnd, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
        if (worker.joinable()) worker.join();
        worker = std::thread([this, action, continuation] {
            OperationResult result;
            std::wstring operationLog;
            try {
                ComponentTransaction transaction(adapter);
                auto progress = [this, &operationLog](int percent, const std::wstring& message) {
                    operationLog += message + L"\r\n";
                    auto update = std::make_unique<Progress>(Progress{percent, message});
                    if (!PostMessageW(hwnd, progressMessage, 0, reinterpret_cast<LPARAM>(update.get())))
                        throw ComponentError(L"Could not deliver installation progress to the window.");
                    update.release();
                };
                if (continuation) result = continueOperation(adapter, progress);
                else if (action == WizardAction::install) result = transaction.install(progress);
                else if (action == WizardAction::update) result = transaction.beginUpdate(progress);
                else result = transaction.beginUninstall(progress);
                {
                    auto state = adapter.readState();
                    if (state && state->phase != WizardPhase::installed)
                        adapter.writeCompletion({state->transactionId, state->targetSid, result.message, operationLog,
                            !result.success, false});
                }
            } catch (const std::exception& error) { result = {false, false, true, errorText(error)}; }
            adapter.setOperationLog({});
            auto value = std::make_unique<OperationResult>(std::move(result));
            if (PostMessageW(hwnd, completeMessage, 0, reinterpret_cast<LPARAM>(value.get()))) value.release();
            else OutputDebugStringW(L"Installer failed to deliver its final window message. Check the persisted operation result.\n");
        });
    }
    void complete(const OperationResult& result) {
        busy = false;
        EnableMenuItem(GetSystemMenu(hwnd, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_ENABLED);
        if (!result.success) {
            setPage(Page::failure, L"Operation failed", result.message);
            buttons(nullptr, nullptr, L"Close");
        } else if (result.rebootRequired) {
            setPage(Page::restart, L"Restart required", result.message);
            buttons(nullptr, L"Restart now", L"Later");
        } else {
            setPage(Page::result, L"Operation verified", result.message);
            buttons(nullptr, L"Finish", nullptr);
        }
    }
    void pollResult() {
        const auto record = adapter.readCompletion();
        if (!record || record->transactionId != resultId) {
            setPage(Page::progress, L"Waiting for verified operation result", L"No successful completion result has been recorded.");
            buttons(nullptr, nullptr, nullptr); return;
        }
        if (!record->finished) {
            setPage(Page::progress, L"Completing operation after restart", record->message + L"\r\n" + record->log);
            buttons(nullptr, nullptr, nullptr); return;
        }
        log = record->log;
        KillTimer(hwnd, 1);
        if (record->success && !adapter.environment().elevated) adapter.startTrayForCompletedOperation(resultId);
        setPage(record->success ? Page::result : Page::failure,
            record->success ? L"Operation completed and verified" : L"Operation failed",
            record->message);
        buttons(nullptr, L"Finish", nullptr);
    }
    void command(int id) {
        if (busy) return;
        if (id == IDC_CANCEL_ACTION) { DestroyWindow(hwnd); return; }
        if (id == IDCANCEL) {
            if (resultMode && (page == Page::result || page == Page::failure)) adapter.acknowledgeCompletion(resultId);
            DestroyWindow(hwnd); return;
        }
        if (id == IDC_BACK) {
            if (page == Page::home && installed) showUninstallConfirmation();
            else home();
            return;
        }
        if (id != IDC_ACTION) return;
        if (resultMode) { adapter.acknowledgeCompletion(resultId); DestroyWindow(hwnd); return; }
        if (page == Page::home) {
            if (!installed) start(WizardAction::install);
            else {
                setPage(Page::update, reinstall ? L"Reinstall " + std::wstring(UNLOCK_PRODUCT_DISPLAY_NAME) : L"Update " + std::wstring(UNLOCK_PRODUCT_DISPLAY_NAME),
                    L"Replace installed program files with the precompiled files supplied beside this installer. "
                    L"Your saved password, phone registration and startup target account will be preserved.\r\n\r\nA restart is required.");
                buttons(L"Back", reinstall ? L"Reinstall" : L"Update", L"Cancel");
            }
        } else if (page == Page::update) start(WizardAction::update);
        else if (page == Page::uninstall) start(WizardAction::uninstall);
        else if (page == Page::restart || (page == Page::failure && pending && adapter.updateRebootRequired())) {
            if (alert(hwnd, L"Restart Windows", L"Restart Windows now? Save your work first. Applications will not be forcibly closed.",
                TDCBF_OK_BUTTON | TDCBF_CANCEL_BUTTON, TD_WARNING_ICON) == IDOK) { adapter.restartWindows(); DestroyWindow(hwnd); }
        } else if (page == Page::failure && pending) start(WizardAction::blocked, true);
        else DestroyWindow(hwnd);
    }
};
INT_PTR CALLBACK procedure(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* window = reinterpret_cast<Window*>(GetWindowLongPtrW(hwnd, DWLP_USER));
    if (message == WM_INITDIALOG) {
        window = reinterpret_cast<Window*>(lParam); window->hwnd = hwnd;
        SetWindowLongPtrW(hwnd, DWLP_USER, reinterpret_cast<LONG_PTR>(window));
        SendDlgItemMessageW(hwnd, IDC_DETAILS, EM_SETLIMITTEXT, 1024 * 1024, 0);
    }
    if (!window) return FALSE;
    try {
        switch (message) {
            case WM_INITDIALOG:
                {
                    window->applyAppearance();
                }
                if (window->resultMode) { SetTimer(hwnd, 1, 500, nullptr); window->pollResult(); }
                else window->home(window->uninstallMode);
                return FALSE;
            case WM_CTLCOLORSTATIC:
                return unlock_windows::desktop_ui::readOnlyBackground(wParam);
            case WM_ERASEBKGND: return TRUE;
            case WM_PAINT: {
                PAINTSTRUCT paint{}; const auto dc = BeginPaint(hwnd, &paint);
                RECT area{}; GetClientRect(hwnd, &area);
                FillRect(dc, &area, GetSysColorBrush(COLOR_WINDOW));
                area.top = window->footerTop;
                FillRect(dc, &area, GetSysColorBrush(COLOR_3DFACE));
                area.bottom = area.top + 1;
                FillRect(dc, &area, GetSysColorBrush(COLOR_3DSHADOW));
                EndPaint(hwnd, &paint); return TRUE;
            }
            case WM_COMMAND: window->command(LOWORD(wParam)); return TRUE;
            case WM_TIMER: window->pollResult(); return TRUE;
            case progressMessage: {
                std::unique_ptr<Progress> value(reinterpret_cast<Progress*>(lParam));
                window->append(*value); return TRUE;
            }
            case completeMessage: {
                std::unique_ptr<OperationResult> value(reinterpret_cast<OperationResult*>(lParam));
                window->complete(*value); return TRUE;
            }
            case WM_CLOSE:
                if (!window->busy) {
                    if (window->resultMode && (window->page == Page::result || window->page == Page::failure))
                        window->adapter.acknowledgeCompletion(window->resultId);
                    DestroyWindow(hwnd);
                }
                return TRUE;
            case WM_DPICHANGED:
                {
                    const auto bounds = reinterpret_cast<RECT*>(lParam);
                    if (!SetWindowPos(hwnd, nullptr, bounds->left, bounds->top,
                        bounds->right - bounds->left, bounds->bottom - bounds->top, SWP_NOZORDER | SWP_NOACTIVATE))
                        throw ComponentError(L"Could not apply installer monitor bounds.");
                }
                unlock_windows::desktop_ui::scheduleDpiAppearance(hwnd, HIWORD(wParam));
                return FALSE;
            case unlock_windows::desktop_ui::kApplyDpiAppearance:
                window->applyAppearance(static_cast<UINT>(wParam));
                window->layout();
                return TRUE;
            case WM_DESTROY: PostQuitMessage(0); return TRUE;
        }
    } catch (const std::exception& error) {
        window->busy = false;
        window->setPage(Page::failure, L"Unable to continue", errorText(error));
        window->buttons(nullptr, nullptr, L"Close");
    }
    return FALSE;
}
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    DWORD processSession = 0;
    const bool sessionZero = !ProcessIdToSessionId(GetCurrentProcessId(), &processSession) || processSession == 0;
    bool headless = sessionZero;
    try {
        int count = 0; LPWSTR* args = CommandLineToArgvW(GetCommandLineW(), &count);
        if (!args) throw ComponentError(L"Cannot read command line.");
        std::wstring mode = count > 1 ? args[1] : L"";
        std::wstring transaction = count > 2 ? args[2] : L"";
        LocalFree(args);
        headless = sessionZero || mode == L"--resume-operation";
        Window window(modulePath());
        if (mode == L"--resume-operation") return transaction.empty() ? ERROR_INVALID_PARAMETER : resume(window.adapter, transaction);
        if (sessionZero) return ERROR_INVALID_PARAMETER;
        window.resultMode = mode == L"--show-result"; window.resultId = transaction;
        window.uninstallMode = mode == L"--uninstall";
        if ((!mode.empty() && !window.resultMode && !window.uninstallMode) ||
            (window.resultMode && transaction.empty()) || (window.uninstallMode && count != 2))
            throw ComponentError(L"Unsupported installer command line.");
        if (!window.resultMode && !window.adapter.environment().elevated) {
            SHELLEXECUTEINFOW request{sizeof(request)};
            request.lpVerb = L"runas"; request.lpFile = window.adapter.wizardPath().c_str(); request.nShow = SW_SHOWNORMAL;
            request.lpParameters = window.uninstallMode ? L"--uninstall" : nullptr;
            if (!ShellExecuteExW(&request)) {
                DWORD error = GetLastError();
                if (error == ERROR_CANCELLED) return 0;
                throw ComponentError(L"Elevation failed (Win32=" + std::to_wstring(error) + L").");
            }
            return 0;
        }
        std::unique_ptr<OperationLock> lock;
        if (!window.resultMode) lock = std::make_unique<OperationLock>();
        window.releaseOperation = [&lock] { lock.reset(); };
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_PROGRESS_CLASS}; InitCommonControlsEx(&controls);
        HWND hwnd = CreateDialogParamW(instance, MAKEINTRESOURCEW(IDD_WIZARD_PAGE), nullptr,
            procedure, reinterpret_cast<LPARAM>(&window));
        if (!hwnd) throw ComponentError(L"Could not create installer window (Win32=" + std::to_wstring(GetLastError()) + L").");
        unlock_windows::desktop_ui::centerOnActiveMonitor(hwnd);
        ShowWindow(hwnd, show); MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
            if (!IsDialogMessageW(hwnd, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        return 0;
    } catch (const std::exception& error) {
        if (!headless) {
            try { alert(nullptr, UNLOCK_PRODUCT_DISPLAY_NAME, errorText(error).c_str(), TDCBF_OK_BUTTON, TD_ERROR_ICON); }
            catch (const std::exception& displayError) {
                OutputDebugStringW((errorText(error) + L"\nUI display failure: " + errorText(displayError)).c_str());
            }
        }
        else OutputDebugStringW(errorText(error).c_str());
        return ERROR_INSTALL_FAILURE;
    }
}
