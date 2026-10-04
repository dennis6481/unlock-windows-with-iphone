// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE
#include "ComponentTransaction.h"
#include "resource.h"
#include "../Resources/resource.h"
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
    return L"Name unavailable; see Technical details";
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
    explicit Window(std::filesystem::path path) : adapter(std::move(path)) {}
    ~Window() { if (worker.joinable()) worker.join(); }
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
    }
    void layout() {
        const bool progress = page == Page::progress;
        const bool expanded = !progress && !log.empty() && IsDlgButtonChecked(hwnd, IDC_LOG_TOGGLE) == BST_CHECKED;
        const LONG height = progress ? 218 : expanded ? 242 : 172;
        const auto place = [&](int id, RECT area) {
            if (!MapDialogRect(hwnd, &area) || !SetWindowPos(GetDlgItem(hwnd, id), nullptr,
                area.left, area.top, area.right - area.left, area.bottom - area.top, SWP_NOZORDER | SWP_NOACTIVATE))
                throw ComponentError(L"Could not lay out installer controls.");
        };
        place(IDC_DETAILS, {14, progress ? 42 : 134, 306, progress ? 160 : 198});
        place(IDC_PROGRESS, {14, 170, 306, 177});
        place(IDC_BACK, {124, height - 28, 182, height - 12});
        place(IDC_ACTION, {190, height - 28, 252, height - 12});
        place(IDC_CANCEL_ACTION, {260, height - 28, 306, height - 12});
        ShowWindow(GetDlgItem(hwnd, IDC_DETAILS), progress || expanded ? SW_SHOW : SW_HIDE);
        RECT size{0, 0, 320, height}, previous{};
        if (!MapDialogRect(hwnd, &size) || !AdjustWindowRectExForDpi(&size,
            static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_STYLE)), FALSE,
            static_cast<DWORD>(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)), GetDpiForWindow(hwnd)) ||
            !GetWindowRect(hwnd, &previous)) throw ComponentError(L"Could not measure installer window.");
        const LONG width = size.right - size.left, outerHeight = size.bottom - size.top;
        MONITORINFO monitor{sizeof(monitor)};
        if (!GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &monitor))
            throw ComponentError(L"Could not find installer display bounds.");
        const LONG x = std::max(monitor.rcWork.left, std::min(
            previous.left + ((previous.right - previous.left) - width) / 2, monitor.rcWork.right - width));
        const LONG y = std::max(monitor.rcWork.top, std::min(
            previous.top + ((previous.bottom - previous.top) - outerHeight) / 2, monitor.rcWork.bottom - outerHeight));
        if (!SetWindowPos(hwnd, nullptr, x, y, width, outerHeight, SWP_NOZORDER | SWP_NOACTIVATE))
            throw ComponentError(L"Could not resize installer window.");
    }
    void setPage(Page next, const std::wstring& title, const std::wstring& details) {
        page = next; text(IDC_MAIN_INSTRUCTION, title); text(IDC_PAGE_DESCRIPTION, details);
        if (!SetWindowTextW(hwnd, next == Page::home && installed ? title.c_str() : L"Unlock Windows with iPhone\u00ae Setup"))
            throw ComponentError(L"Could not set installer window title.");
        text(IDC_DETAILS, next == Page::progress ? details : log);
        ShowWindow(GetDlgItem(hwnd, IDC_PAGE_DESCRIPTION), next == Page::progress ? SW_HIDE : SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, IDC_LOG_TOGGLE), next != Page::progress && !log.empty() ? SW_SHOW : SW_HIDE);
        CheckDlgButton(hwnd, IDC_LOG_TOGGLE, next == Page::failure ? BST_CHECKED : BST_UNCHECKED);
        ShowWindow(GetDlgItem(hwnd, IDC_PROGRESS), next == Page::progress ? SW_SHOW : SW_HIDE);
        layout();
    }
    void showUninstallConfirmation() {
        setPage(Page::uninstall, L"Uninstall Unlock Windows with iPhone\u00ae",
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
                setPage(Page::home, L"Unlock Windows with iPhone\u00ae installed", L"Installed version: " + state->installedVersion +
                    L"\r\nPackage version: " + incoming.text() + L"\r\nStartup account: " + account +
                    L"\r\nBluetooth tray: " + (status.trayRunning ? L"running" : L"not running") +
                    L"\r\n\r\nUpdate and reinstall preserve credentials and pairing. Uninstall removes Windows product data.");
                buttons(L"Uninstall", action == PackageAction::rejectDowngrade ? nullptr : reinstall ? L"Reinstall" : L"Update", L"Cancel");
                if (action == PackageAction::rejectDowngrade) log += L"\r\nThis package is older than the installed product. Downgrade is refused.";
            }
            text(IDC_LOG_TOGGLE, L"Technical details");
        } else {
            log.clear();
            setPage(Page::home, L"Install Unlock Windows with iPhone\u00ae",
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
        text(IDC_LOG_TOGGLE, L"Operation details");
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
        if (id == IDC_LOG_TOGGLE) {
            layout();
            return;
        }
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
                setPage(Page::update, reinstall ? L"Reinstall Unlock Windows with iPhone\u00ae" : L"Update Unlock Windows with iPhone\u00ae",
                    L"Replace installed program files with the precompiled files supplied beside this installer. "
                    L"Your saved password, phone registration and startup target account will be preserved.\r\n\r\nA restart is required.");
                buttons(L"Back", reinstall ? L"Reinstall" : L"Update", L"Cancel");
            }
        } else if (page == Page::update) start(WizardAction::update);
        else if (page == Page::uninstall) start(WizardAction::uninstall);
        else if (page == Page::restart || (page == Page::failure && pending && adapter.updateRebootRequired())) {
            if (MessageBoxW(hwnd, L"Restart Windows now? Save your work first. Applications will not be forcibly closed.",
                L"Restart Windows", MB_OKCANCEL | MB_ICONQUESTION) == IDOK) { adapter.restartWindows(); DestroyWindow(hwnd); }
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
                    window->appearance.apply(hwnd, IDC_MAIN_INSTRUCTION);
                }
                if (window->resultMode) { SetTimer(hwnd, 1, 500, nullptr); window->pollResult(); }
                else window->home(window->uninstallMode);
                return FALSE;
            case WM_CTLCOLORSTATIC:
                if (reinterpret_cast<HWND>(lParam) == GetDlgItem(hwnd, IDC_DETAILS) ||
                    reinterpret_cast<HWND>(lParam) == GetDlgItem(hwnd, IDC_PAGE_DESCRIPTION))
                    return unlock_windows::desktop_ui::readOnlyBackground(wParam);
                return FALSE;
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
                unlock_windows::desktop_ui::scheduleDpiAppearance(hwnd, HIWORD(wParam));
                return FALSE;
            case unlock_windows::desktop_ui::kApplyDpiAppearance:
                window->appearance.apply(hwnd, IDC_MAIN_INSTRUCTION, static_cast<UINT>(wParam));
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
        if (!headless) MessageBoxW(nullptr, errorText(error).c_str(), L"Unlock Windows with iPhone\u00ae", MB_OK | MB_ICONERROR);
        else OutputDebugStringW(errorText(error).c_str());
        return ERROR_INSTALL_FAILURE;
    }
}
