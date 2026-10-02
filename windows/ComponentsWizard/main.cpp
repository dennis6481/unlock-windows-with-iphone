// Created by Rui MA on 28 Sep 2026

#define UNICODE
#define _UNICODE
#include "ComponentTransaction.h"
#include "resource.h"
#include "../Resources/resource.h"
#include <Windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <sddl.h>
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
struct OperationLock {
    HANDLE value = nullptr;
    OperationLock() {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
            throw ComponentError(L"Cannot create operation lock security.");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        value = CreateMutexW(&attributes, FALSE, L"Global\\UnlockWindowsWithIPhone-ComponentOperation");
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
        record.success = result.success && !result.rebootRequired;
        if (record.success) {
            adapter.removeContinuationTask();
        }
        record.finished = true;
        adapter.writeCompletion(record);
        if (record.success && (state->phase == WizardPhase::uninstallPendingReboot || state->phase == WizardPhase::cleaningUp))
            adapter.clearState();
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
    bool resultMode = false, busy = false, installed = false, pending = false;
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
        button(IDC_BACK, left);
        button(IDC_ACTION, action, true, cancel == nullptr);
        button(IDC_CANCEL_ACTION, cancel, true, cancel != nullptr);
        if (cancel) SetFocus(GetDlgItem(hwnd, IDC_CANCEL_ACTION));
        else if (action) SetFocus(GetDlgItem(hwnd, IDC_ACTION));
    }
    void setPage(Page next, const std::wstring& title, const std::wstring& details) {
        page = next; text(IDC_MAIN_INSTRUCTION, title); text(IDC_DETAILS, details);
        ShowWindow(GetDlgItem(hwnd, IDC_PROGRESS), next == Page::progress ? SW_SHOW : SW_HIDE);
    }
    void home() {
        const auto status = adapter.inspect();
        const auto state = adapter.readState();
        if (!status.observationValid || (status.statePresent && !status.stateValid))
            throw ComponentError(status.observationValid ? status.stateError : status.observationError);
        installed = state && state->phase == WizardPhase::installed;
        const auto completion = adapter.readCompletion();
        const bool unfinishedHandoff = state && completion && completion->transactionId == state->transactionId && !completion->finished;
        pending = state && (unfinishedHandoff || state->phase == WizardPhase::installPendingReboot ||
            state->phase == WizardPhase::updatePendingReboot || state->phase == WizardPhase::updating ||
            state->phase == WizardPhase::uninstallPendingReboot || state->phase == WizardPhase::cleaningUp);
        if (pending) {
            if (!state->lastError.empty()) {
                setPage(Page::failure, L"Operation needs attention", state->lastError + L"\r\n\r\nThe transaction is preserved. No other operation may start.");
                buttons(nullptr, adapter.updateRebootRequired() ? L"Restart now" : L"Continue", L"Close");
            } else if (unfinishedHandoff && !adapter.updateRebootRequired() && state->phase == WizardPhase::installed) {
                setPage(Page::failure, L"Completion handoff interrupted", L"Continue verification of the existing transaction. No new operation may start.");
                buttons(nullptr, L"Continue", L"Close");
            } else {
                setPage(Page::restart, L"Restart required",
                    L"A component operation is pending. Restart Windows to complete it. No other operation can start.");
                buttons(nullptr, L"Restart now", L"Later");
            }
            return;
        }
        if (state && !installed) throw ComponentError(L"An interrupted transaction is preserved for diagnosis. No automatic removal or rollback will be performed.\r\n" + state->lastError);
        if (installed) {
            if (!status.isCompleteInstallation()) throw ComponentError(L"Core installation verification failed. No destructive recovery will run automatically.");
            setPage(Page::home, L"Installed", L"Unlock Windows with iPhone is installed.\r\n\r\nStartup account SID: " +
                (state->targetSid.empty() ? L"Will be captured from the physical console during update" : state->targetSid) +
                L"\r\nBluetooth tray: " + (status.trayRunning ? L"running" : L"not running") +
                L"\r\n\r\nUpdate keeps your saved credential and phone registration. Uninstall removes the saved credential.");
            buttons(L"Uninstall", L"Update", L"Cancel");
        } else {
            if (status.hasAnyArtifacts()) throw ComponentError(L"Unregistered component artifacts exist. Installation has not started.");
            setPage(Page::home, L"Install Unlock Windows with iPhone",
                L"Install phone connectivity, lock-screen unlock and saved Windows credential management.\r\n\r\n"
                L"Phone connectivity will start automatically, without elevation, when the target console user signs in. "
                L"Use your normal PIN or password for the first sign-in. A restart is required.");
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
                if (continuation && result.success && !result.rebootRequired) {
                    auto state = adapter.readState();
                    if (!state) throw ComponentError(L"Completion transaction disappeared.");
                    adapter.removeContinuationTask();
                    adapter.writeCompletion({state->transactionId, state->targetSid, result.message, operationLog, true, true});
                    if (state->phase == WizardPhase::cleaningUp) adapter.clearState();
                } else {
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
            setPage(Page::failure, L"Operation failed", result.message + L"\r\n\r\n" + log);
            buttons(nullptr, nullptr, L"Close");
        } else if (result.rebootRequired) {
            setPage(Page::restart, L"Restart required", result.message + L"\r\n\r\n" + log);
            buttons(nullptr, L"Restart now", L"Later");
        } else {
            setPage(Page::result, L"Operation verified", result.message + L"\r\n\r\n" + log);
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
        KillTimer(hwnd, 1);
        if (record->success) adapter.startTrayForCompletedOperation(resultId);
        setPage(record->success ? Page::result : Page::failure,
            record->success ? L"Operation completed and verified" : L"Operation failed",
            record->message + L"\r\n\r\n" + record->log);
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
            if (page == Page::home && installed) {
                setPage(Page::uninstall, L"Uninstall Unlock Windows with iPhone",
                    L"Remove phone connectivity, login startup, lock-screen unlock, credential manager and maintenance shortcuts.\r\n\r\n"
                    L"The saved Windows password copy will be cleared before removal. Phone public-key registration will be retained. A restart is required.");
                buttons(L"Back", L"Uninstall", L"Cancel");
            } else home();
            return;
        }
        if (id != IDC_ACTION) return;
        if (resultMode) { adapter.acknowledgeCompletion(resultId); DestroyWindow(hwnd); return; }
        if (page == Page::home) {
            if (!installed) start(WizardAction::install);
            else {
                setPage(Page::update, L"Update Unlock Windows with iPhone",
                    L"Replace installed program files with the precompiled files supplied beside this installer. "
                    L"Your saved password, phone registration and startup target account will be preserved.\r\n\r\nA restart is required.");
                buttons(L"Back", L"Update", L"Cancel");
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
                    const auto instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hwnd, GWLP_HINSTANCE));
                    const auto largeIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_UNLOCK_APP));
                    const auto smallIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_UNLOCK_APP),
                        IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED));
                    if (!largeIcon || !smallIcon) throw ComponentError(L"Cannot load the application icon.");
                    SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(largeIcon));
                    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
                }
                if (window->resultMode) { SetTimer(hwnd, 1, 500, nullptr); window->pollResult(); }
                else window->home();
                return FALSE;
            case WM_CTLCOLORSTATIC:
                if (reinterpret_cast<HWND>(lParam) == GetDlgItem(hwnd, IDC_DETAILS)) {
                    HDC dc = reinterpret_cast<HDC>(wParam);
                    SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
                    SetBkColor(dc, GetSysColor(COLOR_WINDOW));
                    return reinterpret_cast<INT_PTR>(GetSysColorBrush(COLOR_WINDOW));
                }
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
            case WM_DPICHANGED: return FALSE;
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
        if ((!mode.empty() && !window.resultMode) || (window.resultMode && transaction.empty()))
            throw ComponentError(L"Unsupported installer command line.");
        if (!window.resultMode && !window.adapter.environment().elevated) {
            SHELLEXECUTEINFOW request{sizeof(request)};
            request.lpVerb = L"runas"; request.lpFile = window.adapter.wizardPath().c_str(); request.nShow = SW_SHOWNORMAL;
            if (!ShellExecuteExW(&request)) {
                DWORD error = GetLastError();
                if (error == ERROR_CANCELLED) return 0;
                throw ComponentError(L"Elevation failed (Win32=" + std::to_wstring(error) + L").");
            }
            return 0;
        }
        std::unique_ptr<OperationLock> lock;
        if (!window.resultMode) lock = std::make_unique<OperationLock>();
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_PROGRESS_CLASS}; InitCommonControlsEx(&controls);
        HWND hwnd = CreateDialogParamW(instance, MAKEINTRESOURCEW(IDD_WIZARD_PAGE), nullptr,
            procedure, reinterpret_cast<LPARAM>(&window));
        if (!hwnd) throw ComponentError(L"Could not create installer window (Win32=" + std::to_wstring(GetLastError()) + L").");
        ShowWindow(hwnd, show); MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
            if (!IsDialogMessageW(hwnd, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        return 0;
    } catch (const std::exception& error) {
        if (!headless) MessageBoxW(nullptr, errorText(error).c_str(), L"Unlock Windows with iPhone", MB_OK | MB_ICONERROR);
        else OutputDebugStringW(errorText(error).c_str());
        return ERROR_INSTALL_FAILURE;
    }
}
