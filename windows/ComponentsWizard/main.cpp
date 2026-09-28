#define UNICODE
#define _UNICODE

#include "ComponentState.h"
#include "ComponentTransaction.h"
#include "WindowsAdapter.h"
#include "resource.h"

#include <Windows.h>
#include <commctrl.h>
#include <objbase.h>
#include <prsht.h>

#include <cstdint>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

namespace {

using namespace unlock::components;

constexpr wchar_t kWindowTitle[] = L"Unlock Windows with iPhone Components";
constexpr UINT kProgressMessage = WM_APP + 1;
constexpr UINT kOperationCompleteMessage = WM_APP + 2;
constexpr UINT kFocusWizardButtonMessage = WM_APP + 3;
constexpr int kWizardNextControlId = 0x3024;
constexpr int kWizardFinishControlId = 0x3025;

enum class PageKind {
    status,
    confirmation,
    progress,
    result,
};

struct ProgressUpdate final {
    int percent = 0;
    std::wstring message;
};

std::filesystem::path currentModulePath() {
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            throw ComponentError(L"Could not determine the Components Wizard executable path.");
        }
        if (length < buffer.size() - 1) {
            return std::filesystem::path(std::wstring(buffer.data(), length));
        }
        buffer.resize(buffer.size() * 2);
    }
}

std::wstring exceptionText(const std::exception& error) {
    if (const auto* componentError = dynamic_cast<const ComponentError*>(&error)) {
        return componentError->wideWhat();
    }
    const auto* text = error.what();
    std::wstring result;
    while (*text != '\0') {
        result.push_back(static_cast<unsigned char>(*text));
        ++text;
    }
    return result.empty() ? L"Unexpected component wizard error." : result;
}

class ScopedBitmap final {
public:
    explicit ScopedBitmap(const HBITMAP bitmap) : bitmap_(bitmap) {}
    ScopedBitmap(const ScopedBitmap&) = delete;
    ScopedBitmap& operator=(const ScopedBitmap&) = delete;
    ~ScopedBitmap() {
        if (bitmap_ != nullptr) {
            DeleteObject(bitmap_);
        }
    }

    [[nodiscard]] HBITMAP get() const noexcept {
        return bitmap_;
    }

private:
    HBITMAP bitmap_ = nullptr;
};

HBITMAP createWatermarkBitmap() {
    constexpr int width = 164;
    constexpr int height = 314;

    BITMAPINFO bitmapInfo{};
    bitmapInfo.bmiHeader.biSize = sizeof(bitmapInfo.bmiHeader);
    bitmapInfo.bmiHeader.biWidth = width;
    bitmapInfo.bmiHeader.biHeight = -height;
    bitmapInfo.bmiHeader.biPlanes = 1;
    bitmapInfo.bmiHeader.biBitCount = 32;
    bitmapInfo.bmiHeader.biCompression = BI_RGB;

    void* pixels = nullptr;
    const auto bitmap = CreateDIBSection(
        nullptr,
        &bitmapInfo,
        DIB_RGB_COLORS,
        &pixels,
        nullptr,
        0
    );
    if (bitmap == nullptr || pixels == nullptr) {
        if (bitmap != nullptr) {
            DeleteObject(bitmap);
        }
        throw ComponentError(L"Could not create the wizard sidebar bitmap.");
    }

    auto* colors = static_cast<std::uint32_t*>(pixels);
    for (int y = 0; y < height; ++y) {
        const auto blue = static_cast<std::uint8_t>(112 - (y * 32 / height));
        const auto green = static_cast<std::uint8_t>(48 - (y * 18 / height));
        const auto red = static_cast<std::uint8_t>(18 - (y * 8 / height));
        for (int x = 0; x < width; ++x) {
            auto color = RGB(red, green, blue);
            if (((x + y) / 16) % 2 == 0) {
                color = RGB(red + 5, green + 5, blue + 5);
            }
            if ((x - width / 2) * (x - width / 2) + (y - 78) * (y - 78) < 34 * 34 &&
                (x - width / 2) * (x - width / 2) + (y - 78) * (y - 78) > 27 * 27) {
                color = RGB(228, 240, 248);
            }
            colors[y * width + x] = color;
        }
    }

    return bitmap;
}

class WizardSession final {
public:
    WizardSession(const HINSTANCE instance, const bool resumeUninstall)
        : instance_(instance),
          resumeUninstall_(resumeUninstall),
          adapter_(currentModulePath()),
          transaction_(adapter_) {
        initialize();
    }

    ~WizardSession() {
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    int show() {
        createPages();
        if (pages_.empty()) {
            throw ComponentError(L"Could not create any Components Wizard page.");
        }

        const ScopedBitmap watermark(createWatermarkBitmap());
        PROPSHEETHEADERW header{};
        header.dwSize = sizeof(header);
        header.dwFlags = PSH_WIZARD97 |
            PSH_WIZARDHASFINISH |
            PSH_WATERMARK |
            PSH_USEHBMWATERMARK |
            PSH_PROPSHEETPAGE;
        header.hwndParent = nullptr;
        header.hInstance = instance_;
        header.pszCaption = kWindowTitle;
        header.nPages = static_cast<UINT>(pages_.size());
        header.ppsp = pages_.data();
        header.hbmWatermark = watermark.get();

        const auto result = PropertySheetW(&header);
        if (result == -1) {
            throw ComponentError(L"Could not create the Components Wizard property sheet.");
        }
        return 0;
    }

private:
    struct PageSpec final {
        PageKind kind = PageKind::status;
        std::wstring title;
    };

    void initialize() {
        try {
            refreshPlan();
            if (plan_.action == WizardAction::resetStaleState) {
                const auto reset = transaction_.resetStaleState();
                if (!reset.success) {
                    plan_ = {
                        WizardAction::blocked,
                        L"Stale transaction state could not be removed",
                        reset.message,
                        false,
                    };
                } else {
                    refreshPlan();
                }
            }

            if (resumeUninstall_ && plan_.action != WizardAction::cleanup) {
                plan_ = {
                    WizardAction::blocked,
                    L"Nothing is waiting for uninstall cleanup",
                    L"The --resume-uninstall entry point was called, but the saved transaction is not waiting for post-restart cleanup.",
                    false,
                };
            }
        } catch (const std::exception& error) {
            plan_ = {
                WizardAction::blocked,
                L"Component status could not be initialized",
                exceptionText(error),
                false,
            };
        }
    }

    void refreshPlan() {
        snapshot_ = adapter_.inspect();
        plan_ = determineRecoveryPlan(snapshot_);
    }

    void createPages() {
        pageSpecs_.clear();
        if (!resumeUninstall_) {
            pageSpecs_.push_back({PageKind::status, L"Component status"});
        }

        if (resumeUninstall_ || plan_.action == WizardAction::cleanup) {
            pageSpecs_.push_back({PageKind::progress, L"Completing uninstall"});
        } else if (plan_.action != WizardAction::blocked) {
            pageSpecs_.push_back({PageKind::confirmation, L"Confirm operation"});
            pageSpecs_.push_back({PageKind::progress, L"Applying changes"});
        }

        pageSpecs_.push_back({PageKind::result, L"Operation result"});

        pages_.clear();
        pages_.reserve(pageSpecs_.size());
        for (const auto& spec : pageSpecs_) {
            PROPSHEETPAGEW page{};
            page.dwSize = sizeof(page);
            page.dwFlags = PSP_DEFAULT | PSP_HIDEHEADER;
            page.hInstance = instance_;
            page.pszTemplate = MAKEINTRESOURCEW(IDD_WIZARD_PAGE);
            page.pfnDlgProc = pageProcedure;
            page.lParam = reinterpret_cast<LPARAM>(this);
            pages_.push_back(page);
        }
    }

    static INT_PTR CALLBACK pageProcedure(
        const HWND page,
        const UINT message,
        const WPARAM wordParam,
        const LPARAM longParam
    ) {
        auto* session = reinterpret_cast<WizardSession*>(GetWindowLongPtrW(page, DWLP_USER));
        if (message == WM_INITDIALOG) {
            const auto* propertyPage = reinterpret_cast<const PROPSHEETPAGEW*>(longParam);
            session = reinterpret_cast<WizardSession*>(propertyPage->lParam);
            SetWindowLongPtrW(page, DWLP_USER, reinterpret_cast<LONG_PTR>(session));
            if (session != nullptr) {
                const auto focusWasSet = session->initializePage(page, session->pageIndex(page));
                return focusWasSet ? FALSE : TRUE;
            }
            return TRUE;
        }
        if (session == nullptr) {
            return FALSE;
        }
        return session->handlePageMessage(page, message, wordParam, longParam);
    }

    std::size_t pageIndex(const HWND page) const {
        for (std::size_t index = 0; index < pageWindows_.size(); ++index) {
            if (pageWindows_[index] == page) {
                return index;
            }
        }
        return pageWindows_.size();
    }

    bool initializePage(const HWND page, const std::size_t index) {
        if (index == pageWindows_.size()) {
            pageWindows_.push_back(page);
        } else {
            pageWindows_[index] = page;
        }
        updatePage(page, pageSpecs_[index].kind);
        return focusDefaultWizardButton(page);
    }

    INT_PTR handlePageMessage(
        const HWND page,
        const UINT message,
        const WPARAM wordParam,
        const LPARAM longParam
    ) {
        if (message == kFocusWizardButtonMessage) {
            focusDefaultWizardButton(page);
            return TRUE;
        }
        if (message == kProgressMessage) {
            auto* update = reinterpret_cast<ProgressUpdate*>(longParam);
            if (update != nullptr) {
                SetDlgItemTextW(page, IDC_MAIN_INSTRUCTION, update->message.c_str());
                SendDlgItemMessageW(page, IDC_PROGRESS, PBM_SETPOS, update->percent, 0);
                delete update;
            }
            return TRUE;
        }
        if (message == kOperationCompleteMessage) {
            finishOperation(page);
            return TRUE;
        }

        if (message != WM_NOTIFY) {
            return FALSE;
        }

        const auto* header = reinterpret_cast<const NMHDR*>(longParam);
        if (header == nullptr) {
            return FALSE;
        }
        switch (header->code) {
            case PSN_SETACTIVE:
                updatePage(page, pageSpecs_[pageIndex(page)].kind);
                focusDefaultWizardButton(page);
                return TRUE;

            case PSN_WIZNEXT:
                if (pageSpecs_[pageIndex(page)].kind == PageKind::result && restartAvailable_) {
                    return handleRestart(page);
                }
                SetWindowLongPtrW(page, DWLP_MSGRESULT, 0);
                return TRUE;

            case PSN_QUERYCANCEL:
                SetWindowLongPtrW(page, DWLP_MSGRESULT, operationRunning_ ? 1 : 0);
                return TRUE;

            case PSN_WIZFINISH:
                return handleFinish(page);

            default:
                return FALSE;
        }
    }

    void updatePage(const HWND page, const PageKind kind) {
        switch (kind) {
            case PageKind::status:
                showStatusPage(page);
                break;
            case PageKind::confirmation:
                showConfirmationPage(page);
                break;
            case PageKind::progress:
                showProgressPage(page);
                break;
            case PageKind::result:
                showResultPage(page);
                break;
        }
    }

    bool focusDefaultWizardButton(const HWND page) const {
        const auto propertySheet = GetParent(page);
        HWND button = GetDlgItem(propertySheet, kWizardFinishControlId);
        if (button == nullptr || !IsWindowVisible(button) || !IsWindowEnabled(button)) {
            button = GetDlgItem(propertySheet, kWizardNextControlId);
        }
        if (button == nullptr || !IsWindowVisible(button) || !IsWindowEnabled(button)) {
            return false;
        }
        SetFocus(button);
        return GetFocus() == button;
    }

    void setDetails(const HWND page, const std::wstring& instruction, const std::wstring& details) {
        SetDlgItemTextW(page, IDC_MAIN_INSTRUCTION, instruction.c_str());
        SetDlgItemTextW(page, IDC_DETAILS, details.c_str());
        ShowWindow(GetDlgItem(page, IDC_PROGRESS), SW_HIDE);
    }

    void setWizardButtons(
        const HWND page,
        const DWORD enabledButtons,
        const DWORD visibleButtons
    ) {
        const auto propertySheet = GetParent(page);
        SendMessageW(
            propertySheet,
            PSM_SHOWWIZBUTTONS,
            visibleButtons,
            PSWIZB_BACK | PSWIZB_NEXT | PSWIZB_FINISH | PSWIZB_CANCEL
        );
        PropSheet_SetWizButtons(propertySheet, enabledButtons);
        PostMessageW(page, kFocusWizardButtonMessage, 0, 0);
    }

    void setButtonText(const HWND page, const int button, const wchar_t* text) {
        SendMessageW(GetParent(page), PSM_SETBUTTONTEXT, button, reinterpret_cast<LPARAM>(text));
    }

    void showStatusPage(const HWND page) {
        setDetails(page, plan_.title, plan_.explanation);
        if (plan_.action == WizardAction::blocked) {
            setWizardButtons(page, PSWIZB_FINISH, PSWIZB_FINISH);
            setButtonText(page, PSBTN_FINISH, L"Finish");
        } else {
            setWizardButtons(page, PSWIZB_NEXT, PSWIZB_NEXT | PSWIZB_CANCEL);
            setButtonText(page, PSBTN_NEXT, nextButtonText());
            setButtonText(page, PSBTN_CANCEL, L"Cancel");
        }
    }

    void showConfirmationPage(const HWND page) {
        std::wstring instruction;
        std::wstring details = plan_.explanation + L"\r\n\r\n";
        switch (plan_.action) {
            case WizardAction::install:
                instruction = L"Confirm installation";
                details += L"The components will be installed now. Windows needs to restart before they can be used.";
                break;
            case WizardAction::uninstall:
                instruction = L"Confirm removal";
                details += L"The components will be disabled now. Windows needs to restart to complete removal. The remaining component files will be removed after you sign in.";
                break;
            case WizardAction::recover:
                instruction = L"Confirm repair";
                details += L"The wizard will restore Windows to the state saved before the interrupted operation. Unknown files and settings will not be removed.";
                break;
            default:
                instruction = L"Confirm operation";
                break;
        }
        setDetails(page, instruction, details);
        setWizardButtons(page, PSWIZB_BACK | PSWIZB_NEXT, PSWIZB_BACK | PSWIZB_NEXT | PSWIZB_CANCEL);
        setButtonText(page, PSBTN_NEXT, nextButtonText());
        setButtonText(page, PSBTN_CANCEL, L"Cancel");
    }

    void showProgressPage(const HWND page) {
        SetDlgItemTextW(page, IDC_MAIN_INSTRUCTION, L"Working...");
        SetDlgItemTextW(page, IDC_DETAILS, L"Please wait while the wizard applies the selected changes.");
        ShowWindow(GetDlgItem(page, IDC_PROGRESS), SW_SHOW);
        SendDlgItemMessageW(page, IDC_PROGRESS, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendDlgItemMessageW(page, IDC_PROGRESS, PBM_SETPOS, 0, 0);
        setWizardButtons(page, 0, 0);
        if (!operationStarted_) {
            startOperation(page);
        }
    }

    void showResultPage(const HWND page) {
        OperationResult result;
        {
            std::lock_guard lock(resultMutex_);
            if (operationResult_) {
                result = *operationResult_;
            } else {
                result = {false, false, false, L"The operation did not produce a result."};
            }
        }

        const wchar_t* instruction = result.success ? L"Operation complete" : L"Operation could not be completed";
        std::wstring details;
        if (result.success) {
            switch (plan_.action) {
                case WizardAction::install:
                    instruction = L"Installation complete";
                    details = L"The components were installed successfully. Windows needs to restart to apply the changes. Select Restart to restart now, or Finish to close the wizard.";
                    break;
                case WizardAction::uninstall:
                    instruction = L"Removal ready for restart";
                    details = L"The components have been disabled. Windows needs to restart to complete removal. The remaining component files will be removed after you sign in. Select Restart to restart now, or Finish to close the wizard.";
                    break;
                case WizardAction::cleanup:
                    instruction = L"Removal complete";
                    details = L"The components have been completely removed from Windows.";
                    break;
                case WizardAction::recover:
                case WizardAction::resetStaleState:
                    instruction = L"Repair complete";
                    details = L"The previous operation was repaired successfully.";
                    break;
                default:
                    details = L"The selected operation completed successfully.";
                    break;
            }
        } else {
            details = L"The wizard could not complete this operation.";
            if (!result.message.empty()) {
                details += L" Details: " + result.message;
            }
        }
        if (!result.success && result.statePreserved) {
            details += L" Your recovery information was preserved. Reopen the wizard to retry safely.";
        }
        setDetails(page, instruction, details);
        restartAvailable_ = result.success && result.rebootRequired;
        const auto resultButtons = restartAvailable_ ? PSWIZB_NEXT | PSWIZB_FINISH : PSWIZB_FINISH;
        setWizardButtons(page, resultButtons, resultButtons);
        setButtonText(page, PSBTN_NEXT, L"Restart");
        setButtonText(page, PSBTN_FINISH, L"Finish");
    }

    const wchar_t* nextButtonText() const noexcept {
        switch (plan_.action) {
            case WizardAction::install:
                return L"Install";
            case WizardAction::uninstall:
                return L"Uninstall";
            case WizardAction::recover:
                return L"Repair";
            case WizardAction::cleanup:
                return L"Complete removal";
            default:
                return L"Next";
        }
    }

    void startOperation(const HWND progressPage) {
        operationStarted_ = true;
        operationRunning_ = true;
        progressPage_ = progressPage;
        try {
            worker_ = std::thread([this] {
                OperationResult result;
                const auto callback = [this](const int percent, const std::wstring& message) {
                    auto* update = new ProgressUpdate{percent, message};
                    if (!PostMessageW(progressPage_, kProgressMessage, 0, reinterpret_cast<LPARAM>(update))) {
                        delete update;
                    }
                };
                try {
                    switch (plan_.action) {
                        case WizardAction::install:
                            result = transaction_.install(callback);
                            break;
                        case WizardAction::uninstall:
                            result = transaction_.beginUninstall(callback);
                            break;
                        case WizardAction::cleanup:
                            result = transaction_.completeUninstall(callback);
                            break;
                        case WizardAction::recover:
                            result = transaction_.recover(callback);
                            break;
                        default:
                            result = {false, false, false, L"This action cannot be started from the current wizard state."};
                            break;
                    }
                } catch (const std::exception& error) {
                    result = {false, false, true, exceptionText(error)};
                } catch (...) {
                    result = {false, false, true, L"An unexpected error interrupted the component operation."};
                }
                {
                    std::lock_guard lock(resultMutex_);
                    operationResult_ = std::move(result);
                }
                PostMessageW(progressPage_, kOperationCompleteMessage, 0, 0);
            });
        } catch (const std::exception& error) {
            operationRunning_ = false;
            std::lock_guard lock(resultMutex_);
            operationResult_ = {false, false, true, exceptionText(error)};
            PostMessageW(progressPage_, kOperationCompleteMessage, 0, 0);
        }
    }

    void finishOperation(const HWND page) {
        if (worker_.joinable()) {
            worker_.join();
        }
        operationRunning_ = false;
        SetDlgItemTextW(page, IDC_MAIN_INSTRUCTION, L"Operation finished.");
        SendDlgItemMessageW(page, IDC_PROGRESS, PBM_SETPOS, 100, 0);
        PropSheet_SetWizButtons(GetParent(page), PSWIZB_NEXT);
        PropSheet_PressButton(GetParent(page), PSBTN_NEXT);
    }

    INT_PTR handleRestart(const HWND page) {
        try {
            adapter_.restartWindows();
        } catch (const std::exception& error) {
            MessageBoxW(page, exceptionText(error).c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        }
        SetWindowLongPtrW(page, DWLP_MSGRESULT, 1);
        return TRUE;
    }

    INT_PTR handleFinish(const HWND page) {
        SetWindowLongPtrW(page, DWLP_MSGRESULT, 0);
        return TRUE;
    }

    HINSTANCE instance_ = nullptr;
    bool resumeUninstall_ = false;
    WindowsAdapter adapter_;
    ComponentTransaction transaction_;
    ComponentSnapshot snapshot_;
    RecoveryPlan plan_;
    std::vector<PageSpec> pageSpecs_;
    std::vector<PROPSHEETPAGEW> pages_;
    std::vector<HWND> pageWindows_;

    std::thread worker_;
    std::mutex resultMutex_;
    std::optional<OperationResult> operationResult_;
    HWND progressPage_ = nullptr;
    bool operationStarted_ = false;
    bool operationRunning_ = false;
    bool restartAvailable_ = false;
};

} // namespace

int APIENTRY wWinMain(
    const HINSTANCE instance,
    const HINSTANCE,
    const PWSTR commandLine,
    const int
) {
    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
    if (!InitCommonControlsEx(&controls)) {
        MessageBoxW(nullptr, L"Could not initialize Windows common controls.", kWindowTitle, MB_OK | MB_ICONERROR);
        return 1;
    }

    const auto comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE) {
        MessageBoxW(nullptr, L"Could not initialize COM for the Components Wizard.", kWindowTitle, MB_OK | MB_ICONERROR);
        return 1;
    }

    int result = 1;
    try {
        const std::wstring arguments = commandLine == nullptr ? L"" : commandLine;
        WizardSession session(instance, arguments.find(L"--resume-uninstall") != std::wstring::npos);
        result = session.show();
    } catch (const std::exception& error) {
        MessageBoxW(nullptr, exceptionText(error).c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
    } catch (...) {
        MessageBoxW(nullptr, L"The Components Wizard encountered an unexpected error.", kWindowTitle, MB_OK | MB_ICONERROR);
    }

    if (SUCCEEDED(comResult)) {
        CoUninitialize();
    }
    return result;
}
