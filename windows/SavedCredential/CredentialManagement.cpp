// Created by Rui MA on 30 Sep 2026

#include "SavedCredentialIpc.h"
#include "../DesktopApp/DesktopApp.h"
#include "../Resources/resource.h"
#include "../Resources/DesktopUi.h"
#include "../Enrollment/EnrollmentSession.h"

#include <objbase.h>
#include <wincred.h>

#include <array>
#include <cstring>
#include <cwchar>
#include <string>
#include <utility>

namespace {

using namespace unlock_windows::saved_credential;

constexpr int kRefresh = IDC_UI_REFRESH;
constexpr int kSet = IDC_UI_SAVE;
constexpr int kUpdate = IDC_UI_UPDATE;
constexpr int kClear = IDC_UI_REMOVE;

struct UiState final {
    HWND information = nullptr;
    StatusPayload status;
    bool snapshotAvailable = false;
    bool technicalExpanded = false;
    bool setup = false;
    bool credentialReady = false;
    unlock_windows::desktop_ui::DialogAppearance appearance;
};

struct PasswordBuffer final {
    std::array<wchar_t, 1025> value{};
    ~PasswordBuffer() { SecureZeroMemory(value.data(), sizeof(value)); }
};

UiState gUi;

void showError(const HWND parent, const wchar_t* message) {
    MessageBoxW(parent, message, L"Saved Windows password", MB_OK | MB_ICONERROR);
}

bool refresh(const HWND window) {
    Packet response;
    SensitiveBytes request;
    StatusPayload value;
    CallDiagnostics diagnostics;
    const bool connected = call(Operation::status, std::move(request), response, 2000, &diagnostics);
    const bool accepted = connected && response.result == Result::success;
    if (!accepted ||
        !decodeStatus(response.payload.value.data(), response.payload.value.size(), value)) {
        gUi.snapshotAvailable = false;
        const std::wstring details = !connected
            ? L"Saved credential IPC failed at " + std::wstring(callStageName(diagnostics.stage)) +
                L" (Win32 " + std::to_wstring(diagnostics.win32Error) + L"). No operation can proceed."
            : response.result == Result::rejected
                ? L"No verified LogonUI identity is available for the installed target in this unlocked console. Refresh retries account verification. If the service restarted after sign-in, inspect its diagnostics; no credential change can proceed."
                : L"Saved credential service returned an error or malformed identity status. No operation can proceed.";
        const auto message = !connected
            ? L"Saved password management is unavailable. Your PIN and password still work. See Technical details."
            : response.result == Result::rejected
                ? L"Windows account information is not ready. Choose Refresh to retry verification for this signed-in console."
                : L"Account information could not be verified. See Technical details.";
        SetWindowTextW(gUi.information, message);
        SetDlgItemTextW(window, IDC_UI_ACCOUNT, L"Windows account: not yet verified");
        SetDlgItemTextW(window, IDC_UI_TECHNICAL, details.c_str());
        EnableWindow(GetDlgItem(window, kSet), FALSE);
        EnableWindow(GetDlgItem(window, kUpdate), FALSE);
        EnableWindow(GetDlgItem(window, kClear), connected && response.result == Result::rejected);
        return false;
    }
    gUi.status = std::move(value);
    gUi.snapshotAvailable = true;
    wchar_t provider[39]{};
    if (StringFromGUID2(gUi.status.identity.providerId, provider, 39) == 0) {
        gUi.snapshotAvailable = false;
        EnableWindow(GetDlgItem(window, kSet), FALSE);
        EnableWindow(GetDlgItem(window, kUpdate), FALSE);
        EnableWindow(GetDlgItem(window, kClear), FALSE);
        showError(window, L"Account provider ID cannot be displayed.");
        return false;
    }
    std::wstring details = L"Console account SID: " + gUi.status.identity.sid +
        L"\r\nWindows QualifiedUserName: " + gUi.status.identity.qualifiedUserName +
        L"\r\nAccount provider: " + provider +
        L"\r\nSaved copy: " + (gUi.status.credentialPresent ? L"present" : L"absent") +
        L"\r\nConfirm this is the account you intend to unlock.";
    if (diagnostics.stage == CallStage::replyAcknowledgment) {
        details += L"\r\nReply received, but acknowledgment failed (Win32 " +
            std::to_wstring(diagnostics.win32Error) + L").";
    }
    const auto separator = gUi.status.identity.qualifiedUserName.find_last_of(L'\\');
    const auto displayAccount = gUi.status.identity.qualifiedUserName.substr(
        separator == std::wstring::npos ? 0 : separator + 1);
    SetDlgItemTextW(window, IDC_UI_ACCOUNT, (L"Windows account: " + displayAccount).c_str());
    SetWindowTextW(gUi.information, gUi.status.credentialPresent && !gUi.status.credentialMatches
        ? L"Update the saved password copy for this verified Windows account before continuing setup. This app does not change your account password."
        : gUi.status.credentialPresent
        ? L"An encrypted password copy is saved on this PC. Update it here if your Microsoft Account password changes. This app does not change your account password."
        : L"No password copy is saved. Save your Microsoft Account password to enable iPhone unlock. This app does not change your account password.");
    SetDlgItemTextW(window, IDC_UI_TECHNICAL, details.c_str());
    EnableWindow(GetDlgItem(window, kSet), !gUi.status.credentialPresent);
    EnableWindow(GetDlgItem(window, kUpdate), gUi.status.credentialPresent);
    EnableWindow(GetDlgItem(window, kClear), gUi.status.credentialPresent);
    return true;
}

bool finishPasswordSetup(const HWND window) {
    if (!gUi.setup || !gUi.snapshotAvailable || !gUi.status.credentialMatches) return false;
    Packet response;
    if (!call(Operation::reloadPhoneEnrollment, SensitiveBytes{}, response) || response.result != Result::success) {
        showError(window, L"The service could not reload phone registration. Setup has not continued. Choose Refresh to retry.");
        return false;
    }
    gUi.credentialReady = true;
    DestroyWindow(window);
    return true;
}

void setOrUpdate(const HWND window, const bool update) {
    if (!gUi.snapshotAvailable) {
        showError(window, L"Choose Refresh to verify the Windows account first.");
        return;
    }
    if (MessageBoxW(window,
            L"Save a local encrypted copy of the actual Microsoft Account password for the displayed console user?\r\n"
            L"This does not change the online account password. Saving it does not create an unlock approval.",
            L"Confirm target identity", MB_YESNO | MB_ICONWARNING) != IDYES) return;

    CREDUI_INFOW prompt{};
    prompt.cbSize = sizeof(prompt);
    prompt.hwndParent = window;
    prompt.pszCaptionText = update ? L"Update saved password" : L"Save Windows password";
    prompt.pszMessageText = L"Enter the actual Microsoft Account password for the displayed Windows identity.";
    std::array<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> user{};
    PasswordBuffer password;
    if (gUi.status.identity.qualifiedUserName.size() >= user.size()) {
        showError(window, L"Windows qualified user name is too long for the credential prompt.");
        return;
    }
    if (wcscpy_s(user.data(), user.size(),
            gUi.status.identity.qualifiedUserName.c_str()) != 0) {
        showError(window, L"Windows qualified user name cannot be copied to the prompt.");
        return;
    }
    BOOL save = FALSE;
    const DWORD promptStatus = CredUIPromptForCredentialsW(
        &prompt, L"Unlock Windows saved credential", nullptr, 0,
        user.data(), static_cast<ULONG>(user.size()), password.value.data(),
        static_cast<ULONG>(password.value.size()), &save,
        CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_ALWAYS_SHOW_UI |
        CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_KEEP_USERNAME |
        CREDUI_FLAGS_EXCLUDE_CERTIFICATES
    );
    if (promptStatus == ERROR_CANCELLED) {
        return;
    }
    if (promptStatus != NO_ERROR || std::wcscmp(user.data(),
            gUi.status.identity.qualifiedUserName.c_str()) != 0 ||
        password.value[0] == L'\0') {
        showError(window, L"Credential prompt failed or returned a different identity.");
        return;
    }
    const auto passwordBytes = static_cast<std::uint32_t>(std::wcslen(password.value.data()) * sizeof(wchar_t));
    SensitiveBytes request;
    request.value.resize(kNonceSize + sizeof(passwordBytes) + passwordBytes);
    std::memcpy(request.value.data(), gUi.status.snapshotNonce.data(), kNonceSize);
    std::memcpy(request.value.data() + kNonceSize, &passwordBytes, sizeof(passwordBytes));
    std::memcpy(request.value.data() + kNonceSize + sizeof(passwordBytes), password.value.data(), passwordBytes);
    SecureZeroMemory(password.value.data(), sizeof(password.value));
    Packet response;
    const auto operation = update ? Operation::updateCredential : Operation::setCredential;
    const bool saved = call(operation, std::move(request), response) && response.result == Result::success;
    if (!saved) {
        showError(window, L"The service rejected the credential change. The previous saved copy, if any, was not confirmed replaced.");
    } else {
        MessageBoxW(window, L"Your encrypted password copy is saved. Windows has not yet verified that the password is correct.",
            L"Saved Windows password", MB_OK | MB_ICONINFORMATION);
    }
    if (refresh(window) && saved) finishPasswordSetup(window);
}

void clearCredential(const HWND window) {
    const TASKDIALOG_BUTTON removeButton{IDYES, L"Remove saved password"};
    TASKDIALOGCONFIG confirmation{sizeof(confirmation)};
    confirmation.hwndParent = window;
    confirmation.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    confirmation.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    confirmation.pszWindowTitle = L"Saved Windows password";
    confirmation.pszMainInstruction = L"Remove your saved password copy?";
    confirmation.pszContent = L"iPhone unlock will be unavailable until you save a password again. Your Microsoft Account password will not change.";
    confirmation.pszMainIcon = TD_WARNING_ICON;
    confirmation.cButtons = 1;
    confirmation.pButtons = &removeButton;
    confirmation.nDefaultButton = IDCANCEL;
    int choice = IDCANCEL;
    const auto confirmed = TaskDialogIndirect(&confirmation, &choice, nullptr, nullptr);
    if (FAILED(confirmed)) throw std::runtime_error("TaskDialogIndirect(password removal): HRESULT=" +
        std::to_string(static_cast<unsigned long>(confirmed)));
    if (choice != IDYES) return;
    SensitiveBytes request;
    Packet response;
    if (!call(Operation::clearCredential, std::move(request), response) ||
        response.result != Result::success) {
        showError(window, L"The saved credential could not be confirmed cleared.");
    } else {
        MessageBoxW(window, L"The saved password copy has been removed.", L"Saved Windows password",
            MB_OK | MB_ICONINFORMATION);
    }
    refresh(window);
}

void showTechnicalDetails(HWND window, bool expanded) {
    const LONG top = expanded ? 261 : 197;
    for (int id : {kRefresh, IDCANCEL}) {
        const LONG left = id == kRefresh ? 226 : 304;
        RECT button{left, top, left + 70, top + 16};
        unlock_windows::desktop_ui::require(MapDialogRect(window, &button), "MapDialogRect(password button)");
        unlock_windows::desktop_ui::require(SetWindowPos(GetDlgItem(window, id), nullptr, button.left,
            button.top, button.right - button.left, button.bottom - button.top,
            SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos(password button)");
    }
    RECT bounds{0, 0, 388, expanded ? 292 : 228};
    unlock_windows::desktop_ui::require(MapDialogRect(window, &bounds), "MapDialogRect(password window)");
    unlock_windows::desktop_ui::require(AdjustWindowRectExForDpi(&bounds,
        static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE)), FALSE,
        static_cast<DWORD>(GetWindowLongPtrW(window, GWL_EXSTYLE)), GetDpiForWindow(window)),
        "AdjustWindowRectExForDpi(password window)");
    ShowWindow(GetDlgItem(window, IDC_UI_TECHNICAL), expanded ? SW_SHOW : SW_HIDE);
    unlock_windows::desktop_ui::require(SetWindowPos(window, nullptr, 0, 0, bounds.right - bounds.left,
        bounds.bottom - bounds.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos(password details)");
    gUi.technicalExpanded = expanded;
}

INT_PTR CALLBACK windowProcedure(const HWND window, const UINT message, const WPARAM key, const LPARAM detail) {
    try {
        switch (message) {
        case WM_INITDIALOG:
            gUi.appearance.apply(window, IDC_UI_TITLE);
            gUi.information = GetDlgItem(window, IDC_UI_MESSAGE);
            showTechnicalDetails(window, false);
            refresh(window);
            unlock_windows::desktop_ui::defaultButton(window, gUi.snapshotAvailable
                ? (gUi.status.credentialPresent ? kUpdate : kSet) : kRefresh);
            return FALSE;
        case WM_DPICHANGED:
            unlock_windows::desktop_ui::scheduleDpiAppearance(window, HIWORD(key));
            return FALSE;
        case unlock_windows::desktop_ui::kApplyDpiAppearance:
            gUi.appearance.apply(window, IDC_UI_TITLE, static_cast<UINT>(key));
            showTechnicalDetails(window, gUi.technicalExpanded);
            return TRUE;
        case WM_CTLCOLORSTATIC:
            if (reinterpret_cast<HWND>(detail) == GetDlgItem(window, IDC_UI_TECHNICAL) ||
                reinterpret_cast<HWND>(detail) == GetDlgItem(window, IDC_UI_ACCOUNT))
                return unlock_windows::desktop_ui::readOnlyBackground(key);
            return FALSE;
        case WM_COMMAND:
            switch (LOWORD(key)) {
                case kRefresh:
                    if (refresh(window)) finishPasswordSetup(window);
                    break;
                case kSet: setOrUpdate(window, false); break;
                case kUpdate: setOrUpdate(window, true); break;
                case kClear: clearCredential(window); break;
                case IDC_UI_TECHNICAL_TOGGLE:
                    showTechnicalDetails(window, !gUi.technicalExpanded); break;
                case IDCANCEL: DestroyWindow(window); break;
                default: return FALSE;
            }
            return TRUE;
        case WM_CLOSE: DestroyWindow(window); return TRUE;
        case WM_DESTROY:
            PostQuitMessage(static_cast<int>(gUi.credentialReady
                ? unlock_windows::desktop_app::SetupResult::credentialReady
                : unlock_windows::desktop_app::SetupResult::cancelled));
            return TRUE;
        }
    } catch (const std::exception& error) {
        gUi.snapshotAvailable = false;
        for (int id : {kSet, kUpdate, kClear}) EnableWindow(GetDlgItem(window, id), FALSE);
        const std::string text(error.what());
        showError(window, std::wstring(text.begin(), text.end()).c_str());
    }
    return FALSE;
}

} // namespace

int unlock_windows::desktop_app::runSavedPassword(const HINSTANCE instance, int show, const bool setup) {
    gUi.setup = setup;
    if (!unlock_windows::enrollment::elevatedAdmin()) {
        MessageBoxW(nullptr, L"Run the saved-credential manager as administrator on the physical console.",
            L"Saved Windows password", MB_OK | MB_ICONERROR);
        return 1;
    }
    try {
        unlock_windows::desktop_ui::initialize();
        const HWND window = CreateDialogParamW(instance, MAKEINTRESOURCEW(IDD_SAVED_PASSWORD), nullptr, windowProcedure, 0);
        unlock_windows::desktop_ui::require(window != nullptr, "CreateDialogParamW(saved password)");
        unlock_windows::desktop_ui::centerOnActiveMonitor(window);
        if (!finishPasswordSetup(window)) ShowWindow(window, show);
        MSG message{};
        BOOL received;
        while ((received = GetMessageW(&message, nullptr, 0, 0)) > 0)
            if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        unlock_windows::desktop_ui::require(received != -1, "GetMessageW(saved password)");
        return static_cast<int>(message.wParam);
    } catch (const std::exception& error) {
        const std::string text(error.what());
        showError(nullptr, std::wstring(text.begin(), text.end()).c_str());
        return 1;
    }
}
