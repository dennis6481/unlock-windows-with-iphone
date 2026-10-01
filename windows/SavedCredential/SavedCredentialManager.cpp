// Created by Rui MA on 30 Sep 2026

#include "SavedCredentialIpc.h"

#include <objbase.h>
#include <wincred.h>

#include <array>
#include <cstring>
#include <cwchar>
#include <string>
#include <utility>

namespace {

using namespace unlock_windows::saved_credential;

constexpr int kRefresh = 101;
constexpr int kSet = 102;
constexpr int kUpdate = 103;
constexpr int kClear = 104;
constexpr int kArm = 105;

struct UiState final {
    HWND information = nullptr;
    StatusPayload status;
    bool snapshotAvailable = false;
};

struct PasswordBuffer final {
    std::array<wchar_t, 1025> value{};
    ~PasswordBuffer() { SecureZeroMemory(value.data(), sizeof(value)); }
};

UiState gUi;

void showError(const HWND parent, const wchar_t* message) {
    MessageBoxW(parent, message, L"Saved Windows credential", MB_OK | MB_ICONERROR);
}

bool elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD bytes = 0;
    const bool okay = GetTokenInformation(token, TokenElevation, &elevation,
        sizeof(elevation), &bytes) && elevation.TokenIsElevated;
    CloseHandle(token);
    return okay;
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
        const std::wstring message = !connected
            ? L"Saved credential IPC failed at " + std::wstring(callStageName(diagnostics.stage)) +
                L" (Win32 " + std::to_wstring(diagnostics.win32Error) + L"). No operation can proceed."
            : response.result == Result::rejected
                ? L"No current LogonUI identity snapshot or the console is not unlocked. Lock this console, unlock with native PIN/password, then Refresh."
                : L"Saved credential service returned an error or malformed identity status. No operation can proceed.";
        SetWindowTextW(gUi.information, message.c_str());
        EnableWindow(GetDlgItem(window, kSet), FALSE);
        EnableWindow(GetDlgItem(window, kUpdate), FALSE);
        EnableWindow(GetDlgItem(window, kArm), FALSE);
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
        EnableWindow(GetDlgItem(window, kArm), FALSE);
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
    SetWindowTextW(gUi.information, details.c_str());
    EnableWindow(GetDlgItem(window, kSet), !gUi.status.credentialPresent);
    EnableWindow(GetDlgItem(window, kUpdate), gUi.status.credentialPresent);
    EnableWindow(GetDlgItem(window, kArm), gUi.status.credentialPresent);
    return true;
}

void setOrUpdate(const HWND window, const bool update) {
    if (!gUi.snapshotAvailable) {
        showError(window, L"Refresh a current LogonUI identity snapshot first.");
        return;
    }
    if (MessageBoxW(window,
            L"Save a local encrypted copy of the actual Microsoft Account password for the displayed console user?\r\n"
            L"This does not change the online account password. This VM test does not yet require iPhone approval.",
            L"Confirm target identity", MB_YESNO | MB_ICONWARNING) != IDYES) return;

    CREDUI_INFOW prompt{};
    prompt.cbSize = sizeof(prompt);
    prompt.hwndParent = window;
    prompt.pszCaptionText = update ? L"Update stored credential" : L"Set stored credential";
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
        &prompt, L"Unlock Windows saved credential (VM)", nullptr, 0,
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
    if (!call(operation, std::move(request), response) || response.result != Result::success) {
        showError(window, L"The service rejected the credential change. The previous saved copy, if any, was not confirmed replaced.");
    } else {
        MessageBoxW(window, L"Encrypted local copy saved. Its password has not yet been verified by Windows.",
            L"Saved Windows credential", MB_OK | MB_ICONINFORMATION);
    }
    refresh(window);
}

void clearCredential(const HWND window) {
    if (MessageBoxW(window,
            L"Clear the local saved credential copy? This does not change your Microsoft Account password.",
            L"Clear saved credential", MB_YESNO | MB_ICONWARNING) != IDYES) return;
    SensitiveBytes request;
    Packet response;
    if (!call(Operation::clearCredential, std::move(request), response) ||
        response.result != Result::success) {
        showError(window, L"The saved credential could not be confirmed cleared.");
    } else {
        MessageBoxW(window, L"Saved credential record is absent.", L"Saved Windows credential",
            MB_OK | MB_ICONINFORMATION);
    }
    refresh(window);
}

void armTest(const HWND window) {
    if (!gUi.snapshotAvailable || !gUi.status.credentialPresent) {
        showError(window, L"A fresh identity snapshot and saved credential are required.");
        return;
    }
    SensitiveBytes request;
    request.value.assign(gUi.status.snapshotNonce.begin(), gUi.status.snapshotNonce.end());
    Packet response;
    if (!call(Operation::armTest, std::move(request), response) || response.result != Result::success) {
        showError(window, L"One-time test authorization was rejected.");
        return;
    }
    MessageBoxW(window,
        L"One manual test is authorized for 120 seconds. Lock this console now, select the saved-credential test option, and click Test unlock.\r\n"
        L"Any claim consumes this authorization before Windows checks the password.",
        L"One-time VM test", MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK windowProcedure(const HWND window, const UINT message, const WPARAM key, const LPARAM detail) {
    if (message == WM_CREATE) {
        const HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(window, GWLP_HINSTANCE));
        gUi.information = CreateWindowExW(0, L"STATIC", L"Loading console identity...",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 18, 20, 690, 145,
            window, nullptr, instance, nullptr);
        const struct Button { int id; const wchar_t* label; int x; int width; } buttons[] = {
            {kRefresh, L"Refresh", 18, 105},
            {kSet, L"Set credential", 130, 125},
            {kUpdate, L"Update stored", 262, 125},
            {kClear, L"Clear stored", 394, 125},
            {kArm, L"Authorize one test", 526, 175},
        };
        for (const auto& button : buttons) {
            CreateWindowExW(0, L"BUTTON", button.label, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                button.x, 180, button.width, 35, window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(button.id)), instance, nullptr);
        }
        refresh(window);
        return 0;
    }
    if (message == WM_COMMAND) {
        switch (LOWORD(key)) {
            case kRefresh: refresh(window); break;
            case kSet: setOrUpdate(window, false); break;
            case kUpdate: setOrUpdate(window, true); break;
            case kClear: clearCredential(window); break;
            case kArm: armTest(window); break;
            default: break;
        }
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, key, detail);
}

} // namespace

int WINAPI wWinMain(const HINSTANCE instance, HINSTANCE, LPWSTR, int show) {
    if (!elevated()) {
        MessageBoxW(nullptr, L"Run the saved-credential manager as administrator on the physical console.",
            L"Saved Windows credential", MB_OK | MB_ICONERROR);
        return 1;
    }
    WNDCLASSW kind{};
    kind.lpfnWndProc = windowProcedure;
    kind.hInstance = instance;
    kind.lpszClassName = L"UnlockWindowsSavedCredentialManager";
    kind.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    kind.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassW(&kind)) return 1;
    const HWND window = CreateWindowExW(0, kind.lpszClassName, L"Saved Windows credential (VM test)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 740, 265,
        nullptr, nullptr, instance, nullptr);
    if (window == nullptr) return 1;
    ShowWindow(window, show);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
