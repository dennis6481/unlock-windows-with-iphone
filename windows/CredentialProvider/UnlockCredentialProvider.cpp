// Created by Rui MA on 27 Sep 2026

#include <initguid.h>
#include "UnlockCredentialProvider.h"
#include "SavedCredentialIpc.h"
#include "../Resources/resource.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cwchar>
#include <cstring>
#include <cstdint>
#include <exception>
#include <new>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <propkey.h>
#include <ShlGuid.h>
#include <WtsApi32.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <wincred.h>

namespace {

using unlock_windows::credential_provider::kUnlockCredentialProviderClsid;
constexpr DWORD kIconField = 0;
constexpr DWORD kTitleField = 1;
constexpr DWORD kSubmitField = 2;
constexpr DWORD kFieldCount = 3;
constexpr UINT kApprovalMessage = WM_APP + 73;

struct FieldDefinition final {
    DWORD id;
    CREDENTIAL_PROVIDER_FIELD_TYPE type;
    const wchar_t* label;
    GUID fieldType;
};

const FieldDefinition kFields[] = {
    {kIconField, CPFT_TILE_IMAGE, nullptr, CPFG_CREDENTIAL_PROVIDER_LOGO},
    {kTitleField, CPFT_LARGE_TEXT, L"Unlock with iPhone", GUID{}},
    {kSubmitField, CPFT_SUBMIT_BUTTON, L"Unlock", GUID{}},
};

struct TemporaryPassword final {
    std::vector<wchar_t> value;
    ~TemporaryPassword() {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    }
};

void logAutoSubmitError(const wchar_t* operation, const HRESULT status) noexcept {
    wchar_t message[256]{};
    std::swprintf(message, 256, L"[UnlockCP] %ls failed: 0x%08lx\n",
        operation, static_cast<unsigned long>(status));
    OutputDebugStringW(message);
}

struct ApprovalWatch final {
    unlock_windows::saved_credential::Identity identity;
    DWORD session = 0xffffffff;
    HWND window = nullptr;
    UINT_PTR generation = 0;
    HANDLE stop = nullptr;
    std::mutex mutex;
    std::optional<unlock_windows::saved_credential::AutoSubmitOffer> offer;
    std::wstring failure;
    std::optional<unlock_windows::saved_credential::AuthenticationStatus> authenticationStatus;
    std::thread worker;

    ~ApprovalWatch() {
        if (stop != nullptr) SetEvent(stop);
        if (worker.joinable()) worker.join();
        if (stop != nullptr) CloseHandle(stop);
    }

    void run() noexcept {
        using namespace unlock_windows::saved_credential;
        HRESULT previousError = S_OK;
        try {
            while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) {
                SensitiveBytes request;
                Packet reply;
                CallDiagnostics diagnostics;
                HRESULT status = S_OK;
                if (!encodeIdentity(identity, request)) {
                    status = E_INVALIDARG;
                } else if (!call(Operation::takeAutoSubmitOffer, std::move(request), reply, 250, &diagnostics)) {
                    status = HRESULT_FROM_WIN32(diagnostics.win32Error);
                } else if (reply.result != Result::success) {
                    status = E_ACCESSDENIED;
                } else if (!reply.payload.value.empty()) {
                    AutoSubmitOffer received;
                    if (!decodeAutoSubmitOffer(reply.payload.value.data(), reply.payload.value.size(), received)) {
                        status = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                    } else {
                        {
                            std::lock_guard lock(mutex);
                            offer = received;
                        }
                        if (!PostMessageW(window, kApprovalMessage, generation, 0)) {
                            logAutoSubmitError(L"PostMessage", HRESULT_FROM_WIN32(GetLastError()));
                            return;
                        }
                    }
                }
                if (FAILED(status) && status != previousError) {
                    logAutoSubmitError(L"approval query", status);
                    if (diagnostics.stage != CallStage::none) {
                        OutputDebugStringW(callStageName(diagnostics.stage));
                    }
                }
                previousError = status;
                SensitiveBytes statusRequest;
                Packet statusReply;
                std::wstring latest;
                std::optional<AuthenticationStatus> latestStatus;
                if (!encodeIdentity(identity, statusRequest)) {
                    latest = L"Could not encode the phone authentication status request.";
                    logAutoSubmitError(L"phone status identity encoding", E_INVALIDARG);
                } else if (!call(Operation::phoneAuthenticationStatus, std::move(statusRequest), statusReply, 250, &diagnostics)) {
                    latest = L"Phone authentication service communication failed. Click the arrow again.";
                    logAutoSubmitError(L"phone authentication status", HRESULT_FROM_WIN32(diagnostics.win32Error));
                } else if (statusReply.result == Result::success) {
                    AuthenticationStatus received;
                    if (!decodeAuthenticationStatus(statusReply.payload.value.data(), statusReply.payload.value.size(), received)) {
                        latest = L"Invalid phone authentication status response.";
                        logAutoSubmitError(L"phone status framing", HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
                    } else latestStatus = std::move(received);
                } else {
                    latest = L"Phone authentication status was rejected by the service.";
                }
                {
                    std::lock_guard lock(mutex);
                    failure = latest;
                    authenticationStatus = std::move(latestStatus);
                }
                if (!PostMessageW(window, kApprovalMessage, generation, 0)) {
                    logAutoSubmitError(L"phone status PostMessage", HRESULT_FROM_WIN32(GetLastError()));
                    return;
                }
                const DWORD waited = WaitForSingleObject(stop, 500);
                if (waited == WAIT_OBJECT_0) return;
                if (waited != WAIT_TIMEOUT) {
                    logAutoSubmitError(L"approval wait", HRESULT_FROM_WIN32(GetLastError()));
                    return;
                }
            }
        } catch (const std::exception& error) {
            OutputDebugStringA("[UnlockCP] approval watcher failed: ");
            OutputDebugStringA(error.what());
        }
    }
};

std::atomic<ULONG> gObjectCount{0};
std::atomic<ULONG> gServerLockCount{0};

void objectCreated() noexcept {
    gObjectCount.fetch_add(1, std::memory_order_relaxed);
}

void objectDestroyed() noexcept {
    gObjectCount.fetch_sub(1, std::memory_order_relaxed);
}

HRESULT copyString(const wchar_t* value, LPWSTR* output) noexcept {
    if (output == nullptr) {
        return E_POINTER;
    }
    *output = nullptr;
    if (value == nullptr) {
        return E_INVALIDARG;
    }

    const auto length = std::wcslen(value);
    const auto bytes = (length + 1) * sizeof(wchar_t);
    auto* copy = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
    if (copy == nullptr) {
        return E_OUTOFMEMORY;
    }

    std::memcpy(copy, value, bytes);
    *output = copy;
    return S_OK;
}

HRESULT propertyString(
    ICredentialProviderUser* user,
    REFPROPERTYKEY key,
    std::wstring& value
) {
    LPWSTR raw = nullptr;
    const auto result = user->GetStringValue(key, &raw);
    if (FAILED(result) || raw == nullptr || raw[0] == L'\0') {
        CoTaskMemFree(raw);
        return FAILED(result) ? result : E_UNEXPECTED;
    }
    try {
        value.assign(raw);
    } catch (const std::bad_alloc&) {
        CoTaskMemFree(raw);
        return E_OUTOFMEMORY;
    }
    CoTaskMemFree(raw);
    return S_OK;
}

std::wstring normalizedSid(std::wstring value) {
    if (value.size() > 2 && value.front() == L'{' && value.back() == L'}') {
        value = value.substr(1, value.size() - 2);
    }
    return value;
}

HRESULT sessionString(
    DWORD sessionId,
    WTS_INFO_CLASS field,
    std::wstring& value
) {
    LPWSTR buffer = nullptr;
    DWORD bytes = 0;
    if (!WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, sessionId, field, &buffer, &bytes
        )) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (buffer == nullptr || bytes < sizeof(wchar_t) ||
        bytes % sizeof(wchar_t) != 0 ||
        buffer[bytes / sizeof(wchar_t) - 1] != L'\0' || buffer[0] == L'\0') {
        if (buffer != nullptr) {
            WTSFreeMemory(buffer);
        }
        return E_UNEXPECTED;
    }
    try {
        value.assign(buffer);
    } catch (const std::bad_alloc&) {
        WTSFreeMemory(buffer);
        return E_OUTOFMEMORY;
    }
    WTSFreeMemory(buffer);
    return S_OK;
}

HRESULT activeConsoleUserSid(
    std::wstring& sid,
    DWORD* resolvedSessionId = nullptr,
    std::wstring* sessionAccountName = nullptr,
    const wchar_t** stage = nullptr
) {
    if (stage != nullptr) {
        *stage = L"active-console-session";
    }
    const auto sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xffffffff) {
        return HRESULT_FROM_WIN32(ERROR_NO_SUCH_LOGON_SESSION);
    }
    if (resolvedSessionId != nullptr) {
        *resolvedSessionId = sessionId;
    }
    if (stage != nullptr) {
        *stage = L"provider-process-session";
    }
    DWORD processSessionId = 0xffffffff;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &processSessionId)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (processSessionId != sessionId) {
        return E_ACCESSDENIED;
    }

    std::wstring userName;
    if (stage != nullptr) {
        *stage = L"session-user-name";
    }
    auto result = sessionString(sessionId, WTSUserName, userName);
    if (FAILED(result)) {
        return result;
    }
    std::wstring domainName;
    if (stage != nullptr) {
        *stage = L"session-domain-name";
    }
    result = sessionString(sessionId, WTSDomainName, domainName);
    if (FAILED(result)) {
        return result;
    }
    std::wstring accountName;
    try {
        accountName = domainName + L"\\" + userName;
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    }
    if (sessionAccountName != nullptr) {
        try {
            *sessionAccountName = accountName;
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        }
    }

    DWORD sidBytes = 0;
    if (stage != nullptr) {
        *stage = L"account-sid-lookup";
    }
    DWORD referencedDomainChars = 0;
    SID_NAME_USE use{};
    const auto sized = LookupAccountNameW(
        nullptr, accountName.c_str(), nullptr, &sidBytes,
        nullptr, &referencedDomainChars, &use
    );
    const auto sizingError = GetLastError();
    if (sized || sizingError != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0) {
        return sized ? E_UNEXPECTED : HRESULT_FROM_WIN32(sizingError);
    }
    std::vector<BYTE> sidBuffer;
    std::vector<wchar_t> referencedDomain;
    try {
        sidBuffer.resize(sidBytes);
        referencedDomain.resize(referencedDomainChars == 0 ? 1 : referencedDomainChars);
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    }
    if (!LookupAccountNameW(
            nullptr, accountName.c_str(), sidBuffer.data(), &sidBytes,
            referencedDomain.data(), &referencedDomainChars, &use
        )) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (use != SidTypeUser) {
        return E_UNEXPECTED;
    }
    if (stage != nullptr) {
        *stage = L"sid-conversion";
    }
    LPWSTR rawSid = nullptr;
    if (!ConvertSidToStringSidW(sidBuffer.data(), &rawSid)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    try {
        sid.assign(rawSid);
    } catch (const std::bad_alloc&) {
        LocalFree(rawSid);
        return E_OUTOFMEMORY;
    }
    LocalFree(rawSid);
    if (stage != nullptr) {
        *stage = L"complete";
    }
    return S_OK;
}

HRESULT negotiatePackage(ULONG& identifier) noexcept {
    LSA_HANDLE lsa = nullptr;
    const auto connect = LsaConnectUntrusted(&lsa);
    if (connect < 0) {
        return HRESULT_FROM_NT(connect);
    }
    char name[] = "Negotiate";
    LSA_STRING packageName{};
    packageName.Buffer = name;
    packageName.Length = static_cast<USHORT>(sizeof(name) - 1);
    packageName.MaximumLength = static_cast<USHORT>(sizeof(name));
    const auto status = LsaLookupAuthenticationPackage(lsa, &packageName, &identifier);
    LsaDeregisterLogonProcess(lsa);
    return status < 0 ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT copyFieldDescriptor(
    const FieldDefinition& definition,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** output
) noexcept {
    if (output == nullptr) {
        return E_POINTER;
    }
    *output = nullptr;

    auto* descriptor = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
        CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR))
    );
    if (descriptor == nullptr) {
        return E_OUTOFMEMORY;
    }

    descriptor->dwFieldID = definition.id;
    descriptor->cpft = definition.type;
    descriptor->guidFieldType = definition.fieldType;
    descriptor->pszLabel = nullptr;
    const auto result = definition.label == nullptr
        ? S_OK
        : copyString(definition.label, &descriptor->pszLabel);
    if (FAILED(result)) {
        CoTaskMemFree(descriptor);
        return result;
    }

    *output = descriptor;
    return S_OK;
}

HBITMAP createProviderLogo() noexcept {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&createProviderLogo), &module)) return nullptr;
    return static_cast<HBITMAP>(LoadImageW(module, MAKEINTRESOURCEW(IDB_UNLOCK_TILE),
        IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION));
}

class UnlockCredential final : public ICredentialProviderCredential2 {
public:
    UnlockCredential() noexcept {
        objectCreated();
    }

    UnlockCredential(const UnlockCredential&) = delete;
    UnlockCredential& operator=(const UnlockCredential&) = delete;

    ~UnlockCredential() {
        if (events_ != nullptr) {
            events_->Release();
        }
        objectDestroyed();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        void** object
    ) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) ||
            IsEqualIID(riid, __uuidof(ICredentialProviderCredential)) ||
            IsEqualIID(riid, __uuidof(ICredentialProviderCredential2))) {
            *object = static_cast<ICredentialProviderCredential2*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return refCount_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = refCount_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE Advise(
        ICredentialProviderCredentialEvents* events
    ) override {
        if (events == nullptr) {
            return E_POINTER;
        }
        if (events_ != nullptr) {
            events_->Release();
        }
        events_ = events;
        events_->AddRef();
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE UnAdvise() override {
        if (events_ != nullptr) {
            events_->Release();
            events_ = nullptr;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetSelected(BOOL* autoLogon) override {
        if (autoLogon == nullptr) {
            return E_POINTER;
        }
        *autoLogon = FALSE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetDeselected() override {
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetFieldState(
        DWORD fieldId,
        CREDENTIAL_PROVIDER_FIELD_STATE* state,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState
    ) override {
        if (state == nullptr || interactiveState == nullptr) {
            return E_POINTER;
        }
        switch (fieldId) {
            case kIconField:
            case kTitleField:
                *state = CPFS_DISPLAY_IN_BOTH;
                *interactiveState = CPFIS_READONLY;
                return S_OK;
            case kSubmitField:
                *state = CPFS_DISPLAY_IN_SELECTED_TILE;
                *interactiveState = CPFIS_NONE;
                return S_OK;
            default:
                return E_INVALIDARG;
        }
    }

    HRESULT STDMETHODCALLTYPE GetStringValue(
        DWORD fieldId,
        LPWSTR* value
    ) override {
        switch (fieldId) {
            case kIconField:
                if (value == nullptr) {
                    return E_POINTER;
                }
                *value = nullptr;
                return S_OK;
            case kTitleField:
                return copyString(L"Unlock with iPhone", value);
            default:
                if (value != nullptr) {
                    *value = nullptr;
                }
                return E_INVALIDARG;
        }
    }

    HRESULT STDMETHODCALLTYPE GetBitmapValue(
        DWORD fieldId,
        HBITMAP* bitmap
    ) override {
        if (bitmap == nullptr) {
            return E_POINTER;
        }
        *bitmap = nullptr;
        if (fieldId != kIconField) {
            return E_INVALIDARG;
        }
        *bitmap = createProviderLogo();
        return *bitmap == nullptr ? E_OUTOFMEMORY : S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCheckboxValue(
        DWORD fieldId,
        BOOL* checked,
        LPWSTR* label
    ) override {
        if (checked == nullptr || label == nullptr) return E_POINTER;
        *checked = FALSE;
        *label = nullptr;
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(
        DWORD fieldId,
        DWORD* adjacentTo
    ) override {
        if (adjacentTo == nullptr) {
            return E_POINTER;
        }
        if (fieldId != kSubmitField) {
            return E_INVALIDARG;
        }
        *adjacentTo = kTitleField;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(
        DWORD,
        DWORD* itemCount,
        DWORD* selectedItem
    ) override {
        if (itemCount != nullptr) {
            *itemCount = 0;
        }
        if (selectedItem != nullptr) {
            *selectedItem = 0;
        }
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(
        DWORD,
        DWORD,
        LPWSTR* item
    ) override {
        if (item != nullptr) {
            *item = nullptr;
        }
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE SetStringValue(DWORD, LPCWSTR) override {
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD, BOOL) override {
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD, DWORD) override {
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override {
        return E_INVALIDARG;
    }

    void showAuthenticationStatus(const std::wstring& text) {
        if (events_ != nullptr) {
            const HRESULT result = events_->SetFieldString(this, kTitleField,
                text.empty() ? L"Unlock with iPhone" : text.c_str());
            if (FAILED(result)) logAutoSubmitError(L"authentication status field", result);
        }
    }

    void updateAuthenticationStatus(const std::optional<unlock_windows::saved_credential::AuthenticationStatus>& status,
                                    const std::wstring& failure) {
        if (!authenticationPending_) return;
        if (!failure.empty()) {
            authenticationPending_ = false;
            showAuthenticationStatus(failure);
        } else if (status && status->requestId == authenticationRequestId_) {
            if (status->stage == unlock_windows::saved_credential::AuthenticationStage::failed ||
                status->stage == unlock_windows::saved_credential::AuthenticationStage::consumed)
                authenticationPending_ = false;
            showAuthenticationStatus(unlock_windows::saved_credential::authenticationStatusText(*status));
        } else if (status && status->stage == unlock_windows::saved_credential::AuthenticationStage::idle) {
            authenticationPending_ = false;
            showAuthenticationStatus(L"The authentication service has no active request. Press Enter to retry.");
        }
    }

    HRESULT STDMETHODCALLTYPE GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
        LPWSTR* optionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* optionalStatusIcon
    ) override {
        if (response == nullptr || serialization == nullptr ||
            optionalStatusText == nullptr || optionalStatusIcon == nullptr) {
            return E_POINTER;
        }

        *serialization = {};
        *optionalStatusText = nullptr;
        *optionalStatusIcon = CPSI_WARNING;
        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

        const auto automaticApproval = std::exchange(automaticApproval_, std::nullopt);

        if (qualifiedUserName_.empty() || userSid_.empty() || primarySid_ != userSid_ ||
            consoleSessionId_ == 0xffffffff) {
            return copyString(L"The selected Windows user identity is incomplete or inconsistent.", optionalStatusText);
        }

        if (WTSGetActiveConsoleSessionId() != consoleSessionId_) {
            return copyString(L"The active console session changed. Select the tile again.", optionalStatusText);
        }
        std::wstring consoleSid;
        DWORD consoleSessionId = 0xffffffff;
        const wchar_t* consoleIdentityStage = L"not-started";
        const auto consoleStatus = activeConsoleUserSid(
            consoleSid, &consoleSessionId, nullptr, &consoleIdentityStage
        );
        if (FAILED(consoleStatus)) {
            wchar_t statusText[192]{};
            std::swprintf(
                statusText, 192,
                L"Console identity check failed at %ls (0x%08lx).",
                consoleIdentityStage, static_cast<unsigned long>(consoleStatus)
            );
            return copyString(statusText, optionalStatusText);
        }
        if (consoleSessionId != consoleSessionId_ || consoleSid != userSid_) {
            return copyString(L"The selected account is not the active console user.", optionalStatusText);
        }

        if (!automaticApproval) {
            if (authenticationPending_) {
                *optionalStatusIcon = CPSI_NONE;
                return S_OK;
            }
            try {
                using namespace unlock_windows::saved_credential;
                SensitiveBytes request;
                Packet reply;
                CallDiagnostics diagnostics;
                const Identity identity{userSid_, qualifiedUserName_, providerId_};
                if (!encodeIdentity(identity, request)) {
                    logAutoSubmitError(L"phone authentication identity encoding", E_INVALIDARG);
                    return copyString(L"Could not encode the selected Windows identity.", optionalStatusText);
                }
                if (!call(Operation::beginPhoneAuthentication, std::move(request), reply, 250, &diagnostics)) {
                    logAutoSubmitError(L"begin phone authentication", HRESULT_FROM_WIN32(diagnostics.win32Error));
                    return copyString(L"Could not contact the phone authentication service.", optionalStatusText);
                }
                if (reply.result != Result::success) {
                    const std::string text(reply.payload.value.begin(), reply.payload.value.end());
                    const std::wstring message(text.begin(), text.end());
                    return copyString(message.empty() ? L"Phone authentication is unavailable for this account." :
                        message.c_str(), optionalStatusText);
                }
                AuthenticationStatus started;
                if (!decodeAuthenticationStatus(reply.payload.value.data(), reply.payload.value.size(), started) ||
                    started.stage != AuthenticationStage::waitingPhone) {
                    logAutoSubmitError(L"phone request framing", HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
                    return copyString(L"Invalid phone authentication request response.", optionalStatusText);
                }
                authenticationRequestId_ = started.requestId;
                authenticationPending_ = true;
                showAuthenticationStatus(authenticationStatusText(started));
                *optionalStatusIcon = CPSI_NONE;
                return S_OK;
            } catch (const std::bad_alloc&) {
                logAutoSubmitError(L"phone authentication allocation", E_OUTOFMEMORY);
                return E_OUTOFMEMORY;
            }
        }

        ULONG authenticationPackage = 0;
        const auto packageStatus = negotiatePackage(authenticationPackage);
        if (FAILED(packageStatus)) {
            return copyString(
                L"The Windows Negotiate authentication package is unavailable.",
                optionalStatusText
            );
        }

        TemporaryPassword savedPassword;
        try {
            unlock_windows::saved_credential::Identity identity{
                userSid_, qualifiedUserName_, providerId_
            };
            std::array<std::uint8_t, unlock_windows::saved_credential::kNonceSize> savedNonce{};
            unlock_windows::saved_credential::SensitiveBytes captureRequest;
            unlock_windows::saved_credential::Packet captureReply;
            if (!unlock_windows::saved_credential::encodeIdentity(identity, captureRequest) ||
                !unlock_windows::saved_credential::call(
                    unlock_windows::saved_credential::Operation::captureIdentity,
                    std::move(captureRequest), captureReply
                ) || captureReply.result != unlock_windows::saved_credential::Result::success ||
                captureReply.payload.value.size() != savedNonce.size()) {
                return copyString(L"Saved credential identity capture failed while submitting. Unlock normally, then request a new iPhone approval.",
                    optionalStatusText);
            }
            std::copy_n(captureReply.payload.value.begin(), savedNonce.size(), savedNonce.begin());
            if (automaticApproval && *automaticApproval != savedNonce) {
                return copyString(L"The iPhone approval changed before automatic submission. Request a new approval.",
                    optionalStatusText);
            }
            unlock_windows::saved_credential::SensitiveBytes request;
            unlock_windows::saved_credential::Packet reply;
            if (!unlock_windows::saved_credential::encodeIdentity(identity, request)) {
                return copyString(L"The saved-credential identity cannot be encoded.", optionalStatusText);
            }
            request.value.insert(request.value.end(), savedNonce.begin(), savedNonce.end());
            if (!unlock_windows::saved_credential::call(
                    unlock_windows::saved_credential::Operation::claimCredential,
                    std::move(request), reply
                ) || reply.result != unlock_windows::saved_credential::Result::success ||
                reply.payload.value.empty() || reply.payload.value.size() > 2048 ||
                reply.payload.value.size() % sizeof(wchar_t) != 0) {
                return copyString(L"Saved credential claim was refused. Request a new iPhone approval.",
                    optionalStatusText);
            }
            const auto chars = reply.payload.value.size() / sizeof(wchar_t);
            savedPassword.value.resize(chars + 1, L'\0');
            std::memcpy(savedPassword.value.data(), reply.payload.value.data(), reply.payload.value.size());
            if (savedPassword.value[0] == L'\0' ||
                std::find(savedPassword.value.begin(), savedPassword.value.begin() + chars, L'\0') !=
                    savedPassword.value.begin() + chars) {
                return copyString(L"Saved credential response is malformed.", optionalStatusText);
            }
            reply.payload.clear();
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        }

        constexpr DWORD flags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;
        DWORD size = 0;
        const auto sized = CredPackAuthenticationBufferW(
            flags, const_cast<LPWSTR>(qualifiedUserName_.c_str()), savedPassword.value.data(), nullptr, &size
        );
        if (sized || GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            return copyString(
                L"Windows could not size the online identity credential buffer.",
                optionalStatusText
            );
        }

        const DWORD allocatedSize = size;
        auto* packed = static_cast<BYTE*>(CoTaskMemAlloc(allocatedSize));
        if (packed == nullptr) {
            return E_OUTOFMEMORY;
        }
        const auto packedResult = CredPackAuthenticationBufferW(
            flags, const_cast<LPWSTR>(qualifiedUserName_.c_str()), savedPassword.value.data(), packed, &size
        );
        if (!packedResult) {
            SecureZeroMemory(packed, allocatedSize);
            CoTaskMemFree(packed);
            return copyString(L"Windows rejected online identity credential packing.", optionalStatusText);
        }

        serialization->ulAuthenticationPackage = authenticationPackage;
        serialization->clsidCredentialProvider = kUnlockCredentialProviderClsid;
        serialization->cbSerialization = size;
        serialization->rgbSerialization = packed;
        *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        *optionalStatusIcon = CPSI_NONE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ReportResult(
        NTSTATUS,
        NTSTATUS,
        LPWSTR* optionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* optionalStatusIcon
    ) override {
        if (optionalStatusText == nullptr || optionalStatusIcon == nullptr) {
            return E_POINTER;
        }
        *optionalStatusText = nullptr;
        *optionalStatusIcon = CPSI_NONE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetUserSid(LPWSTR* sid) override {
        if (sid == nullptr) {
            return E_POINTER;
        }
        if (userSid_.empty()) {
            *sid = nullptr;
            return E_UNEXPECTED;
        }
        return copyString(userSid_.c_str(), sid);
    }

    HRESULT setUserIdentity(
        const std::wstring& sid,
        const std::wstring& primarySid,
        const std::wstring& qualifiedName,
        const GUID& providerId,
        DWORD consoleSessionId
    ) noexcept {
        if (sid.empty() || primarySid.empty() || qualifiedName.empty()) {
            userSid_.clear();
            primarySid_.clear();
            qualifiedUserName_.clear();
            consoleSessionId_ = 0xffffffff;
            return E_INVALIDARG;
        }
        try {
            userSid_ = sid;
            primarySid_ = primarySid;
            qualifiedUserName_ = qualifiedName;
            providerId_ = providerId;
            consoleSessionId_ = consoleSessionId;
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        }
        return S_OK;
    }

    void clearIdentity() noexcept {
        userSid_.clear();
        primarySid_.clear();
        qualifiedUserName_.clear();
        providerId_ = GUID{};
        consoleSessionId_ = 0xffffffff;
        automaticApproval_.reset();
        authenticationPending_ = false;
    }

    void armAutomaticSubmission(const std::array<std::uint8_t,
            unlock_windows::saved_credential::kNonceSize>& nonce) noexcept {
        authenticationPending_ = false;
        automaticApproval_ = nonce;
    }

private:
    std::atomic<ULONG> refCount_{1};
    bool authenticationPending_ = false;
    std::string authenticationRequestId_;
    ICredentialProviderCredentialEvents* events_ = nullptr;
    std::wstring userSid_;
    std::wstring primarySid_;
    std::wstring qualifiedUserName_;
    GUID providerId_{};
    DWORD consoleSessionId_ = 0xffffffff;
    std::optional<std::array<std::uint8_t,
        unlock_windows::saved_credential::kNonceSize>> automaticApproval_;
};

class UnlockCredentialProvider final : public ICredentialProvider,
                                       public ICredentialProviderSetUserArray {
public:
    UnlockCredentialProvider() noexcept
        : credential_(new (std::nothrow) UnlockCredential()) {
        objectCreated();
    }

    UnlockCredentialProvider(const UnlockCredentialProvider&) = delete;
    UnlockCredentialProvider& operator=(const UnlockCredentialProvider&) = delete;

    ~UnlockCredentialProvider() {
        stopWatching();
        destroyApprovalWindow();
        if (events_ != nullptr) {
            events_->Release();
        }
        if (credential_ != nullptr) {
            credential_->Release();
        }
        objectDestroyed();
    }

    [[nodiscard]] bool ready() const noexcept {
        return credential_ != nullptr;
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        void** object
    ) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) ||
            IsEqualIID(riid, __uuidof(ICredentialProvider))) {
            *object = static_cast<ICredentialProvider*>(this);
            AddRef();
            return S_OK;
        }
        if (IsEqualIID(riid, __uuidof(ICredentialProviderSetUserArray))) {
            *object = static_cast<ICredentialProviderSetUserArray*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return refCount_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = refCount_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
        DWORD
    ) override {
        // Windows 10 and later normally use CPUS_LOGON for both sign-in and
        // workstation unlock. CPUS_UNLOCK_WORKSTATION remains possible when
        // system policy requires the stricter unlock-only scenario.
        if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) {
            return E_NOTIMPL;
        }
        usageScenarioSet_ = true;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization
    ) override {
        return serialization == nullptr ? E_POINTER : S_OK;
    }

    HRESULT STDMETHODCALLTYPE Advise(
        ICredentialProviderEvents* events,
        UINT_PTR adviseContext
    ) override {
        if (events == nullptr) {
            return E_POINTER;
        }
        UnAdvise();
        events_ = events;
        events_->AddRef();
        adviseContext_ = adviseContext;
        const HRESULT windowStatus = createApprovalWindow();
        if (FAILED(windowStatus)) {
            logAutoSubmitError(L"approval window", windowStatus);
            UnAdvise();
            return windowStatus;
        }
        const HRESULT watchStatus = startWatching();
        if (FAILED(watchStatus)) {
            UnAdvise();
        }
        return watchStatus;
    }

    HRESULT STDMETHODCALLTYPE UnAdvise() override {
        stopWatching();
        destroyApprovalWindow();
        if (events_ != nullptr) {
            events_->Release();
            events_ = nullptr;
        }
        adviseContext_ = 0;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetUserArray(
        ICredentialProviderUserArray* users
    ) override {
        if (users == nullptr) {
            return E_POINTER;
        }

        const auto previousIdentity = std::move(identity_);
        const auto previousSession = consoleSessionId_;
        const auto previousOffer = pendingAutomaticOffer_;
        hasUserSid_ = false;
        identity_ = {};
        consoleSessionId_ = 0xffffffff;
        if (credential_ == nullptr) {
            return E_UNEXPECTED;
        }
        credential_->clearIdentity();

        DWORD userCount = 0;
        auto result = users->GetCount(&userCount);
        if (FAILED(result)) {
            return result;
        }
        if (userCount == 0) {
            stopWatching();
            return S_OK;
        }

        std::wstring consoleSid;
        DWORD consoleSessionId = 0xffffffff;
        const auto consoleStatus = activeConsoleUserSid(consoleSid, &consoleSessionId);
        if (FAILED(consoleStatus)) {
            stopWatching();
            return S_OK;
        }
        ICredentialProviderUser* user = nullptr;
        for (DWORD index = 0; index < userCount; ++index) {
            ICredentialProviderUser* candidate = nullptr;
            result = users->GetAt(index, &candidate);
            if (FAILED(result) || candidate == nullptr) {
                return FAILED(result) ? result : E_UNEXPECTED;
            }
            LPWSTR candidateSid = nullptr;
            result = candidate->GetSid(&candidateSid);
            bool matches = false;
            try {
                matches = SUCCEEDED(result) && candidateSid != nullptr &&
                    normalizedSid(candidateSid) == consoleSid;
            } catch (const std::bad_alloc&) {
                CoTaskMemFree(candidateSid);
                candidate->Release();
                return E_OUTOFMEMORY;
            }
            CoTaskMemFree(candidateSid);
            if (matches) {
                user = candidate;
                break;
            }
            candidate->Release();
        }
        if (user == nullptr) {
            stopWatching();
            return S_OK;
        }
        LPWSTR rawSid = nullptr;
        result = user->GetSid(&rawSid);
        if (FAILED(result) || rawSid == nullptr || rawSid[0] == L'\0') {
            CoTaskMemFree(rawSid);
            user->Release();
            return FAILED(result) ? result : E_UNEXPECTED;
        }
        std::wstring sidValue;
        std::wstring primarySid;
        std::wstring qualifiedName;
        GUID providerId{};
        try {
            sidValue = normalizedSid(rawSid);
        } catch (const std::bad_alloc&) {
            CoTaskMemFree(rawSid);
            user->Release();
            return E_OUTOFMEMORY;
        }
        CoTaskMemFree(rawSid);
        result = propertyString(user, PKEY_Identity_PrimarySid, primarySid);
        if (SUCCEEDED(result)) result = propertyString(user, PKEY_Identity_QualifiedUserName, qualifiedName);
        if (SUCCEEDED(result)) result = user->GetProviderID(&providerId);
        user->Release();
        if (FAILED(result)) {
            return result;
        }
        try {
            primarySid = normalizedSid(primarySid);
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        }
        if (sidValue != primarySid) {
            return E_UNEXPECTED;
        }
        {
            using namespace unlock_windows::saved_credential;
            SensitiveBytes request;
            Packet reply;
            if (!encodeIdentity({sidValue, qualifiedName, providerId}, request)) return E_UNEXPECTED;
            if (!call(Operation::unlockEligibility, std::move(request), reply, 250) ||
                reply.result != Result::success) {
                stopWatching();
                return S_OK;
            }
        }
        if (SUCCEEDED(consoleStatus) && consoleSid == sidValue) {
            unlock_windows::saved_credential::Identity identity{
                sidValue, qualifiedName, providerId
            };
            unlock_windows::saved_credential::SensitiveBytes request;
            unlock_windows::saved_credential::Packet reply;
            if (!unlock_windows::saved_credential::encodeIdentity(identity, request)) {
                return E_UNEXPECTED;
            }
            if (!unlock_windows::saved_credential::call(
                    unlock_windows::saved_credential::Operation::captureIdentity,
                    std::move(request), reply, 250
                )) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            if (reply.result != unlock_windows::saved_credential::Result::success ||
                reply.payload.value.size() != unlock_windows::saved_credential::kNonceSize) {
                return E_ACCESSDENIED;
            }
        }
        if (credential_ == nullptr) {
            return E_UNEXPECTED;
        }
        result = credential_->setUserIdentity(
            sidValue, primarySid, qualifiedName, providerId, consoleSessionId
        );
        if (SUCCEEDED(result)) {
            hasUserSid_ = true;
            try {
                identity_ = {sidValue, qualifiedName, providerId};
            } catch (const std::bad_alloc&) {
                hasUserSid_ = false;
                return E_OUTOFMEMORY;
            }
            consoleSessionId_ = SUCCEEDED(consoleStatus) && consoleSid == sidValue
                ? consoleSessionId : 0xffffffff;
            result = startWatching();
            if (SUCCEEDED(result) && previousOffer && previousSession == consoleSessionId_ &&
                previousIdentity.sid == identity_.sid &&
                previousIdentity.qualifiedUserName == identity_.qualifiedUserName &&
                IsEqualGUID(previousIdentity.providerId, identity_.providerId) &&
                GetTickCount64() < previousOffer->expiresAt) pendingAutomaticOffer_ = previousOffer;
        }
        return result;
    }

    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* count) override {
        if (count == nullptr) {
            return E_POINTER;
        }
        if (!usageScenarioSet_) {
            return E_UNEXPECTED;
        }
        *count = kFieldCount;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(
        DWORD index,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor
    ) override {
        if (index >= kFieldCount) {
            if (descriptor != nullptr) {
                *descriptor = nullptr;
            }
            return E_INVALIDARG;
        }
        return copyFieldDescriptor(kFields[index], descriptor);
    }

    HRESULT STDMETHODCALLTYPE GetCredentialCount(
        DWORD* count,
        DWORD* defaultIndex,
        BOOL* autoLogonWithDefault
    ) override {
        if (count == nullptr || defaultIndex == nullptr ||
            autoLogonWithDefault == nullptr) {
            return E_POINTER;
        }
        *count = 0;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogonWithDefault = FALSE;
        if (!usageScenarioSet_ || !ready()) {
            return E_UNEXPECTED;
        }
        if (!hasUserSid_) return S_OK;
        unlock_windows::saved_credential::SensitiveBytes eligibility;
        unlock_windows::saved_credential::Packet eligibilityReply;
        if (!unlock_windows::saved_credential::encodeIdentity(identity_, eligibility) ||
            !unlock_windows::saved_credential::call(unlock_windows::saved_credential::Operation::unlockEligibility,
                std::move(eligibility), eligibilityReply, 250) ||
            eligibilityReply.result != unlock_windows::saved_credential::Result::success) return S_OK;
        *count = 1;
        *defaultIndex = 0;
        *autoLogonWithDefault = FALSE;
        if (pendingAutomaticOffer_) {
            const auto offer = std::exchange(pendingAutomaticOffer_, std::nullopt);
            if (events_ != nullptr && GetTickCount64() < offer->expiresAt &&
                WTSGetActiveConsoleSessionId() == consoleSessionId_) {
                credential_->armAutomaticSubmission(offer->nonce);
                *defaultIndex = 0;
                *autoLogonWithDefault = TRUE;
                OutputDebugStringW(L"[UnlockCP] automatic submission offered once\n");
            }
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCredentialAt(
        DWORD index,
        ICredentialProviderCredential** credential
    ) override {
        if (credential == nullptr) {
            return E_POINTER;
        }
        *credential = nullptr;
        if (index != 0 || !usageScenarioSet_ || !ready() || !hasUserSid_) {
            return E_INVALIDARG;
        }
        *credential = credential_;
        credential_->AddRef();
        return S_OK;
    }

private:
    static LRESULT CALLBACK approvalWindowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* provider = reinterpret_cast<UnlockCredentialProvider*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto* creation = reinterpret_cast<const CREATESTRUCTW*>(lparam);
            provider = static_cast<UnlockCredentialProvider*>(creation->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(provider));
        }
        if (message == kApprovalMessage && provider != nullptr) {
            provider->AddRef();
            provider->approvalArrived(static_cast<UINT_PTR>(wparam));
            provider->Release();
            return 0;
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }

    HRESULT createApprovalWindow() {
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&approvalWindowProcedure), &windowModule_)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        try {
            windowClassName_ = L"UnlockIPhoneApproval." + std::to_wstring(reinterpret_cast<UINT_PTR>(this));
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        }
        WNDCLASSW windowClass{};
        windowClass.lpfnWndProc = approvalWindowProcedure;
        windowClass.hInstance = windowModule_;
        windowClass.lpszClassName = windowClassName_.c_str();
        windowClass_ = RegisterClassW(&windowClass);
        if (windowClass_ == 0) return HRESULT_FROM_WIN32(GetLastError());
        approvalWindow_ = CreateWindowExW(0, windowClassName_.c_str(), L"", 0,
            0, 0, 0, 0, HWND_MESSAGE, nullptr, windowModule_, this);
        return approvalWindow_ != nullptr ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    }

    void destroyApprovalWindow() noexcept {
        if (approvalWindow_ != nullptr) {
            if (!DestroyWindow(approvalWindow_)) logAutoSubmitError(L"DestroyWindow", HRESULT_FROM_WIN32(GetLastError()));
            approvalWindow_ = nullptr;
        }
        if (windowClass_ != 0) {
            if (!UnregisterClassW(windowClassName_.c_str(), windowModule_)) {
                logAutoSubmitError(L"UnregisterClass", HRESULT_FROM_WIN32(GetLastError()));
            }
            windowClass_ = 0;
        }
    }

    void stopWatching() noexcept {
        watch_.reset();
        pendingAutomaticOffer_.reset();
        ++watchGeneration_;
    }

    HRESULT startWatching() {
        if (events_ == nullptr || !hasUserSid_ || consoleSessionId_ == 0xffffffff) return S_OK;
        if (watch_ && watch_->session == consoleSessionId_ && watch_->identity.sid == identity_.sid &&
            watch_->identity.qualifiedUserName == identity_.qualifiedUserName &&
            IsEqualGUID(watch_->identity.providerId, identity_.providerId)) return S_OK;
        stopWatching();
        try {
            auto watch = std::make_unique<ApprovalWatch>();
            watch->identity = identity_;
            watch->session = consoleSessionId_;
            watch->window = approvalWindow_;
            watch->generation = watchGeneration_;
            watch->stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (watch->stop == nullptr) return HRESULT_FROM_WIN32(GetLastError());
            auto* running = watch.get();
            watch->worker = std::thread([running]() { running->run(); });
            watch_ = std::move(watch);
        } catch (const std::bad_alloc&) {
            logAutoSubmitError(L"start approval watcher", E_OUTOFMEMORY);
            return E_OUTOFMEMORY;
        } catch (const std::system_error& error) {
            OutputDebugStringA(error.what());
            return E_FAIL;
        }
        return S_OK;
    }

    void approvalArrived(const UINT_PTR generation) noexcept {
        if (!watch_ || generation != watchGeneration_ || !hasUserSid_ || events_ == nullptr) return;
        std::optional<unlock_windows::saved_credential::AutoSubmitOffer> offer;
        std::wstring failure;
        std::optional<unlock_windows::saved_credential::AuthenticationStatus> authenticationStatus;
        {
            std::lock_guard lock(watch_->mutex);
            offer = std::exchange(watch_->offer, std::nullopt);
            failure = watch_->failure;
            authenticationStatus = watch_->authenticationStatus;
        }
        credential_->updateAuthenticationStatus(authenticationStatus, failure);
        if (!offer || GetTickCount64() >= offer->expiresAt ||
            WTSGetActiveConsoleSessionId() != consoleSessionId_) return;
        pendingAutomaticOffer_ = offer;
        auto* events = events_;
        events->AddRef();
        const HRESULT status = events->CredentialsChanged(adviseContext_);
        events->Release();
        if (FAILED(status)) {
            pendingAutomaticOffer_.reset();
            logAutoSubmitError(L"CredentialsChanged", status);
        } else {
            OutputDebugStringW(L"[UnlockCP] phone approval triggered CredentialsChanged\n");
        }
    }

    std::atomic<ULONG> refCount_{1};
    UnlockCredential* credential_ = nullptr;
    ICredentialProviderEvents* events_ = nullptr;
    UINT_PTR adviseContext_ = 0;
    bool usageScenarioSet_ = false;
    bool hasUserSid_ = false;
    unlock_windows::saved_credential::Identity identity_;
    DWORD consoleSessionId_ = 0xffffffff;
    HMODULE windowModule_ = nullptr;
    ATOM windowClass_ = 0;
    std::wstring windowClassName_;
    HWND approvalWindow_ = nullptr;
    UINT_PTR watchGeneration_ = 0;
    std::unique_ptr<ApprovalWatch> watch_;
    std::optional<unlock_windows::saved_credential::AutoSubmitOffer> pendingAutomaticOffer_;
};

class ClassFactory final : public IClassFactory {
public:
    ClassFactory() noexcept {
        objectCreated();
    }

    ~ClassFactory() {
        objectDestroyed();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) ||
            IsEqualIID(riid, __uuidof(IClassFactory))) {
            *object = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return refCount_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = refCount_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(
        IUnknown* outer,
        REFIID riid,
        void** object
    ) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (outer != nullptr) {
            return CLASS_E_NOAGGREGATION;
        }

        auto* provider = new (std::nothrow) UnlockCredentialProvider();
        if (provider == nullptr) {
            return E_OUTOFMEMORY;
        }
        if (!provider->ready()) {
            provider->Release();
            return E_OUTOFMEMORY;
        }

        const auto result = provider->QueryInterface(riid, object);
        provider->Release();
        return result;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) {
            gServerLockCount.fetch_add(1, std::memory_order_relaxed);
        } else {
            gServerLockCount.fetch_sub(1, std::memory_order_relaxed);
        }
        return S_OK;
    }

private:
    std::atomic<ULONG> refCount_{1};
};

} // namespace

STDAPI DllGetClassObject(
    REFCLSID rclsid,
    REFIID riid,
    LPVOID* ppv
) {
    if (ppv == nullptr) {
        return E_POINTER;
    }
    *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, kUnlockCredentialProviderClsid)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    auto* factory = new (std::nothrow) ClassFactory();
    if (factory == nullptr) {
        return E_OUTOFMEMORY;
    }
    const auto result = factory->QueryInterface(riid, ppv);
    factory->Release();
    return result;
}

STDAPI DllCanUnloadNow() {
    return gObjectCount.load(std::memory_order_acquire) == 0 &&
            gServerLockCount.load(std::memory_order_acquire) == 0
        ? S_OK
        : S_FALSE;
}
