// Created by Rui MA on 27 Sep 2026

#include <initguid.h>
#include "UnlockCredentialProvider.h"
#include "SavedCredentialIpc.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cwchar>
#include <cstring>
#include <cstdint>
#include <new>
#include <string>
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
constexpr DWORD kPasswordField = 2;
constexpr DWORD kSavedCredentialField = 3;
constexpr DWORD kSubmitField = 4;
constexpr DWORD kFieldCount = 5;

struct FieldDefinition final {
    DWORD id;
    CREDENTIAL_PROVIDER_FIELD_TYPE type;
    const wchar_t* label;
    GUID fieldType;
};

const FieldDefinition kFields[] = {
    {kIconField, CPFT_TILE_IMAGE, nullptr, CPFG_CREDENTIAL_PROVIDER_LOGO},
    {kTitleField, CPFT_LARGE_TEXT, L"MSA password probe", GUID{}},
    {kPasswordField, CPFT_PASSWORD_TEXT, L"Microsoft account password", GUID{}},
    {kSavedCredentialField, CPFT_CHECKBOX, L"Use saved credential (VM test)", GUID{}},
    {kSubmitField, CPFT_SUBMIT_BUTTON, L"Test unlock", GUID{}},
};

struct TemporaryPassword final {
    std::vector<wchar_t> value;
    ~TemporaryPassword() {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
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

void clearPassword(LPWSTR& password) noexcept {
    if (password != nullptr) {
        SecureZeroMemory(password, std::wcslen(password) * sizeof(wchar_t));
        CoTaskMemFree(password);
        password = nullptr;
    }
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

HRESULT writeIdentityReport(
    const std::wstring& sid,
    const std::wstring& primarySid,
    const std::wstring& qualifiedName,
    const std::wstring& userName,
    const GUID& providerId,
    const HRESULT consoleStatus,
    const DWORD consoleSessionId,
    const wchar_t* consoleIdentityStage,
    const std::wstring& consoleAccountName,
    const std::wstring& consoleSid,
    const wchar_t* savedIdentityCapture
) {
    wchar_t tempDirectory[MAX_PATH]{};
    const auto tempLength = GetTempPathW(MAX_PATH, tempDirectory);
    if (tempLength == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (tempLength >= MAX_PATH) {
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    wchar_t providerText[39]{};
    if (StringFromGUID2(providerId, providerText, 39) == 0) {
        return E_UNEXPECTED;
    }
    const std::wstring path = std::wstring(tempDirectory) + L"unlock-msa-credential-probe.txt";
    const std::wstring report =
        L"Unlock Windows with iPhone - MSA credential probe\r\n"
        L"stage=identity-enumeration\r\n"
        L"userSid=" + sid + L"\r\n" +
        L"primarySid=" + primarySid + L"\r\n" +
        L"qualifiedUserName=" + qualifiedName + L"\r\n" +
        L"userName=" + userName + L"\r\n" +
        L"providerId=" + providerText + L"\r\n" +
        L"consoleSessionId=" + std::to_wstring(consoleSessionId) + L"\r\n" +
        L"consoleIdentityStage=" + consoleIdentityStage + L"\r\n" +
        L"consoleAccountName=" + consoleAccountName + L"\r\n" +
        L"consoleSidStatus=" + std::to_wstring(static_cast<unsigned long>(consoleStatus)) + L"\r\n" +
        L"consoleSid=" + consoleSid + L"\r\n" +
        L"savedIdentityCapture=" + savedIdentityCapture + L"\r\n" +
        L"passwordRecorded=no\r\n";
    const auto file = CreateFileW(
        path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    constexpr wchar_t bom = 0xfeff;
    DWORD written = 0;
    const bool wroteBom = WriteFile(file, &bom, sizeof(bom), &written, nullptr) && written == sizeof(bom);
    const auto bytes = static_cast<DWORD>(report.size() * sizeof(wchar_t));
    const bool wroteReport = wroteBom && WriteFile(file, report.data(), bytes, &written, nullptr) && written == bytes;
    const auto error = wroteReport ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    return wroteReport ? S_OK : HRESULT_FROM_WIN32(error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error);
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
    BITMAPINFO bitmapInfo{};
    bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bitmapInfo.bmiHeader.biWidth = 72;
    bitmapInfo.bmiHeader.biHeight = -72;
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
        return nullptr;
    }

    auto* const pixelBuffer = static_cast<std::uint32_t*>(pixels);
    for (int y = 0; y < 72; ++y) {
        for (int x = 0; x < 72; ++x) {
            pixelBuffer[y * 72 + x] = 0x00c2410c;
        }
    }

    for (int y = 12; y < 60; ++y) {
        for (int x = 24; x < 48; ++x) {
            pixelBuffer[y * 72 + x] = 0x00ffffff;
        }
    }
    for (int y = 18; y < 54; ++y) {
        for (int x = 28; x < 44; ++x) {
            pixelBuffer[y * 72 + x] = 0x00c2410c;
        }
    }
    for (int y = 55; y < 58; ++y) {
        for (int x = 33; x < 39; ++x) {
            pixelBuffer[y * 72 + x] = 0x00c2410c;
        }
    }

    return bitmap;
}

class UnlockCredential final : public ICredentialProviderCredential2 {
public:
    UnlockCredential() noexcept {
        objectCreated();
    }

    UnlockCredential(const UnlockCredential&) = delete;
    UnlockCredential& operator=(const UnlockCredential&) = delete;

    ~UnlockCredential() {
        clearPassword(password_);
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
        clearPassword(password_);
        useSavedCredential_ = false;
        if (events_ != nullptr) {
            const auto status = events_->SetFieldString(this, kPasswordField, L"");
            if (FAILED(status)) return status;
            return events_->SetFieldCheckbox(this, kSavedCredentialField, FALSE, L"Use saved credential (VM test)");
        }
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
            case kPasswordField:
                *state = CPFS_DISPLAY_IN_SELECTED_TILE;
                *interactiveState = CPFIS_FOCUSED;
                return S_OK;
            case kSavedCredentialField:
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
                return copyString(L"MSA password probe", value);
            case kPasswordField:
                return copyString(password_ == nullptr ? L"" : password_, value);
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
        if (fieldId != kSavedCredentialField) return E_INVALIDARG;
        *checked = useSavedCredential_ ? TRUE : FALSE;
        return copyString(L"Use saved credential (VM test)", label);
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
        *adjacentTo = kPasswordField;
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

    HRESULT STDMETHODCALLTYPE SetStringValue(DWORD fieldId, LPCWSTR value) override {
        if (fieldId != kPasswordField || value == nullptr) {
            return E_INVALIDARG;
        }
        LPWSTR replacement = nullptr;
        const auto result = copyString(value, &replacement);
        if (FAILED(result)) {
            return result;
        }
        clearPassword(password_);
        password_ = replacement;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD fieldId, BOOL checked) override {
        if (fieldId != kSavedCredentialField) return E_INVALIDARG;
        useSavedCredential_ = checked != FALSE;
        if (useSavedCredential_) {
            clearPassword(password_);
            if (events_ != nullptr) return events_->SetFieldString(this, kPasswordField, L"");
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD, DWORD) override {
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override {
        return E_INVALIDARG;
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

        if (!useSavedCredential_ && (password_ == nullptr || password_[0] == L'\0')) {
            clearPassword(password_);
            return copyString(L"Enter the Microsoft account password for this VM probe.", optionalStatusText);
        }
        if (qualifiedUserName_.empty() || userSid_.empty() || primarySid_ != userSid_ ||
            consoleSessionId_ == 0xffffffff) {
            clearPassword(password_);
            return copyString(L"The selected Windows user identity is incomplete or inconsistent.", optionalStatusText);
        }

        if (WTSGetActiveConsoleSessionId() != consoleSessionId_) {
            clearPassword(password_);
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
            clearPassword(password_);
            return copyString(statusText, optionalStatusText);
        }
        if (consoleSessionId != consoleSessionId_ || consoleSid != userSid_) {
            clearPassword(password_);
            return copyString(L"The selected account is not the active console user.", optionalStatusText);
        }

        ULONG authenticationPackage = 0;
        const auto packageStatus = negotiatePackage(authenticationPackage);
        if (FAILED(packageStatus)) {
            clearPassword(password_);
            return copyString(
                L"The Windows Negotiate authentication package is unavailable.",
                optionalStatusText
            );
        }

        TemporaryPassword savedPassword;
        LPWSTR passwordForPacking = password_;
        if (useSavedCredential_) {
            try {
                unlock_windows::saved_credential::Identity identity{
                    userSid_, qualifiedUserName_, providerId_
                };
                if (!savedNonceAvailable_) {
                    unlock_windows::saved_credential::SensitiveBytes captureRequest;
                    unlock_windows::saved_credential::Packet captureReply;
                    if (!unlock_windows::saved_credential::encodeIdentity(identity, captureRequest) ||
                        !unlock_windows::saved_credential::call(
                            unlock_windows::saved_credential::Operation::captureIdentity,
                            std::move(captureRequest), captureReply
                        ) || captureReply.result != unlock_windows::saved_credential::Result::success ||
                        captureReply.payload.value.size() != savedNonce_.size()) {
                        clearPassword(password_);
                        return copyString(L"Saved credential identity capture failed while submitting. Use the native PIN, then try a new test.",
                            optionalStatusText);
                    }
                    std::copy_n(captureReply.payload.value.begin(), savedNonce_.size(), savedNonce_.begin());
                    savedNonceAvailable_ = true;
                }
                unlock_windows::saved_credential::SensitiveBytes request;
                unlock_windows::saved_credential::Packet reply;
                if (!unlock_windows::saved_credential::encodeIdentity(identity, request)) {
                    clearPassword(password_);
                    return copyString(L"The saved-credential identity cannot be encoded.", optionalStatusText);
                }
                request.value.insert(request.value.end(), savedNonce_.begin(), savedNonce_.end());
                if (!unlock_windows::saved_credential::call(
                        unlock_windows::saved_credential::Operation::claimCredential,
                        std::move(request), reply
                    ) || reply.result != unlock_windows::saved_credential::Result::success ||
                    reply.payload.value.empty() || reply.payload.value.size() > 2048 ||
                    reply.payload.value.size() % sizeof(wchar_t) != 0) {
                    clearPassword(password_);
                    return copyString(L"Saved credential claim was refused. Re-authorize one VM test on the desktop.",
                        optionalStatusText);
                }
                const auto chars = reply.payload.value.size() / sizeof(wchar_t);
                savedPassword.value.resize(chars + 1, L'\0');
                std::memcpy(savedPassword.value.data(), reply.payload.value.data(), reply.payload.value.size());
                if (savedPassword.value[0] == L'\0' ||
                    std::find(savedPassword.value.begin(), savedPassword.value.begin() + chars, L'\0') !=
                        savedPassword.value.begin() + chars) {
                    clearPassword(password_);
                    return copyString(L"Saved credential response is malformed.", optionalStatusText);
                }
                passwordForPacking = savedPassword.value.data();
                reply.payload.clear();
            } catch (const std::bad_alloc&) {
                clearPassword(password_);
                return E_OUTOFMEMORY;
            }
        }

        constexpr DWORD flags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;
        DWORD size = 0;
        const auto sized = CredPackAuthenticationBufferW(
            flags, const_cast<LPWSTR>(qualifiedUserName_.c_str()), passwordForPacking, nullptr, &size
        );
        if (sized || GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            clearPassword(password_);
            return copyString(
                L"Windows could not size the online identity credential buffer.",
                optionalStatusText
            );
        }

        const DWORD allocatedSize = size;
        auto* packed = static_cast<BYTE*>(CoTaskMemAlloc(allocatedSize));
        if (packed == nullptr) {
            clearPassword(password_);
            return E_OUTOFMEMORY;
        }
        const auto packedResult = CredPackAuthenticationBufferW(
            flags, const_cast<LPWSTR>(qualifiedUserName_.c_str()), passwordForPacking, packed, &size
        );
        clearPassword(password_);
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
        NTSTATUS status,
        NTSTATUS,
        LPWSTR* optionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* optionalStatusIcon
    ) override {
        if (optionalStatusText == nullptr || optionalStatusIcon == nullptr) {
            return E_POINTER;
        }
        *optionalStatusText = nullptr;
        *optionalStatusIcon = CPSI_NONE;
        if (status < 0) {
            clearPassword(password_);
            if (events_ != nullptr) {
                return events_->SetFieldString(this, kPasswordField, L"");
            }
        }
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
        DWORD consoleSessionId,
        const std::array<std::uint8_t, unlock_windows::saved_credential::kNonceSize>& savedNonce,
        bool savedNonceAvailable
    ) noexcept {
        if (sid.empty() || primarySid.empty() || qualifiedName.empty()) {
            userSid_.clear();
            primarySid_.clear();
            qualifiedUserName_.clear();
            savedNonce_.fill(0);
            savedNonceAvailable_ = false;
            consoleSessionId_ = 0xffffffff;
            return E_INVALIDARG;
        }
        try {
            userSid_ = sid;
            primarySid_ = primarySid;
            qualifiedUserName_ = qualifiedName;
            providerId_ = providerId;
            consoleSessionId_ = consoleSessionId;
            savedNonce_ = savedNonce;
            savedNonceAvailable_ = savedNonceAvailable;
            useSavedCredential_ = false;
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        }
        return S_OK;
    }

    void clearIdentity() noexcept {
        clearPassword(password_);
        userSid_.clear();
        primarySid_.clear();
        qualifiedUserName_.clear();
        providerId_ = GUID{};
        savedNonce_.fill(0);
        savedNonceAvailable_ = false;
        useSavedCredential_ = false;
        consoleSessionId_ = 0xffffffff;
    }

private:
    std::atomic<ULONG> refCount_{1};
    ICredentialProviderCredentialEvents* events_ = nullptr;
    std::wstring userSid_;
    std::wstring primarySid_;
    std::wstring qualifiedUserName_;
    GUID providerId_{};
    std::array<std::uint8_t, unlock_windows::saved_credential::kNonceSize> savedNonce_{};
    bool savedNonceAvailable_ = false;
    DWORD consoleSessionId_ = 0xffffffff;
    LPWSTR password_ = nullptr;
    bool useSavedCredential_ = false;
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
        if (events_ != nullptr) {
            events_->Release();
        }
        events_ = events;
        events_->AddRef();
        adviseContext_ = adviseContext;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE UnAdvise() override {
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

        hasUserSid_ = false;
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
            return S_FALSE;
        }

        std::wstring consoleSid;
        std::wstring consoleAccountName;
        DWORD consoleSessionId = 0xffffffff;
        const wchar_t* consoleIdentityStage = L"not-started";
        const auto consoleStatus = activeConsoleUserSid(
            consoleSid, &consoleSessionId, &consoleAccountName, &consoleIdentityStage
        );
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
            if (matches || (userCount == 1 && index == 0)) {
                user = candidate;
                break;
            }
            candidate->Release();
        }
        if (user == nullptr) {
            return E_UNEXPECTED;
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
        std::wstring userName;
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
        if (SUCCEEDED(result)) result = propertyString(user, PKEY_Identity_UserName, userName);
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
        const wchar_t* savedIdentityCapture = L"not-attempted";
        std::array<std::uint8_t, unlock_windows::saved_credential::kNonceSize> savedNonce{};
        bool savedNonceAvailable = false;
        if (SUCCEEDED(consoleStatus) && consoleSid == sidValue && sidValue == primarySid) {
            unlock_windows::saved_credential::SensitiveBytes request;
            unlock_windows::saved_credential::Packet reply;
            try {
                unlock_windows::saved_credential::Identity identity{sidValue, qualifiedName, providerId};
                if (unlock_windows::saved_credential::encodeIdentity(identity, request) &&
                    unlock_windows::saved_credential::call(
                        unlock_windows::saved_credential::Operation::captureIdentity,
                        std::move(request), reply, 250
                    ) && reply.result == unlock_windows::saved_credential::Result::success &&
                    reply.payload.value.size() == savedNonce.size()) {
                    std::copy_n(reply.payload.value.begin(), savedNonce.size(), savedNonce.begin());
                    savedNonceAvailable = true;
                    savedIdentityCapture = L"accepted";
                } else {
                    savedIdentityCapture = L"unavailable-or-rejected";
                }
            } catch (const std::bad_alloc&) {
                savedIdentityCapture = L"out-of-memory";
            }
        }
        result = writeIdentityReport(
            sidValue, primarySid, qualifiedName, userName, providerId,
            consoleStatus, consoleSessionId, consoleIdentityStage,
            consoleAccountName, consoleSid, savedIdentityCapture
        );
        if (FAILED(result)) {
            return result;
        }
        if (sidValue != primarySid) {
            return E_UNEXPECTED;
        }
        if (credential_ == nullptr) {
            return E_UNEXPECTED;
        }
        result = credential_->setUserIdentity(
            sidValue, primarySid, qualifiedName, providerId, consoleSessionId,
            savedNonce, savedNonceAvailable
        );
        if (SUCCEEDED(result)) {
            hasUserSid_ = true;
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
        if (!usageScenarioSet_ || !ready() || !hasUserSid_) {
            return E_UNEXPECTED;
        }
        *count = 1;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogonWithDefault = FALSE;
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
        if (index != 0 || !usageScenarioSet_ || !ready()) {
            return E_INVALIDARG;
        }
        *credential = credential_;
        credential_->AddRef();
        return S_OK;
    }

private:
    std::atomic<ULONG> refCount_{1};
    UnlockCredential* credential_ = nullptr;
    ICredentialProviderEvents* events_ = nullptr;
    UINT_PTR adviseContext_ = 0;
    bool usageScenarioSet_ = false;
    bool hasUserSid_ = false;
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
