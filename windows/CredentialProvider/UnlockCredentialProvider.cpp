// Created by Rui MA on 27 Sep 2026

#include "UnlockCredentialProvider.h"

#include <atomic>
#include <cwchar>
#include <cstring>
#include <new>

namespace {

using unlock_windows::credential_provider::kUnlockCredentialProviderClsid;

constexpr DWORD kTitleField = 0;
constexpr DWORD kStatusField = 1;
constexpr DWORD kSubmitField = 2;
constexpr DWORD kFieldCount = 3;

struct FieldDefinition final {
    DWORD id;
    CREDENTIAL_PROVIDER_FIELD_TYPE type;
    const wchar_t* label;
};

constexpr FieldDefinition kFields[] = {
    {kTitleField, CPFT_LARGE_TEXT, L"Unlock with iPhone"},
    {kStatusField, CPFT_SMALL_TEXT, L"Status"},
    {kSubmitField, CPFT_SUBMIT_BUTTON, L"Unlock"},
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
    descriptor->guidFieldType = GUID_NULL;
    descriptor->pszLabel = nullptr;
    const auto result = copyString(definition.label, &descriptor->pszLabel);
    if (FAILED(result)) {
        CoTaskMemFree(descriptor);
        return result;
    }

    *output = descriptor;
    return S_OK;
}

class UnlockCredential final : public ICredentialProviderCredential {
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
            IsEqualIID(riid, __uuidof(ICredentialProviderCredential))) {
            *object = static_cast<ICredentialProviderCredential*>(this);
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
            case kTitleField:
            case kStatusField:
                *state = CPFS_DISPLAY_IN_BOTH;
                *interactiveState = CPFIS_READONLY;
                return S_OK;
            case kSubmitField:
                *state = CPFS_DISPLAY_IN_SELECTED_TILE;
                *interactiveState = CPFIS_FOCUSED;
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
            case kTitleField:
                return copyString(L"Unlock Windows with iPhone", value);
            case kStatusField:
                return copyString(
                    L"Test provider: LSA authentication package is not installed",
                    value
                );
            default:
                if (value != nullptr) {
                    *value = nullptr;
                }
                return E_INVALIDARG;
        }
    }

    HRESULT STDMETHODCALLTYPE GetBitmapValue(
        DWORD,
        HBITMAP* bitmap
    ) override {
        if (bitmap == nullptr) {
            return E_POINTER;
        }
        *bitmap = nullptr;
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE GetCheckboxValue(
        DWORD,
        BOOL* checked,
        LPWSTR* label
    ) override {
        if (checked != nullptr) {
            *checked = FALSE;
        }
        if (label != nullptr) {
            *label = nullptr;
        }
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

        *response = CPGSR_NO_CREDENTIAL_FINISHED;
        *serialization = {};
        *optionalStatusText = nullptr;
        *optionalStatusIcon = CPSI_WARNING;
        return copyString(
            L"The LSA authentication package is not installed; no credential was submitted.",
            optionalStatusText
        );
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

private:
    std::atomic<ULONG> refCount_{1};
    ICredentialProviderCredentialEvents* events_ = nullptr;
};

class UnlockCredentialProvider final : public ICredentialProvider {
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
        if (scenario != CPUS_UNLOCK_WORKSTATION) {
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
        if (!usageScenarioSet_ || !ready()) {
            return E_UNEXPECTED;
        }
        *count = 1;
        *defaultIndex = 0;
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
