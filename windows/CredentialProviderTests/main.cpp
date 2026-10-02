// Created by Rui MA on 27 Sep 2026

#include "UnlockCredentialProvider.h"

#include <Windows.h>
#include <initguid.h>
#include <propkey.h>
#include <ShlGuid.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cwchar>
#include <stdexcept>
#include <string>

namespace {

using unlock_windows::credential_provider::kUnlockCredentialProviderClsid;

using GetClassObject = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);
using CanUnloadNow = HRESULT(STDAPICALLTYPE*)();

class TestEvents final : public ICredentialProviderEvents {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override {
        if (value == nullptr) return E_POINTER;
        *value = nullptr;
        if (!IsEqualIID(iid, IID_IUnknown) && !IsEqualIID(iid, __uuidof(ICredentialProviderEvents))) {
            return E_NOINTERFACE;
        }
        *value = static_cast<ICredentialProviderEvents*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { return --references; }
    HRESULT STDMETHODCALLTYPE CredentialsChanged(UINT_PTR) override {
        ++changes;
        return S_OK;
    }
    std::atomic<ULONG> references{1};
    unsigned int changes = 0;
};

void require(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TestUser final : public ICredentialProviderUser {
public:
    explicit TestUser(const wchar_t* sid) : sid_(sid) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        void** object
    ) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) ||
            IsEqualIID(riid, __uuidof(ICredentialProviderUser))) {
            *object = static_cast<ICredentialProviderUser*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return refCount_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        return refCount_.fetch_sub(1, std::memory_order_acq_rel) - 1;
    }

    HRESULT STDMETHODCALLTYPE GetSid(LPWSTR* sid) override {
        if (sid == nullptr) {
            return E_POINTER;
        }
        *sid = nullptr;
        const auto bytes = (sid_.size() + 1) * sizeof(wchar_t);
        *sid = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (*sid == nullptr) {
            return E_OUTOFMEMORY;
        }
        std::memcpy(*sid, sid_.c_str(), bytes);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetProviderID(GUID* providerId) override {
        if (providerId == nullptr) {
            return E_POINTER;
        }
        *providerId = GUID{};
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetStringValue(
        REFPROPERTYKEY key,
        LPWSTR* stringValue
    ) override {
        if (stringValue == nullptr) {
            return E_POINTER;
        }
        *stringValue = nullptr;
        const wchar_t* value = nullptr;
        if (IsEqualPropertyKey(key, PKEY_Identity_PrimarySid)) {
            value = sid_.c_str();
        } else if (IsEqualPropertyKey(key, PKEY_Identity_QualifiedUserName)) {
            value = L"MicrosoftAccount\\test@example.com";
        } else if (IsEqualPropertyKey(key, PKEY_Identity_UserName)) {
            value = L"test@example.com";
        } else {
            return E_NOTIMPL;
        }
        const auto bytes = (std::wcslen(value) + 1) * sizeof(wchar_t);
        *stringValue = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (*stringValue == nullptr) {
            return E_OUTOFMEMORY;
        }
        std::memcpy(*stringValue, value, bytes);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetValue(
        REFPROPERTYKEY,
        PROPVARIANT* value
    ) override {
        if (value != nullptr) {
            *value = {};
        }
        return E_NOTIMPL;
    }

private:
    std::atomic<ULONG> refCount_{1};
    std::wstring sid_;
};

class TestUserArray final : public ICredentialProviderUserArray {
public:
    explicit TestUserArray(const wchar_t* sid) : user_(sid) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        void** object
    ) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) ||
            IsEqualIID(riid, __uuidof(ICredentialProviderUserArray))) {
            *object = static_cast<ICredentialProviderUserArray*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return refCount_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        return refCount_.fetch_sub(1, std::memory_order_acq_rel) - 1;
    }

    HRESULT STDMETHODCALLTYPE SetProviderFilter(REFGUID) override {
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetAccountOptions(
        CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* options
    ) override {
        if (options == nullptr) {
            return E_POINTER;
        }
        *options = CPAO_NONE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCount(DWORD* count) override {
        if (count == nullptr) {
            return E_POINTER;
        }
        *count = 1;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetAt(
        DWORD index,
        ICredentialProviderUser** user
    ) override {
        if (user == nullptr) {
            return E_POINTER;
        }
        *user = nullptr;
        if (index != 0) {
            return E_INVALIDARG;
        }
        *user = &user_;
        user_.AddRef();
        return S_OK;
    }

private:
    std::atomic<ULONG> refCount_{1};
    TestUser user_;
};

std::wstring moduleDirectory() {
    std::wstring path(32'768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(length != 0 && length < path.size(), "GetModuleFileNameW failed");
    path.resize(length);
    const auto separator = path.find_last_of(L'\\');
    require(separator != std::wstring::npos, "test executable path has no directory");
    path.resize(separator + 1);
    return path;
}

void run() {
    const auto comResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    require(SUCCEEDED(comResult), "CoInitializeEx failed");

    const auto dllPath = moduleDirectory() + L"unlock_credential_provider.dll";
    const auto module = LoadLibraryW(dllPath.c_str());
    require(module != nullptr, "could not load Credential Provider prototype DLL");

    const auto getClassObject = reinterpret_cast<GetClassObject>(
        GetProcAddress(module, "DllGetClassObject")
    );
    const auto canUnloadNow = reinterpret_cast<CanUnloadNow>(
        GetProcAddress(module, "DllCanUnloadNow")
    );
    require(getClassObject != nullptr, "DllGetClassObject is not exported");
    require(canUnloadNow != nullptr, "DllCanUnloadNow is not exported");

    IClassFactory* factory = nullptr;
    require(
        SUCCEEDED(getClassObject(
            kUnlockCredentialProviderClsid,
            __uuidof(IClassFactory),
            reinterpret_cast<void**>(&factory)
        )),
        "class factory could not be created"
    );

    ICredentialProvider* provider = nullptr;
    require(
        SUCCEEDED(factory->CreateInstance(
            nullptr,
            __uuidof(ICredentialProvider),
            reinterpret_cast<void**>(&provider)
        )),
        "Credential Provider could not be instantiated"
    );
    factory->Release();

    require(
        provider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0) == S_OK,
        "unlock workstation usage scenario was rejected"
    );
    require(
        provider->SetUsageScenario(CPUS_LOGON, 0) == S_OK,
        "Windows 10+ logon/unlock usage scenario was rejected"
    );
    require(
        provider->SetUsageScenario(CPUS_CREDUI, 0) == E_NOTIMPL,
        "CredUI usage scenario was unexpectedly enabled"
    );

    ICredentialProviderSetUserArray* setUserArray = nullptr;
    require(
        provider->QueryInterface(
            __uuidof(ICredentialProviderSetUserArray),
            reinterpret_cast<void**>(&setUserArray)
        ) == S_OK,
        "V2 user-array interface is missing"
    );
    TestUserArray users(L"S-1-5-21-1000-1000-1000-1001");
    require(
        setUserArray->SetUserArray(&users) == S_OK,
        "Credential Provider rejected the user array"
    );
    setUserArray->Release();

    DWORD fieldCount = 0;
    require(provider->GetFieldDescriptorCount(&fieldCount) == S_OK && fieldCount == 3,
        "unexpected Credential Provider field count");

    DWORD credentialCount = 0;
    DWORD defaultIndex = 0;
    BOOL autoLogon = TRUE;
    require(
        provider->GetCredentialCount(&credentialCount, &defaultIndex, &autoLogon) == S_OK &&
            credentialCount == 1 && defaultIndex == CREDENTIAL_PROVIDER_NO_DEFAULT && autoLogon == FALSE,
        "unexpected Credential Provider credential count"
    );

    TestEvents events;
    for (unsigned int cycle = 0; cycle < 2; ++cycle) {
        require(provider->Advise(&events, 42) == S_OK, "automatic submission advice failed");
        require(provider->GetCredentialCount(&credentialCount, &defaultIndex, &autoLogon) == S_OK &&
            defaultIndex == CREDENTIAL_PROVIDER_NO_DEFAULT && autoLogon == FALSE && events.changes == 0,
            "advice must not auto-submit without a service offer");
        require(provider->UnAdvise() == S_OK && events.references == 1,
            "unadvice must release the callback and permit another advice cycle");
    }

    ICredentialProviderCredential* credential = nullptr;
    require(provider->GetCredentialAt(0, &credential) == S_OK, "credential tile missing");

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
    require(provider->GetFieldDescriptorAt(0, &descriptor) == S_OK, "logo field missing");
    require(descriptor->cpft == CPFT_TILE_IMAGE, "logo field type mismatch");
    require(IsEqualGUID(descriptor->guidFieldType, CPFG_CREDENTIAL_PROVIDER_LOGO),
        "logo field GUID mismatch");
    HBITMAP logo = nullptr;
    require(credential != nullptr, "credential must be available before testing its logo");
    CoTaskMemFree(descriptor->pszLabel);
    CoTaskMemFree(descriptor);
    require(credential->GetBitmapValue(0, &logo) == S_OK && logo != nullptr,
        "credential logo is missing");
    DeleteObject(logo);

    descriptor = nullptr;
    require(provider->GetFieldDescriptorAt(1, &descriptor) == S_OK, "title field missing");
    require(descriptor->cpft == CPFT_LARGE_TEXT, "title field type mismatch");
    CoTaskMemFree(descriptor->pszLabel);
    CoTaskMemFree(descriptor);

    ICredentialProviderCredential2* credential2 = nullptr;
    require(
        credential->QueryInterface(
            __uuidof(ICredentialProviderCredential2),
            reinterpret_cast<void**>(&credential2)
        ) == S_OK,
        "V2 credential interface is missing"
    );
    LPWSTR userSid = nullptr;
    require(
        credential2->GetUserSid(&userSid) == S_OK &&
            std::wstring(userSid) == L"S-1-5-21-1000-1000-1000-1001",
        "Credential Provider returned the wrong user SID"
    );
    CoTaskMemFree(userSid);
    credential2->Release();

    LPWSTR title = nullptr;
    require(credential->GetStringValue(1, &title) == S_OK, "credential title missing");
    require(std::wstring(title) == L"Unlock with iPhone", "credential title mismatch");
    CoTaskMemFree(title);

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
    LPWSTR status = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON statusIcon = CPSI_NONE;
    require(
        credential->GetSerialization(&response, &serialization, &status, &statusIcon) == S_OK,
        "Credential Provider serialization call failed"
    );
    require(
        response == CPGSR_NO_CREDENTIAL_NOT_FINISHED &&
            serialization.cbSerialization == 0 &&
            statusIcon == CPSI_WARNING &&
            status != nullptr,
        "provider unexpectedly returned a credential without an approved grant"
    );
    CoTaskMemFree(status);
    credential->Release();
    provider->Release();
    require(canUnloadNow() == S_OK, "Credential Provider DLL still has live objects");
    FreeLibrary(module);
    CoUninitialize();
}

} // namespace

int main() {
    try {
        run();
        return 0;
    } catch (const std::exception& error) {
        return std::fprintf(stderr, "Credential Provider test failed: %s\n", error.what()), 1;
    }
}
