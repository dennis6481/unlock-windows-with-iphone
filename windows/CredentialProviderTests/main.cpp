// Created by Rui MA on 27 Sep 2026

#include "UnlockCredentialProvider.h"
#include "../CredentialProvider/CredentialSerialization.h"
#include "../SavedCredential/SavedCredentialIpc.h"
#include "../ComponentFiles.h"
#include "../Resources/resource.h"

#include <Windows.h>
#include <initguid.h>
#include <propkey.h>
#include <ShlGuid.h>
#include <wincred.h>
#define SECURITY_WIN32
#include <sspi.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <vector>

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

struct Serialization final {
    BYTE* value = nullptr;
    DWORD bytes = 0;
    ~Serialization() {
        if (value) {
            SecureZeroMemory(value, bytes);
            CoTaskMemFree(value);
        }
    }
};

std::wstring packedString(const Serialization& serialized, const UNICODE_STRING& field, std::size_t& offset) {
    require(reinterpret_cast<ULONG_PTR>(field.Buffer) == offset && field.Length == field.MaximumLength &&
        field.Length % sizeof(wchar_t) == 0 && offset <= serialized.bytes && field.Length <= serialized.bytes - offset,
        "native strings must be consecutive byte offsets within the serialization buffer");
    const std::wstring result(reinterpret_cast<const wchar_t*>(serialized.value + offset), field.Length / sizeof(wchar_t));
    offset += field.Length;
    return result;
}

void testPasswordSerialization() {
    using unlock_windows::credential_provider::serializePassword;
    using unlock_windows::saved_credential::localAccountIdentity;
    const auto identity = localAccountIdentity(L"S-1-5-21-1-2-3-1001", L"TEST-PC", L"élise 用户");
    wchar_t password[] = L"Test-only password! 123";
    for (const auto scenario : {CPUS_LOGON, CPUS_UNLOCK_WORKSTATION}) {
        Serialization serialized;
        require(serializePassword(identity.qualifiedUserName, identity.providerId, password, scenario,
            &serialized.value, &serialized.bytes) == S_OK && serialized.bytes >= sizeof(KERB_INTERACTIVE_UNLOCK_LOGON),
            "local password must serialize for either Windows logon/unlock scenario");
        const auto* native = reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(serialized.value);
        require(native->Logon.MessageType == (scenario == CPUS_LOGON ? KerbInteractiveLogon : KerbWorkstationUnlockLogon),
            "native message type must follow the Windows-provided usage scenario");
        require(native->LogonId.LowPart == 0 && native->LogonId.HighPart == 0, "Winlogon must supply the native logon ID");
        std::size_t offset = sizeof(*native);
        require(packedString(serialized, native->Logon.LogonDomainName, offset) == L"TEST-PC", "local domain changed");
        require(packedString(serialized, native->Logon.UserName, offset) == L"élise 用户", "Unicode local username changed");
        auto secret = packedString(serialized, native->Logon.Password, offset);
        require(offset == serialized.bytes && secret != password, "serialized password must be protected without trailing data");
        CRED_PROTECTION_TYPE protection{};
        require(CredIsProtectedW(secret.data(), &protection) && protection != CredUnprotected,
            "local password must use Windows credential protection");
        DWORD chars = 0;
        require(!CredUnprotectW(FALSE, secret.data(), static_cast<DWORD>(secret.size() + 1), nullptr, &chars) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && chars > 0, "protected password must be readable in its own logon session");
        std::vector<wchar_t> plain(chars);
        require(CredUnprotectW(FALSE, secret.data(), static_cast<DWORD>(secret.size() + 1), plain.data(), &chars) &&
            std::wcscmp(plain.data(), password) == 0, "password protection changed the original password");
        SecureZeroMemory(plain.data(), plain.size() * sizeof(wchar_t));
        SecureZeroMemory(secret.data(), secret.size() * sizeof(wchar_t));
    }
    for (const auto& name : {std::wstring{}, std::wstring(L"user"), std::wstring(L"\\user"),
        std::wstring(L"TEST-PC\\"), std::wstring(L"TEST-PC\\user\\other"), std::wstring(L"PC\\user\0extra", 13)}) {
        Serialization invalid;
        require(serializePassword(name, identity.providerId, password, CPUS_LOGON, &invalid.value, &invalid.bytes) == E_INVALIDARG &&
            !invalid.value && invalid.bytes == 0, "malformed local names must not return credentials");
    }
    for (const auto scenario : {CPUS_INVALID, CPUS_CREDUI, CPUS_CHANGE_PASSWORD, CPUS_PLAP}) {
        Serialization invalid;
        require(serializePassword(identity.qualifiedUserName, identity.providerId, password, scenario,
            &invalid.value, &invalid.bytes) == E_INVALIDARG && !invalid.value && invalid.bytes == 0,
            "unsupported scenarios must not serialize a password");
    }
    wchar_t empty[] = L"";
    Serialization invalid;
    require(serializePassword(identity.qualifiedUserName, identity.providerId, empty, CPUS_LOGON,
        &invalid.value, &invalid.bytes) == E_INVALIDARG, "empty passwords are unsupported");
    require(serializePassword(identity.qualifiedUserName, identity.providerId, {}, CPUS_LOGON,
        &invalid.value, &invalid.bytes) == E_INVALIDARG, "missing passwords must reject");
    wchar_t unterminated[]{L'x', L'y'};
    require(serializePassword(identity.qualifiedUserName, identity.providerId, unterminated, CPUS_LOGON,
        &invalid.value, &invalid.bytes) == E_INVALIDARG && !invalid.value && invalid.bytes == 0,
        "unterminated password buffers must reject without scanning past their bounds");
    wchar_t embeddedNul[]{L'x', L'\0', L'y', L'\0'};
    require(serializePassword(identity.qualifiedUserName, identity.providerId, embeddedNul, CPUS_LOGON,
        &invalid.value, &invalid.bytes) == E_INVALIDARG, "embedded NUL must not truncate a password");
    std::wstring tooLong(unlock_windows::saved_credential::kMaxPasswordChars + 1, L'x');
    require(serializePassword(identity.qualifiedUserName, identity.providerId,
        std::span<wchar_t>{tooLong.data(), tooLong.size() + 1}, CPUS_LOGON,
        &invalid.value, &invalid.bytes) == E_INVALIDARG, "passwords must respect the vault limit");
    require(serializePassword(identity.qualifiedUserName, identity.providerId, password, CPUS_LOGON,
        nullptr, &invalid.bytes) == E_POINTER, "missing output pointers must reject");

    // MSA retains the native protected ID-provider format rather than the local KERB structure.
    for (const auto scenario : {CPUS_LOGON, CPUS_UNLOCK_WORKSTATION}) {
        Serialization online;
        require(serializePassword(L"MicrosoftAccount\\test@example.invalid", GUID{}, password, scenario,
            &online.value, &online.bytes) == S_OK && online.bytes > sizeof(ULONG), "MSA packing regressed");
        ULONG version = 0;
        std::memcpy(&version, online.value, sizeof(version));
        require(version == SEC_WINNT_AUTH_IDENTITY_VERSION_2, "MSA must keep SEC_WINNT_AUTH_IDENTITY_EX2 serialization");
        DWORD userChars = 0, domainChars = 0, passwordChars = 0;
        require(!CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS, online.value, online.bytes,
            nullptr, &userChars, nullptr, &domainChars, nullptr, &passwordChars) && GetLastError() == ERROR_INSUFFICIENT_BUFFER,
            "Windows must recognize and decrypt the protected MSA buffer");
        std::vector<wchar_t> user(userChars), domain(domainChars), secret(passwordChars);
        require(CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS, online.value, online.bytes,
            user.data(), &userChars, domain.data(), &domainChars, secret.data(), &passwordChars), "MSA buffer must unpack");
        SecureZeroMemory(secret.data(), secret.size() * sizeof(wchar_t));
    }
    SecureZeroMemory(password, sizeof(password));
}

void run() {
    const auto comResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    require(SUCCEEDED(comResult), "CoInitializeEx failed");
    testPasswordSerialization();

    const auto dllPath = moduleDirectory() + unlock::components::kCredentialProviderFile;
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
    require(provider->GetFieldDescriptorCount(&fieldCount) == S_OK && fieldCount == 5,
        "unexpected Credential Provider field count");

    DWORD credentialCount = 0;
    DWORD defaultIndex = 0;
    BOOL autoLogon = TRUE;
    require(
        provider->GetCredentialCount(&credentialCount, &defaultIndex, &autoLogon) == S_OK &&
            credentialCount == 0 && defaultIndex == CREDENTIAL_PROVIDER_NO_DEFAULT && autoLogon == FALSE,
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
    require(provider->GetCredentialAt(0, &credential) == E_INVALIDARG && credential == nullptr,
        "a synthetic user without verified locked console identity must have no tile");

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
    require(provider->GetFieldDescriptorAt(0, &descriptor) == S_OK, "logo field missing");
    require(descriptor->cpft == CPFT_TILE_IMAGE &&
        IsEqualGUID(descriptor->guidFieldType, CPFG_CREDENTIAL_PROVIDER_LOGO),
        "provider logo must not replace the account photo");
    CoTaskMemFree(descriptor->pszLabel);
    CoTaskMemFree(descriptor);
    const auto logo = static_cast<HBITMAP>(LoadImageW(module, MAKEINTRESOURCEW(IDB_UNLOCK_TILE),
        IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION));
    require(logo != nullptr, "embedded tile bitmap missing");
    BITMAP image{};
    require(GetObjectW(logo, sizeof(image), &image) != 0 && image.bmWidth == 72 && image.bmHeight == 72,
        "tile bitmap dimensions changed");
    DeleteObject(logo);
    descriptor = nullptr;
    require(provider->GetFieldDescriptorAt(1, &descriptor) == S_OK &&
        descriptor->cpft == CPFT_LARGE_TEXT, "title field missing");
    require(descriptor->pszLabel != nullptr &&
        std::wcscmp(descriptor->pszLabel, L"Unlock with iPhone\u00ae") == 0,
        "provider title must use the user-facing iPhone name and registered symbol");
    CoTaskMemFree(descriptor->pszLabel);
    CoTaskMemFree(descriptor);
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
