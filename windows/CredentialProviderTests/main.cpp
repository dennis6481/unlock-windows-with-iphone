// Created by Rui MA on 27 Sep 2026

#include "UnlockCredentialProvider.h"
#include "UnlockCredentialSerialization.h"

#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace {

using unlock_windows::credential_provider::kUnlockCredentialProviderClsid;
using unlock_windows::credential_provider::ApprovedUnlock;
using unlock_windows::credential_provider::buildCredentialSerialization;
using unlock_windows::protocol::UnlockLogonBuffer;
using unlock_windows::protocol::validateUnlockLogonBuffer;

using GetClassObject = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);
using CanUnloadNow = HRESULT(STDAPICALLTYPE*)();

void require(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

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
        provider->SetUsageScenario(CPUS_LOGON, 0) == E_NOTIMPL,
        "logon usage scenario was unexpectedly enabled"
    );

    DWORD fieldCount = 0;
    require(provider->GetFieldDescriptorCount(&fieldCount) == S_OK && fieldCount == 3,
        "unexpected Credential Provider field count");

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
    require(provider->GetFieldDescriptorAt(0, &descriptor) == S_OK, "title field missing");
    require(descriptor->cpft == CPFT_LARGE_TEXT, "title field type mismatch");
    CoTaskMemFree(descriptor->pszLabel);
    CoTaskMemFree(descriptor);

    DWORD credentialCount = 0;
    DWORD defaultIndex = 0;
    BOOL autoLogon = TRUE;
    require(
        provider->GetCredentialCount(&credentialCount, &defaultIndex, &autoLogon) == S_OK &&
            credentialCount == 1 && defaultIndex == 0 && autoLogon == FALSE,
        "unexpected Credential Provider credential count"
    );

    ICredentialProviderCredential* credential = nullptr;
    require(provider->GetCredentialAt(0, &credential) == S_OK, "credential tile missing");

    LPWSTR title = nullptr;
    require(credential->GetStringValue(0, &title) == S_OK, "credential title missing");
    require(std::wstring(title) == L"Unlock Windows with iPhone", "credential title mismatch");
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
        response == CPGSR_NO_CREDENTIAL_FINISHED &&
            serialization.cbSerialization == 0 &&
            statusIcon == CPSI_WARNING &&
            status != nullptr,
        "prototype unexpectedly returned a credential"
    );
    CoTaskMemFree(status);
    credential->Release();
    provider->Release();
    require(canUnloadNow() == S_OK, "Credential Provider DLL still has live objects");
    FreeLibrary(module);
    CoUninitialize();
}

void testSerializationAdapter() {
    ApprovedUnlock approval;
    approval.challenge.version = 1;
    approval.challenge.issuedAtMilliseconds = 123456789;
    approval.challenge.audience = "windows-unlock";
    for (std::size_t index = 0; index < approval.challenge.requestId.size(); ++index) {
        approval.challenge.requestId[index] = static_cast<std::uint8_t>(0x10 + index);
    }
    for (std::size_t index = 0; index < approval.challenge.nonce.size(); ++index) {
        approval.challenge.nonce[index] = static_cast<std::uint8_t>(0x20 + index);
    }

    for (std::size_t index = 0; index < approval.keyId.size(); ++index) {
        approval.keyId[index] = static_cast<std::uint8_t>(0xa0 + index);
    }
    approval.sid = {
        1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0
    };
    for (std::size_t index = 0; index < approval.signature.size(); ++index) {
        approval.signature[index] = static_cast<std::uint8_t>(0x40 + index);
    }

    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
    const auto result = buildCredentialSerialization(approval, 0x1234, serialization);
    require(result.succeeded(), "valid approval was not serialized");
    require(
        serialization.ulAuthenticationPackage == 0x1234 &&
            IsEqualGUID(serialization.clsidCredentialProvider, kUnlockCredentialProviderClsid) &&
            serialization.cbSerialization == sizeof(UnlockLogonBuffer) &&
            serialization.rgbSerialization != nullptr,
        "serialization metadata is incorrect"
    );

    const auto bytes = std::span<const std::uint8_t>(
        serialization.rgbSerialization,
        serialization.cbSerialization
    );
    require(validateUnlockLogonBuffer(bytes).succeeded(), "serialized buffer failed codec validation");

    const auto* buffer = reinterpret_cast<const UnlockLogonBuffer*>(
        serialization.rgbSerialization
    );
    require(
        std::memcmp(buffer->keyId, approval.keyId.data(), approval.keyId.size()) == 0 &&
            std::memcmp(buffer->sid, approval.sid.data(), approval.sid.size()) == 0 &&
            std::memcmp(buffer->signatureRaw, approval.signature.data(), approval.signature.size()) == 0,
        "serialized buffer does not preserve approval fields"
    );
    CoTaskMemFree(serialization.rgbSerialization);

    approval.sid.clear();
    serialization = {};
    const auto invalid = buildCredentialSerialization(approval, 0x1234, serialization);
    require(
        invalid.code == unlock_windows::credential_provider::SerializationCode::invalid_logon_buffer &&
            invalid.bufferCode == unlock_windows::protocol::UnlockLogonBufferCode::invalid_sid &&
            serialization.rgbSerialization == nullptr,
        "invalid approval unexpectedly produced a serialization"
    );
}

} // namespace

int main() {
    try {
        run();
        testSerializationAdapter();
        return 0;
    } catch (const std::exception& error) {
        return std::fprintf(stderr, "Credential Provider test failed: %s\n", error.what()), 1;
    }
}
