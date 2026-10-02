// Created by Rui MA on 26 Sep 2026

#include "EnrollmentStore.h"

#include <Windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

namespace {

void require(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::wstring testPath() {
    wchar_t directory[MAX_PATH]{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(directory)), directory);
    require(length != 0 && length < std::size(directory), "GetTempPathW failed");
    return std::wstring(directory) +
        L"unlock-windows-with-iphone-enrollment-test-" +
        std::to_wstring(GetCurrentProcessId()) +
        L".dat";
}

std::vector<std::uint8_t> generatePublicKey() {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) >= 0,
        "could not open P-256 provider");
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(algorithm, &key, 256, 0);
    if (status >= 0) status = BCryptFinalizeKeyPair(key, 0);
    ULONG size = 0;
    if (status >= 0) status = BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &size, 0);
    std::vector<std::uint8_t> blob(size);
    if (status >= 0) status = BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob.data(), size, &size, 0);
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    require(status >= 0 && blob.size() == sizeof(BCRYPT_ECCKEY_BLOB) + 64, "could not export P-256 test key");
    std::vector<std::uint8_t> result{0x04};
    result.insert(result.end(), blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.end());
    return result;
}

std::vector<char> encryptedBytes(const std::wstring& path) {
    std::ifstream input(std::filesystem::path(path), std::ios::binary);
    require(input.is_open(), "could not read encrypted enrollment file");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

} // namespace

int main() {
    try {
        const auto expected = generatePublicKey();

        unlock_windows::phone_approval::EnrollmentStore store(testPath());
        const unlock_windows::phone_approval::EnrollmentRecord expectedRecord{
            expected,
            unlock_windows::phone_approval::EnrollmentStore::currentUserSid()
        };
        store.remove();
        store.save(expectedRecord);
        const auto loaded = store.load();
        require(loaded.has_value(), "enrollment store did not load the saved record");
        require(loaded->publicKey == expected, "enrollment store returned a different key");
        require(
            loaded->accountSid == expectedRecord.accountSid,
            "enrollment store returned a different account SID"
        );
        const auto originalBytes = encryptedBytes(store.path());
        const unlock_windows::phone_approval::EnrollmentRecord replacement{
            generatePublicKey(), expectedRecord.accountSid
        };
        bool rejected = false;
        try { store.save(replacement, [] { throw std::runtime_error("cancelled before commit"); }); }
        catch (const std::exception&) { rejected = true; }
        require(rejected, "cancelled commit was accepted");
        require(encryptedBytes(store.path()) == originalBytes, "cancelled commit changed original bytes");
        const HANDLE held = CreateFileW(store.path().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        require(held != INVALID_HANDLE_VALUE, "could not hold enrollment file against replacement");
        rejected = false;
        try { store.save(replacement); }
        catch (const std::exception&) { rejected = true; }
        CloseHandle(held);
        require(rejected, "replacement of a held file unexpectedly succeeded");
        require(encryptedBytes(store.path()) == originalBytes, "failed replacement changed original bytes");
        auto invalid = expectedRecord;
        invalid.publicKey.assign(65, 0);
        invalid.publicKey[0] = 0x04;
        rejected = false;
        try { store.save(invalid); }
        catch (const std::exception&) { rejected = true; }
        require(rejected, "invalid P-256 point was accepted");
        require(encryptedBytes(store.path()) == originalBytes, "invalid key changed original bytes");
        store.save(replacement);
        const auto replaced = store.load();
        require(replaced && replaced->publicKey == replacement.publicKey &&
            replaced->accountSid == expectedRecord.accountSid, "replacement was not committed");
        const auto parent = std::filesystem::path(store.path()).parent_path();
        const auto prefix = std::filesystem::path(store.path()).filename().wstring() + L".pending-";
        for (const auto& entry : std::filesystem::directory_iterator(parent))
            require(!entry.path().filename().wstring().starts_with(prefix), "temporary enrollment file was not removed");
        store.remove();
        std::cout << "EnrollmentStore tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "EnrollmentStore tests failed: " << error.what() << "\n";
        return 1;
    }
}
