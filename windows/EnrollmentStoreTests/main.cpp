// Created by Rui MA on 26 Sep 2026

#include "EnrollmentStore.h"

#include <Windows.h>

#include <cstdint>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

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

} // namespace

int main() {
    try {
        std::vector<std::uint8_t> expected(65);
        expected[0] = 0x04;
        for (std::size_t index = 1; index < expected.size(); ++index) {
            expected[index] = static_cast<std::uint8_t>(index);
        }

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
        store.remove();
        std::cout << "EnrollmentStore tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "EnrollmentStore tests failed: " << error.what() << "\n";
        return 1;
    }
}
