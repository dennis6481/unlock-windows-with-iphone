// Created by Rui MA on 04 Oct 2026

#pragma once

#include "WindowsAdapter.h"
#include "../PhoneApproval/EnrollmentStore.h"
#include <Windows.h>
#include <shlobj.h>

namespace unlock::components {
[[nodiscard]] inline std::filesystem::path setupKnownFolder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    const HRESULT result = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &raw);
    if (FAILED(result)) throw ComponentError(L"Cannot resolve installation folder (HRESULT=" +
        std::to_wstring(static_cast<unsigned long>(result)) + L").");
    const std::filesystem::path path(raw);
    CoTaskMemFree(raw);
    return path;
}
[[nodiscard]] inline std::filesystem::path desktopDirectory() {
    return setupKnownFolder(FOLDERID_ProgramFiles) / kDesktopDirectoryName;
}
[[nodiscard]] inline std::filesystem::path productDataDirectory() {
    return setupKnownFolder(FOLDERID_ProgramData) / unlock_windows::phone_approval::kEnrollmentDataDirectoryName;
}
[[nodiscard]] inline std::filesystem::path transactionRoot() {
    return productDataDirectory() / kSetupDirectoryName / kTransactionsDirectoryName;
}
}
