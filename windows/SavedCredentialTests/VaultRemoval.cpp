#include "../SavedCredential/SavedCredentialVault.h"
#include "../ProductIdentity.h"
#include <sddl.h>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
template<class Work> void rejects(Work work, const char* message) {
    bool rejected = false;
    try { work(); } catch (...) { rejected = true; }
    require(rejected, message);
}
void ciphertext(const std::filesystem::path& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    winrt::check_bool(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;FA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    const auto raw = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW, 0, nullptr);
    LocalFree(descriptor);
    require(raw != INVALID_HANDLE_VALUE, "Cannot create isolated ciphertext fixture");
    winrt::handle file(raw);
}
}

// Explicit SYSTEM-only mode; the process-local ProgramData override isolates all deletion.
int runVaultRemovalTests() {
    using unlock_windows::saved_credential::Vault;
    std::filesystem::path fixture;
    std::wstring original;
    bool overridden = false;
    bool created = false;
    int result = 0;
    try {
        winrt::handle token;
        winrt::check_bool(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.put()));
        DWORD size = 0;
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
        std::vector<BYTE> user(size);
        winrt::check_bool(GetTokenInformation(token.get(), TokenUser, user.data(), size, &size));
        require(IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, WinLocalSystemSid),
            "Vault removal tests require explicit LocalSystem authorization");
        std::array<wchar_t, 32768> buffer{};
        const auto length = GetEnvironmentVariableW(L"ProgramData", buffer.data(), static_cast<DWORD>(buffer.size()));
        require(length && length < buffer.size(), "Cannot preserve ProgramData");
        original.assign(buffer.data(), length);
        const auto temporary = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
        require(temporary && temporary < buffer.size(), "Cannot locate test temporary directory");
        fixture = std::filesystem::path(buffer.data()) /
            (L"UnlockVaultRemoval-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        winrt::check_bool(CreateDirectoryW(fixture.c_str(), nullptr));
        created = true;
        winrt::check_bool(SetEnvironmentVariableW(L"ProgramData", fixture.c_str()));
        overridden = true;
        const auto root = fixture / unlock::components::kProductDataDirectoryName;
        const auto directory = root / unlock_windows::saved_credential::kVaultDirectoryName;
        const auto file = directory / L"credential.dat";
        const auto pending = directory / L"temporary-0123456789abcdef0123456789abcdef.dat";

        Vault::clearStored();
        require(!std::filesystem::exists(root), "Missing-data cleanup must not create storage");
        Vault vault;
        ciphertext(file); ciphertext(pending);
        ciphertext(directory / L"unknown.dat");
        rejects([&] { Vault::clearStored(); }, "Unknown files must block vault removal");
        require(std::filesystem::exists(file) && std::filesystem::exists(pending),
            "Unknown-file preflight must preserve known ciphertext");
        require(std::filesystem::remove(directory / L"unknown.dat"), "Cannot remove unknown-file fixture");
        {
            winrt::handle locked(CreateFileW(pending.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, 0, nullptr));
            require(locked.get() != INVALID_HANDLE_VALUE, "Cannot lock pending ciphertext");
            rejects([&] { Vault::clearStored(); }, "Locked ciphertext must fail removal");
            require(std::filesystem::exists(pending), "Failed removal must leave locked ciphertext present");
        }
        Vault::clearStored();
        Vault::clearStored();
        require(!std::filesystem::exists(directory), "Uninstall must remove the empty vault directory");
        Vault empty;
        const auto target = root / L"outside-vault";
        require(std::filesystem::create_directory(target), "Cannot create reparse fixture target");
        ciphertext(target / L"sentinel.dat");
        std::filesystem::create_symlink(target / L"sentinel.dat", file);
        bool rejectedReparse = false;
        try { Vault::clearStored(); }
        catch (const std::runtime_error& error) {
            if (std::string_view(error.what()) != "saved credential vault file path is unsafe") throw;
            rejectedReparse = true;
        }
        require(rejectedReparse, "A recognized ciphertext filename must reject a reparse point");
        require(std::filesystem::exists(target / L"sentinel.dat"), "Cleanup must not follow reparse points");
        require(std::filesystem::remove(file), "Cannot remove reparse fixture");
        Vault::clearStored();
        std::filesystem::create_directory_symlink(target, directory);
        rejects([&] { Vault::clearStored(); }, "A reparse vault directory must block removal");
        require(std::filesystem::exists(target / L"sentinel.dat"), "Cleanup must not follow the vault directory");
        require(std::filesystem::remove(directory), "Cannot remove vault-directory link");
        std::cout << "Isolated vault removal tests passed.\n";
    } catch (...) {
        std::cerr << winrt::to_string(winrt::to_message()) << '\n';
        result = 1;
    }
    if (overridden && !SetEnvironmentVariableW(L"ProgramData", original.c_str())) {
        std::cerr << "Cannot restore test ProgramData (Win32=" << GetLastError() << ").\n";
        result = 1;
    }
    if (created) {
        std::error_code error;
        std::filesystem::remove_all(fixture, error);
        if (error) { std::cerr << "Test cleanup failed: " << error.message() << '\n'; result = 1; }
    }
    return result;
}
