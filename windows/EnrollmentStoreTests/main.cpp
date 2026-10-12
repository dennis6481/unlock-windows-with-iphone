// Created by Rui MA on 26 Sep 2026

#include "../Enrollment/EnrollmentStore.h"
#include "../Enrollment/EnrollmentSession.h"
#include "../ProtectedStorage.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class Action> void rejects(Action action, const char* message) {
    bool rejected = false;
    try { action(); } catch (...) { rejected = true; }
    require(rejected, message);
}
}

int main() {
    namespace ble = unlock_windows::system_ble;
    namespace storage = unlock_windows::storage;
    std::filesystem::path directory;
    try {
        require(unlock_windows::enrollment::elevatedAdmin(), "Run protected storage tests with explicit administrator authorization");
        wchar_t temporary[MAX_PATH]{};
        require(GetTempPathW(MAX_PATH, temporary) != 0, "Cannot locate temporary directory");
        directory = std::filesystem::path(temporary) / (L"unlock-binding-tests-" + std::to_wstring(GetCurrentProcessId()));
        storage::ensureProtectedDirectory(directory, true);
        const auto path = directory / L"enrollment.dat";
        ble::EnrollmentStore store(path.wstring());
        require(!store.load(), "Absent binding must remain absent");
        const ble::BindingRecord first{ble::EnrollmentStore::currentUserSid(), L"classic-one", L"ble-one",
            winrt::guid{L"01234567-89ab-cdef-0123-456789abcdef"}, L"Same display name", ble::kDefaultThreshold};
        store.save(first);
        require(store.load() == std::optional<ble::BindingRecord>{first}, "Encrypted binding must round trip");
        storage::verifyProtectedPath(path, false);
        auto second = first; second.bleId = L"ble-two";
        rejects([&] { store.save(second, [] { throw std::runtime_error("Cancelled before atomic commit"); }); },
            "Cancellation must abort the pending commit");
        require(store.load() == std::optional<ble::BindingRecord>{first}, "Cancelled replacement changed the original");
        require(std::distance(std::filesystem::directory_iterator(directory), std::filesystem::directory_iterator{}) == 1,
            "Failed commit left a temporary binding behind");
        rejects([&] { store.save(second, [] { throw winrt::hresult_error(E_ABORT); }); },
            "WinRT cancellation must abort the pending commit");
        require(store.load() == std::optional<ble::BindingRecord>{first} &&
            std::distance(std::filesystem::directory_iterator(directory), std::filesystem::directory_iterator{}) == 1,
            "WinRT cancellation changed the binding or left a pending file");
        auto invalid = first; invalid.threshold = ble::kMaximumThreshold + 1;
        rejects([&] { store.save(invalid); }, "Invalid threshold must not commit");
        require(store.load() == std::optional<ble::BindingRecord>{first}, "Rejected threshold changed the original");
        auto changedThreshold = first; changedThreshold.threshold = -55;
        store.save(changedThreshold);
        require(store.load() == std::optional<ble::BindingRecord>{changedThreshold},
            "Threshold changes must preserve legacy fields");
        second.classicId.clear(); second.containerId = {};
        second.threshold = -55; store.save(second);
        require(store.load() == std::optional<ble::BindingRecord>{second}, "Successful replacement must be atomic");
        {
            winrt::handle locked(CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr));
            require(locked.get() != INVALID_HANDLE_VALUE, "Cannot create exclusive-read fixture");
            rejects([&] { static_cast<void>(store.load()); }, "Read failures must be errors, not absent bindings");
        }
        {
            struct Descriptor final { PSECURITY_DESCRIPTOR value = nullptr; ~Descriptor() { LocalFree(value); } } original, unsafe;
            PACL originalAcl = nullptr;
            require(GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION, nullptr, nullptr, &originalAcl, nullptr, &original.value) == ERROR_SUCCESS,
                "Cannot read original fixture ACL");
            winrt::check_bool(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)", SDDL_REVISION_1, &unsafe.value, nullptr));
            BOOL present = FALSE, defaulted = FALSE;
            PACL unsafeAcl = nullptr;
            winrt::check_bool(GetSecurityDescriptorDacl(unsafe.value, &present, &unsafeAcl, &defaulted));
            require(present && unsafeAcl, "Unsafe ACL fixture must contain a DACL");
            require(SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, unsafeAcl, nullptr) == ERROR_SUCCESS,
                "Cannot apply unsafe fixture ACL");
            rejects([&] { static_cast<void>(store.load()); }, "Unsafe ACLs must be errors, not absent bindings");
            require(SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, originalAcl, nullptr) == ERROR_SUCCESS,
                "Cannot restore original fixture ACL");
        }
        std::vector<unsigned char> unsupported;
        {
            std::ifstream file(path, std::ios::binary);
            require(static_cast<bool>(file), "Cannot read current-format fixture");
            unsupported.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>{});
            require(!file.bad() && unsupported.size() > 8, "Current-format fixture must contain encrypted data");
        }
        unsupported[4] ^= 0x80;
        store.remove(); require(!store.load(), "Product removal must remove only the stored binding");
        {
            std::ofstream file(path, std::ios::binary);
            file.write(reinterpret_cast<const char*>(unsupported.data()), static_cast<std::streamsize>(unsupported.size()));
            require(static_cast<bool>(file), "Cannot write unsupported-format fixture");
        }
        rejects([&] { static_cast<void>(store.load()); }, "Unknown formats must be errors, not absent bindings");
        {
            std::ifstream file(path, std::ios::binary);
            const std::vector<unsigned char> unchanged{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>{}};
            require(!file.bad() && unchanged == unsupported, "Rejected formats must not migrate or overwrite the file");
        }
        {
            std::ofstream file(path, std::ios::binary | std::ios::trunc); file << "corrupted";
            require(static_cast<bool>(file), "Cannot write corrupt fixture");
        }
        rejects([&] { static_cast<void>(store.load()); }, "Corrupt storage must be an error, not unregistered");
        store.remove();
        require(std::filesystem::remove(directory), "Test directory cleanup failed"); directory.clear();
        std::cout << "Binding storage tests passed\n";
        return 0;
    } catch (...) {
        std::cerr << winrt::to_string(winrt::to_message()) << '\n';
        if (!directory.empty()) {
            std::error_code cleanup;
            std::filesystem::remove_all(directory, cleanup);
            if (cleanup) std::cerr << "Test cleanup failed: " << cleanup.message() << '\n';
        }
        return 1;
    }
}
