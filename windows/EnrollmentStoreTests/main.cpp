// Created by Rui MA on 26 Sep 2026

#include "../Enrollment/EnrollmentStore.h"
#include "../Enrollment/EnrollmentSession.h"
#include "../ProtectedStorage.h"
#include <fstream>
#include <iostream>
#include <array>

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
        second.threshold = -55; store.save(second);
        require(store.load() == std::optional<ble::BindingRecord>{second}, "Successful replacement must be atomic");
        store.remove(); require(!store.load(), "Product removal must remove only the stored binding");
        {
            std::ofstream file(path, std::ios::binary);
            const std::array<unsigned char, 8> previous{0x45,0x4e,0x4b,0x32,1,0,1,0};
            file.write(reinterpret_cast<const char*>(previous.data()), previous.size());
            require(static_cast<bool>(file), "Cannot write old-format fixture");
        }
        bool rebind = false;
        try { store.load(); } catch (const ble::RebindRequired&) { rebind = true; }
        require(rebind && std::filesystem::file_size(path) == 8, "Old format must require explicit rebinding without migration or overwrite");
        {
            std::ofstream file(path, std::ios::binary | std::ios::trunc); file << "corrupted";
            require(static_cast<bool>(file), "Cannot write corrupt fixture");
        }
        rejects([&] { store.load(); }, "Corrupt storage must be an error, not unregistered");
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
