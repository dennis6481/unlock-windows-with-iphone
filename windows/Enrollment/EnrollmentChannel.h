// Created by Rui MA on 02 Oct 2026

#pragma once

#include "EnrollmentSession.h"
#include <array>
#include <algorithm>
#include <string_view>
#include <vector>

namespace unlock_windows::enrollment {
inline constexpr wchar_t kChannelPrefix[] = L"\\\\.\\pipe\\UnlockWindowsWithIPhone-Pairing-";

class EnrollmentChannel final {
public:
    EnrollmentChannel(const std::wstring& name, const std::wstring& sid, DWORD parentPid = 0) {
        const std::wstring_view prefix(kChannelPrefix);
        if (!name.starts_with(prefix) || name.size() != prefix.size() + 32 ||
            std::wstring_view(name).substr(prefix.size()).find_first_not_of(L"0123456789abcdef") != std::wstring_view::npos)
            throw std::invalid_argument("Invalid pairing channel name");
        for (auto* operation : {&connect_, &read_, &write_}) {
            operation->event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            require(operation->event.value != nullptr, "CreateEventW(pairing channel)");
            operation->io.hEvent = operation->event.value;
        }
        server_ = parentPid == 0;
        if (server_) {
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            const std::wstring acl = L"D:P(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;" + sid + L")";
            require(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1,
                &descriptor, nullptr), "Pairing channel ACL");
            SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
            pipe_.value = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 128, 128, 0, &attributes);
            const DWORD error = GetLastError();
            LocalFree(descriptor);
            if (pipe_.value == INVALID_HANDLE_VALUE) { SetLastError(error); require(FALSE, "CreateNamedPipeW(pairing)"); }
            if (ConnectNamedPipe(pipe_.value, &connect_.io)) connected_ = true;
            else {
                const DWORD connectError = GetLastError();
                if (connectError == ERROR_PIPE_CONNECTED) connected_ = true;
                else if (connectError == ERROR_IO_PENDING) connect_.pending = true;
                else { SetLastError(connectError); require(FALSE, "ConnectNamedPipe(pairing)"); }
            }
        } else {
            pipe_.value = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED, nullptr);
            require(pipe_.value != INVALID_HANDLE_VALUE, "CreateFileW(pairing channel)");
            ULONG actualPid = 0;
            require(GetNamedPipeServerProcessId(pipe_.value, &actualPid), "GetNamedPipeServerProcessId(pairing)");
            if (actualPid != parentPid) throw std::runtime_error("Pairing channel server identity mismatch");
            connected_ = true;
        }
    }
    ~EnrollmentChannel() {
        if (!pipe_.value || pipe_.value == INVALID_HANDLE_VALUE) return;
        for (auto* operation : {&connect_, &read_, &write_}) {
            if (!operation->pending) continue;
            if (!CancelIoEx(pipe_.value, &operation->io) && GetLastError() != ERROR_NOT_FOUND)
                OutputDebugStringW((L"Pairing channel CancelIoEx failed: " + std::to_wstring(GetLastError()) + L"\n").c_str());
            DWORD transferred = 0;
            if (!GetOverlappedResult(pipe_.value, &operation->io, &transferred, TRUE) && GetLastError() != ERROR_OPERATION_ABORTED)
                OutputDebugStringW((L"Pairing channel cleanup GetOverlappedResult failed: " + std::to_wstring(GetLastError()) + L"\n").c_str());
        }
    }
    void announceReady() {
        if (server_ || announced_) throw std::logic_error("Invalid pairing ready transition");
        announced_ = true;
        output_[0] = 0x7f;
        start(write_, true, output_.data(), 1);
        start(read_, false, input_.data(), static_cast<DWORD>(input_.size()));
    }
    bool ready(DWORD helperPid) {
        if (!server_ || helperPid == 0) return false;
        if (ready_) return true;
        if (!connected_) {
            if (!complete(connect_)) return false;
            connected_ = true;
        }
        if (!peerChecked_) {
            ULONG actualPid = 0;
            require(GetNamedPipeClientProcessId(pipe_.value, &actualPid), "GetNamedPipeClientProcessId(pairing)");
            if (actualPid != helperPid) throw std::runtime_error("Pairing channel client identity mismatch");
            peerChecked_ = true;
            start(read_, false, input_.data(), 1);
        }
        if (!complete(read_)) return false;
        if (input_[0] != 0x7f) throw std::runtime_error("Invalid pairing ready message");
        ready_ = true;
        return true;
    }
    void sendKey(const std::vector<std::uint8_t>& key) {
        if (!server_ || !ready_ || sent_ || key.size() != output_.size())
            throw std::logic_error("Invalid pairing candidate transition");
        std::copy(key.begin(), key.end(), output_.begin());
        sent_ = true;
        start(write_, true, output_.data(), static_cast<DWORD>(output_.size()));
    }
    void checkWrite() { if (write_.pending) complete(write_); }
    bool receiveKey(std::vector<std::uint8_t>& key) {
        if (server_ || !announced_ || received_) return false;
        checkWrite();
        if (!complete(read_)) return false;
        received_ = true;
        key.assign(input_.begin(), input_.end());
        return true;
    }
private:
    struct Operation final {
        Handle event;
        OVERLAPPED io{};
        bool pending = false;
        DWORD expected = 0;
    };
    void start(Operation& operation, bool write, BYTE* bytes, DWORD size) {
        operation.expected = size;
        DWORD transferred = 0;
        const BOOL ok = write ? WriteFile(pipe_.value, bytes, size, &transferred, &operation.io)
            : ReadFile(pipe_.value, bytes, size, &transferred, &operation.io);
        if (!ok && GetLastError() != ERROR_IO_PENDING) require(FALSE, write ? "WriteFile(pairing channel)" : "ReadFile(pairing channel)");
        operation.pending = true;
    }
    bool complete(Operation& operation) {
        if (!operation.pending) return true;
        DWORD transferred = 0;
        if (!GetOverlappedResult(pipe_.value, &operation.io, &transferred, FALSE)) {
            if (GetLastError() == ERROR_IO_INCOMPLETE) return false;
            require(FALSE, "GetOverlappedResult(pairing channel)");
        }
        operation.pending = false;
        if (transferred != operation.expected) throw std::runtime_error("Incomplete pairing channel message");
        return true;
    }
    Handle pipe_;
    Operation connect_, read_, write_;
    std::array<BYTE, 65> input_{}, output_{};
    bool server_ = false, connected_ = false, peerChecked_ = false, ready_ = false;
    bool announced_ = false, sent_ = false, received_ = false;
};
}
