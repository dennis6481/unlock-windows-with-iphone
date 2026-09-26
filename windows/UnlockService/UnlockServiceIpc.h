// Created by Rui MA on 26 Sep 2026

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace unlock_windows::service::ipc {

inline constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\unlock-windows-with-iphone-v1";
inline constexpr std::uint32_t kMaxPayloadSize = 64 * 1024;

enum class Operation : std::uint16_t {
    issueChallenge = 1,
    verifyAssertion = 2,
};

enum class Status : std::uint32_t {
    success = 0,
    invalidRequest = 1,
    serviceRejected = 2,
    unavailable = 3,
};

struct Response final {
    Status status = Status::unavailable;
    std::string payload;
};

// Opens one authenticated local IPC exchange. The server accepts a pipe
// connection only when the client process belongs to the same Windows user.
[[nodiscard]] Response call(Operation operation, std::string_view payload);

class Server final {
public:
    Server() = default;
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    ~Server();

    [[nodiscard]] bool waitForRequest(Operation& operation, std::string& payload);
    [[nodiscard]] bool respond(Status status, std::string_view payload);

private:
    void closePipe() noexcept;

    void* pipe_ = nullptr;
    Operation operation_ = Operation::issueChallenge;
};

} // namespace unlock_windows::service::ipc
