// Created by Rui MA on 26 Sep 2026

#include "UnlockServiceIpc.h"

#include <Windows.h>
#include <sddl.h>

#include <cstring>
#include <string>
#include <vector>

namespace unlock_windows::service::ipc {
namespace {

constexpr std::uint32_t kMagic = 0x31504955; // "UIP1" in little-endian memory
constexpr std::uint16_t kVersion = 1;

#pragma pack(push, 1)
struct MessageHeader final {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t operation;
    std::uint32_t status;
    std::uint32_t payloadSize;
};
#pragma pack(pop)

static_assert(sizeof(MessageHeader) == 16);

[[nodiscard]] HANDLE asHandle(void* value) noexcept {
    return static_cast<HANDLE>(value);
}

void closeHandle(HANDLE handle) noexcept {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
}

[[nodiscard]] bool writeMessage(
    const HANDLE pipe,
    const Operation operation,
    const Status status,
    const std::string_view payload
) {
    if (payload.size() > kMaxPayloadSize) {
        return false;
    }

    MessageHeader header{
        kMagic,
        kVersion,
        static_cast<std::uint16_t>(operation),
        static_cast<std::uint32_t>(status),
        static_cast<std::uint32_t>(payload.size()),
    };
    std::vector<std::uint8_t> message(sizeof(header) + payload.size());
    std::memcpy(message.data(), &header, sizeof(header));
    if (!payload.empty()) {
        std::memcpy(message.data() + sizeof(header), payload.data(), payload.size());
    }

    DWORD written = 0;
    return WriteFile(
        pipe,
        message.data(),
        static_cast<DWORD>(message.size()),
        &written,
        nullptr
    ) != FALSE && written == message.size();
}

[[nodiscard]] bool readMessage(
    const HANDLE pipe,
    MessageHeader& header,
    std::string& payload
) {
    std::vector<std::uint8_t> message(kMaxPayloadSize + sizeof(MessageHeader));
    std::size_t received = 0;

    for (;;) {
        DWORD read = 0;
        const auto remaining = message.size() - received;
        if (ReadFile(
                pipe,
                message.data() + received,
                static_cast<DWORD>(remaining),
                &read,
                nullptr
        ) == FALSE) {
            if (GetLastError() != ERROR_MORE_DATA) {
                return false;
            }
        }
        if (read == 0) {
            return false;
        }
        received += read;
        if (received < sizeof(MessageHeader)) {
            continue;
        }

        std::memcpy(&header, message.data(), sizeof(header));
        if (header.magic != kMagic || header.version != kVersion ||
            header.payloadSize > kMaxPayloadSize ||
            received >= sizeof(MessageHeader) + header.payloadSize) {
            break;
        }
    }

    if (header.magic != kMagic || header.version != kVersion ||
        header.payloadSize > kMaxPayloadSize ||
        received != sizeof(MessageHeader) + header.payloadSize) {
        return false;
    }

    payload.assign(
        reinterpret_cast<const char*>(message.data() + sizeof(MessageHeader)),
        header.payloadSize
    );
    return true;
}

[[nodiscard]] SECURITY_ATTRIBUTES makeSecurityAttributes(PSECURITY_DESCRIPTOR& descriptor) {
    // The server performs an exact-user token check after connection. The
    // broad local handle ACL is required on this development machine because
    // its hosted process token does not match SDDL aliases consistently.
    // Production must use the exact GattHost package/service identity.
    constexpr LPCWSTR kSddl = L"D:P(A;;GA;;;WD)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kSddl,
            SDDL_REVISION_1,
            &descriptor,
            nullptr
        )) {
        return SECURITY_ATTRIBUTES{};
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    return attributes;
}

[[nodiscard]] bool isSameUserClient(const HANDLE pipe) {
    ULONG clientProcessId = 0;
    if (!GetNamedPipeClientProcessId(pipe, &clientProcessId)) {
        return false;
    }

    const auto clientProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        clientProcessId
    );
    if (clientProcess == nullptr) {
        return false;
    }

    HANDLE clientToken = nullptr;
    HANDLE serverToken = nullptr;
    const bool openedTokens =
        OpenProcessToken(clientProcess, TOKEN_QUERY, &clientToken) != FALSE &&
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &serverToken) != FALSE;
    if (!openedTokens) {
        closeHandle(clientToken);
        closeHandle(serverToken);
        CloseHandle(clientProcess);
        return false;
    }

    DWORD clientUserSize = 0;
    DWORD serverUserSize = 0;
    GetTokenInformation(clientToken, TokenUser, nullptr, 0, &clientUserSize);
    GetTokenInformation(serverToken, TokenUser, nullptr, 0, &serverUserSize);
    if (clientUserSize == 0 || serverUserSize == 0) {
        closeHandle(clientToken);
        closeHandle(serverToken);
        CloseHandle(clientProcess);
        return false;
    }

    std::vector<std::uint8_t> clientUserBuffer(clientUserSize);
    std::vector<std::uint8_t> serverUserBuffer(serverUserSize);
    const bool readTokens =
        GetTokenInformation(
            clientToken,
            TokenUser,
            clientUserBuffer.data(),
            clientUserSize,
            &clientUserSize
        ) != FALSE &&
        GetTokenInformation(
            serverToken,
            TokenUser,
            serverUserBuffer.data(),
            serverUserSize,
            &serverUserSize
        ) != FALSE;

    bool sameUser = false;
    if (readTokens) {
        const auto clientUser = reinterpret_cast<const TOKEN_USER*>(clientUserBuffer.data());
        const auto serverUser = reinterpret_cast<const TOKEN_USER*>(serverUserBuffer.data());
        sameUser = EqualSid(clientUser->User.Sid, serverUser->User.Sid) != FALSE;
    }

    closeHandle(clientToken);
    closeHandle(serverToken);
    CloseHandle(clientProcess);
    return sameUser;
}

} // namespace

Response call(const Operation operation, const std::string_view payload) {
    if (payload.size() > kMaxPayloadSize) {
        return {Status::invalidRequest, "IPC payload is too large"};
    }

    if (!WaitNamedPipeW(kPipeName, 5'000)) {
        return {Status::unavailable, "UnlockService pipe is unavailable"};
    }

    const auto pipe = CreateFileW(
        kPipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );
    if (pipe == INVALID_HANDLE_VALUE) {
        return {Status::unavailable, "UnlockService pipe could not be opened"};
    }

    const auto close = [&]() noexcept { closeHandle(pipe); };
    if (!writeMessage(pipe, operation, Status::success, payload)) {
        close();
        return {Status::unavailable, "UnlockService request write failed"};
    }

    MessageHeader header{};
    std::string responsePayload;
    if (!readMessage(pipe, header, responsePayload)) {
        close();
        return {Status::unavailable, "UnlockService response read failed"};
    }
    close();

    if (header.operation != static_cast<std::uint16_t>(operation)) {
        return {Status::invalidRequest, "UnlockService response operation mismatch"};
    }
    return {
        static_cast<Status>(header.status),
        std::move(responsePayload),
    };
}

Server::~Server() {
    closePipe();
}

bool Server::waitForRequest(Operation& operation, std::string& payload) {
    closePipe();

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto attributes = makeSecurityAttributes(descriptor);
    if (attributes.lpSecurityDescriptor == nullptr) {
        return false;
    }

    const auto pipe = CreateNamedPipeW(
        kPipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        kMaxPayloadSize + sizeof(MessageHeader),
        kMaxPayloadSize + sizeof(MessageHeader),
        0,
        &attributes
    );
    LocalFree(descriptor);
    if (pipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    pipe_ = pipe;

    const auto connected = ConnectNamedPipe(pipe, nullptr) != FALSE ||
        GetLastError() == ERROR_PIPE_CONNECTED;
    if (!connected) {
        closePipe();
        return false;
    }

    if (!isSameUserClient(pipe)) {
        closePipe();
        return false;
    }

    MessageHeader header{};
    if (!readMessage(pipe, header, payload) ||
        header.operation < static_cast<std::uint16_t>(Operation::issueChallenge) ||
        header.operation > static_cast<std::uint16_t>(Operation::verifyAssertion) ||
        header.status != static_cast<std::uint32_t>(Status::success)) {
        closePipe();
        return false;
    }
    operation = static_cast<Operation>(header.operation);
    operation_ = operation;
    return true;
}

bool Server::respond(const Status status, const std::string_view payload) {
    const auto pipe = asHandle(pipe_);
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    return writeMessage(pipe, operation_, status, payload);
}

void Server::closePipe() noexcept {
    const auto pipe = asHandle(pipe_);
    if (pipe != nullptr && pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    pipe_ = nullptr;
}

} // namespace unlock_windows::service::ipc
