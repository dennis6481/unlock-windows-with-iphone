// Created by Rui MA on 30 Sep 2026

#include "SavedCredentialIpc.h"

#include <sddl.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <limits>
#include <utility>

namespace unlock_windows::saved_credential {
namespace {

constexpr std::uint32_t kMagic = 0x31434347;
constexpr std::uint16_t kVersion = 1;
constexpr std::uint32_t kAckMagic = 0x314b4341;

#pragma pack(push, 1)
struct Header final {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t operation;
    std::uint32_t result;
    std::uint32_t size;
};
struct ReplyAcknowledgment final {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t operation;
};
#pragma pack(pop)
static_assert(sizeof(Header) == 16);
static_assert(sizeof(ReplyAcknowledgment) == 8);

void append(SensitiveBytes& target, const void* source, const std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(source);
    target.value.insert(target.value.end(), bytes, bytes + size);
}

bool take(const std::uint8_t*& cursor, std::size_t& left, void* target, const std::size_t size) {
    if (size > left) return false;
    std::memcpy(target, cursor, size);
    cursor += size;
    left -= size;
    return true;
}

bool readExact(const HANDLE pipe, void* output, const DWORD size) {
    auto* cursor = static_cast<std::uint8_t*>(output);
    DWORD total = 0;
    while (total < size) {
        DWORD read = 0;
        if (!ReadFile(pipe, cursor + total, size - total, &read, nullptr)) return false;
        if (read == 0) {
            SetLastError(ERROR_BROKEN_PIPE);
            return false;
        }
        total += read;
    }
    return true;
}

bool writeExact(const HANDLE pipe, const void* input, const DWORD size) {
    const auto* cursor = static_cast<const std::uint8_t*>(input);
    DWORD total = 0;
    while (total < size) {
        DWORD written = 0;
        if (!WriteFile(pipe, cursor + total, size - total, &written, nullptr)) return false;
        if (written == 0) {
            SetLastError(ERROR_BROKEN_PIPE);
            return false;
        }
        total += written;
    }
    return true;
}

bool transferExactWithTimeout(const HANDLE pipe, void* buffer, const DWORD size,
                              const bool write, const DWORD waitMs) {
    auto* cursor = static_cast<std::uint8_t*>(buffer);
    DWORD total = 0;
    while (total < size) {
        const HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (event == nullptr) return false;
        OVERLAPPED pending{};
        pending.hEvent = event;
        DWORD transferred = 0;
        const BOOL started = write
            ? WriteFile(pipe, cursor + total, size - total, &transferred, &pending)
            : ReadFile(pipe, cursor + total, size - total, &transferred, &pending);
        if (!started && GetLastError() == ERROR_IO_PENDING) {
            const DWORD wait = WaitForSingleObject(event, waitMs);
            if (wait != WAIT_OBJECT_0) {
                const DWORD error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
                CancelIoEx(pipe, &pending);
                DWORD ignored = 0;
                GetOverlappedResult(pipe, &pending, &ignored, TRUE);
                CloseHandle(event);
                SetLastError(error);
                return false;
            }
            if (!GetOverlappedResult(pipe, &pending, &transferred, FALSE)) {
                const DWORD error = GetLastError();
                CloseHandle(event);
                SetLastError(error);
                return false;
            }
        } else if (!started) {
            const DWORD error = GetLastError();
            CloseHandle(event);
            SetLastError(error);
            return false;
        }
        CloseHandle(event);
        if (transferred == 0) {
            SetLastError(ERROR_BROKEN_PIPE);
            return false;
        }
        total += transferred;
    }
    return true;
}

bool writePacketWithTimeout(const HANDLE pipe, const Packet& packet, const DWORD waitMs) {
    if (packet.payload.value.size() > kMaxPacket) return false;
    Header header{kMagic, kVersion, static_cast<std::uint16_t>(packet.operation),
        static_cast<std::uint32_t>(packet.result), static_cast<std::uint32_t>(packet.payload.value.size())};
    return transferExactWithTimeout(pipe, &header, sizeof(header), true, waitMs) &&
        (header.size == 0 || transferExactWithTimeout(pipe,
            const_cast<std::uint8_t*>(packet.payload.value.data()), header.size, true, waitMs));
}

bool readPacketWithTimeout(const HANDLE pipe, Packet& packet, const DWORD waitMs) {
    Header header{};
    if (!transferExactWithTimeout(pipe, &header, sizeof(header), false, waitMs)) return false;
    if (header.magic != kMagic || header.version != kVersion || header.size > kMaxPacket ||
        header.operation < static_cast<std::uint16_t>(Operation::captureIdentity) ||
        header.operation > static_cast<std::uint16_t>(Operation::clearForRemoval)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    packet.payload.clear();
    packet.payload.value.resize(header.size);
    if (header.size != 0 && !transferExactWithTimeout(pipe,
            packet.payload.value.data(), header.size, false, waitMs)) return false;
    packet.operation = static_cast<Operation>(header.operation);
    packet.result = static_cast<Result>(header.result);
    return true;
}

bool isExpectedServer(const HANDLE pipe) {
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid)) return false;
    const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return false;
    wchar_t image[MAX_PATH]{};
    DWORD imageSize = MAX_PATH;
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT systemSize = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    DWORD session = 0xffffffff;
    const bool pathValid = QueryFullProcessImageNameW(process, 0, image, &imageSize) &&
        systemSize > 0 && systemSize < MAX_PATH &&
        _wcsicmp(image, (std::wstring(systemDirectory) + L"\\" + kServiceExeName).c_str()) == 0 &&
        ProcessIdToSessionId(pid, &session) && session == 0;
    HANDLE token = nullptr;
    const bool tokenOpened = pathValid && OpenProcessToken(process, TOKEN_QUERY, &token);
    bool systemUser = false;
    if (tokenOpened) {
        DWORD bytes = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
        std::vector<std::uint8_t> buffer(bytes);
        PSID systemSid = nullptr;
        if (bytes >= sizeof(TOKEN_USER) &&
            GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes) &&
            ConvertStringSidToSidW(L"S-1-5-18", &systemSid)) {
            systemUser = EqualSid(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, systemSid);
        }
        if (systemSid != nullptr) LocalFree(systemSid);
        CloseHandle(token);
    }
    CloseHandle(process);
    return systemUser;
}

} // namespace

SensitiveBytes& SensitiveBytes::operator=(SensitiveBytes&& other) noexcept {
    if (this != &other) {
        clear();
        value = std::move(other.value);
    }
    return *this;
}

SensitiveBytes::~SensitiveBytes() { clear(); }

void SensitiveBytes::clear() noexcept {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}

bool encodeIdentity(const Identity& identity, SensitiveBytes& output) {
    if (identity.sid.empty() || identity.qualifiedUserName.empty() ||
        identity.sid.size() > 256 || identity.qualifiedUserName.size() > 1024 ||
        identity.sid.size() > std::numeric_limits<std::uint16_t>::max() ||
        identity.qualifiedUserName.size() > std::numeric_limits<std::uint16_t>::max()) return false;
    const auto sidLength = static_cast<std::uint16_t>(identity.sid.size());
    const auto nameLength = static_cast<std::uint16_t>(identity.qualifiedUserName.size());
    output.clear();
    append(output, &sidLength, sizeof(sidLength));
    append(output, &nameLength, sizeof(nameLength));
    append(output, &identity.providerId, sizeof(GUID));
    append(output, identity.sid.data(), sidLength * sizeof(wchar_t));
    append(output, identity.qualifiedUserName.data(), nameLength * sizeof(wchar_t));
    return true;
}

bool decodeIdentity(const std::uint8_t* data, const std::size_t size, Identity& output) {
    if (data == nullptr || size < 4 + sizeof(GUID)) return false;
    const auto* cursor = data;
    auto left = size;
    std::uint16_t sidLength = 0;
    std::uint16_t nameLength = 0;
    GUID provider{};
    if (!take(cursor, left, &sidLength, sizeof(sidLength)) ||
        !take(cursor, left, &nameLength, sizeof(nameLength)) ||
        !take(cursor, left, &provider, sizeof(provider)) ||
        sidLength == 0 || nameLength == 0 || sidLength > 256 || nameLength > 1024 ||
        left != (static_cast<std::size_t>(sidLength) + nameLength) * sizeof(wchar_t)) return false;
    std::wstring sid(sidLength, L'\0');
    std::memcpy(sid.data(), cursor, sidLength * sizeof(wchar_t));
    cursor += sidLength * sizeof(wchar_t);
    std::wstring name(nameLength, L'\0');
    std::memcpy(name.data(), cursor, nameLength * sizeof(wchar_t));
    if (sid.find(L'\0') != std::wstring::npos || name.find(L'\0') != std::wstring::npos) return false;
    output = {std::move(sid), std::move(name), provider};
    return true;
}

bool encodeStatus(const StatusPayload& status, SensitiveBytes& output) {
    SensitiveBytes identity;
    if (!encodeIdentity(status.identity, identity)) return false;
    output.clear();
    append(output, status.snapshotNonce.data(), status.snapshotNonce.size());
    const std::uint8_t present = status.credentialPresent ? 1 : 0;
    append(output, &present, 1);
    append(output, identity.value.data(), identity.value.size());
    return true;
}

bool decodeStatus(const std::uint8_t* data, const std::size_t size, StatusPayload& output) {
    if (data == nullptr || size < kNonceSize + 1) return false;
    std::copy_n(data, kNonceSize, output.snapshotNonce.begin());
    if (data[kNonceSize] > 1) return false;
    output.credentialPresent = data[kNonceSize] == 1;
    return decodeIdentity(data + kNonceSize + 1, size - kNonceSize - 1, output.identity);
}

bool writePacket(const HANDLE pipe, const Packet& packet) {
    if (packet.payload.value.size() > kMaxPacket) return false;
    const Header header{kMagic, kVersion, static_cast<std::uint16_t>(packet.operation),
        static_cast<std::uint32_t>(packet.result), static_cast<std::uint32_t>(packet.payload.value.size())};
    return writeExact(pipe, &header, sizeof(header)) &&
        (header.size == 0 || writeExact(pipe, packet.payload.value.data(), header.size));
}

bool readPacket(const HANDLE pipe, Packet& packet) {
    Header header{};
    if (!readExact(pipe, &header, sizeof(header)) || header.magic != kMagic ||
        header.version != kVersion || header.size > kMaxPacket ||
        header.operation < static_cast<std::uint16_t>(Operation::captureIdentity) ||
        header.operation > static_cast<std::uint16_t>(Operation::clearForRemoval)) return false;
    packet.payload.clear();
    packet.payload.value.resize(header.size);
    if (header.size != 0 && !readExact(pipe, packet.payload.value.data(), header.size)) return false;
    packet.operation = static_cast<Operation>(header.operation);
    packet.result = static_cast<Result>(header.result);
    return true;
}

bool awaitReplyAcknowledgment(const HANDLE pipe, const Operation operation, const DWORD waitMs) {
    const ULONGLONG deadline = GetTickCount64() + waitMs;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) return false;
        if (available >= sizeof(ReplyAcknowledgment)) {
            ReplyAcknowledgment acknowledgment{};
            if (!readExact(pipe, &acknowledgment, sizeof(acknowledgment))) return false;
            if (acknowledgment.magic != kAckMagic || acknowledgment.version != kVersion ||
                acknowledgment.operation != static_cast<std::uint16_t>(operation)) {
                SetLastError(ERROR_INVALID_DATA);
                return false;
            }
            return true;
        }
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) {
            SetLastError(ERROR_TIMEOUT);
            return false;
        }
        Sleep(static_cast<DWORD>(std::min<ULONGLONG>(10, deadline - now)));
    }
}

const wchar_t* callStageName(const CallStage stage) {
    switch (stage) {
    case CallStage::none: return L"none";
    case CallStage::requestValidation: return L"request-validation";
    case CallStage::waitForPipe: return L"wait-for-pipe";
    case CallStage::openPipe: return L"open-pipe";
    case CallStage::serverVerification: return L"server-verification";
    case CallStage::requestWrite: return L"request-write";
    case CallStage::replyRead: return L"reply-read";
    case CallStage::replyValidation: return L"reply-validation";
    case CallStage::replyAcknowledgment: return L"reply-acknowledgment";
    }
    return L"unknown";
}

bool call(const Operation operation, SensitiveBytes&& request, Packet& reply, const DWORD waitMs,
          CallDiagnostics* const diagnostics) {
    if (diagnostics != nullptr) *diagnostics = {};
    const auto failed = [diagnostics](const CallStage stage, const DWORD error) {
        if (diagnostics != nullptr) *diagnostics = {stage, error};
        SetLastError(error);
        return false;
    };
    if (request.value.size() > kMaxPacket) {
        return failed(CallStage::requestValidation, ERROR_INVALID_PARAMETER);
    }
    const ULONGLONG deadline = GetTickCount64() + waitMs;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        const DWORD remaining = now < deadline ? static_cast<DWORD>(deadline - now) : 0;
        if (!WaitNamedPipeW(kPipeName, remaining)) {
            return failed(CallStage::waitForPipe, GetLastError());
        }
        pipe = CreateFileW(kPipeName, 0x0012019B, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY || GetTickCount64() >= deadline) {
            return failed(CallStage::openPipe, error);
        }
    }
    if (!isExpectedServer(pipe)) {
        CloseHandle(pipe);
        return failed(CallStage::serverVerification, ERROR_ACCESS_DENIED);
    }
    Packet outbound;
    outbound.operation = operation;
    outbound.payload = std::move(request);
    CallStage failureStage = CallStage::none;
    DWORD failureError = NO_ERROR;
    if (!writePacketWithTimeout(pipe, outbound, waitMs)) {
        failureStage = CallStage::requestWrite;
        failureError = GetLastError();
    } else if (!readPacketWithTimeout(pipe, reply, waitMs)) {
        failureStage = CallStage::replyRead;
        failureError = GetLastError();
    } else if (reply.operation != operation) {
        failureStage = CallStage::replyValidation;
        failureError = ERROR_INVALID_DATA;
    } else {
        ReplyAcknowledgment acknowledgment{kAckMagic, kVersion,
            static_cast<std::uint16_t>(operation)};
        if (!transferExactWithTimeout(pipe, &acknowledgment,
                sizeof(acknowledgment), true, waitMs)) {
            const DWORD error = GetLastError();
            if (diagnostics != nullptr) {
                *diagnostics = {CallStage::replyAcknowledgment, error};
            }
            const std::wstring message = L"saved credential reply acknowledgment failed; win32=" +
                std::to_wstring(error);
            OutputDebugStringW(message.c_str());
        }
    }
    CloseHandle(pipe);
    if (failureStage != CallStage::none) {
        reply.payload.clear();
        return failed(failureStage, failureError);
    }
    return true;
}

} // namespace unlock_windows::saved_credential
