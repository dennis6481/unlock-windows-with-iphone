// Created by Rui MA on 30 Sep 2026

#include "../Resources/resource.h"
#include "SavedCredentialIpc.h"
#include "../ComponentFiles.h"

#include <sddl.h>
#include <winsvc.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <limits>
#include <utility>
#include <string_view>

namespace unlock_windows::saved_credential {
namespace {

constexpr std::uint32_t kMagic = 0x31434347;
constexpr std::uint16_t kVersion = kProtocolVersion;
constexpr std::uint8_t kCredentialPresentFlag = 1;
constexpr std::uint8_t kCredentialMatchesFlag = 2;
constexpr std::uint8_t kCredentialStatusFlags = kCredentialPresentFlag | kCredentialMatchesFlag;
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

bool ioAllowed(const PipeIoContext& context) {
    if (context.stopEvent) {
        const auto stopped = WaitForSingleObject(context.stopEvent, 0);
        if (stopped != WAIT_TIMEOUT) {
            if (stopped == WAIT_OBJECT_0) SetLastError(ERROR_OPERATION_ABORTED);
            return false;
        }
    }
    if (GetTickCount64() >= context.deadline) {
        SetLastError(ERROR_TIMEOUT);
        return false;
    }
    return true;
}

bool finishPipeIo(const HANDLE pipe, OVERLAPPED& pending, const BOOL started,
                  const PipeIoContext& context, DWORD& transferred) {
    if (!started) {
        if (GetLastError() != ERROR_IO_PENDING) return false;
        const auto now = GetTickCount64();
        const auto remaining = now < context.deadline ? context.deadline - now : 0;
        const DWORD timeout = context.deadline == (std::numeric_limits<std::uint64_t>::max)()
            ? INFINITE : static_cast<DWORD>((std::min<std::uint64_t>)(remaining, INFINITE - 1));
        HANDLE events[]{context.stopEvent, pending.hEvent};
        const DWORD wait = context.stopEvent
            ? WaitForMultipleObjects(2, events, FALSE, timeout)
            : WaitForSingleObject(pending.hEvent, timeout);
        const DWORD completed = context.stopEvent ? WAIT_OBJECT_0 + 1 : WAIT_OBJECT_0;
        if (wait != completed) {
            const DWORD error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT
                : wait == WAIT_OBJECT_0 ? ERROR_OPERATION_ABORTED : GetLastError();
            if (!CancelIoEx(pipe, &pending) && GetLastError() != ERROR_NOT_FOUND) {
                const auto message = L"saved credential I/O cancellation failed; win32=" + std::to_wstring(GetLastError());
                OutputDebugStringW(message.c_str());
            }
            DWORD ignored = 0;
            if (!GetOverlappedResult(pipe, &pending, &ignored, TRUE) && GetLastError() != ERROR_OPERATION_ABORTED) {
                const auto message = L"saved credential cancelled I/O completion failed; win32=" + std::to_wstring(GetLastError());
                OutputDebugStringW(message.c_str());
            }
            SetLastError(error);
            return false;
        }
    }
    if (!GetOverlappedResult(pipe, &pending, &transferred, FALSE)) return false;
    return ioAllowed(context);
}

bool transferExact(const HANDLE pipe, void* buffer, const DWORD size,
                   const bool write, const PipeIoContext& context) {
    auto* cursor = static_cast<std::uint8_t*>(buffer);
    DWORD total = 0;
    while (total < size) {
        if (!ioAllowed(context)) return false;
        const HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (event == nullptr) return false;
        OVERLAPPED pending{};
        pending.hEvent = event;
        DWORD transferred = 0;
        const BOOL started = write
            ? WriteFile(pipe, cursor + total, size - total, &transferred, &pending)
            : ReadFile(pipe, cursor + total, size - total, &transferred, &pending);
        const bool completed = finishPipeIo(pipe, pending, started, context, transferred);
        const DWORD error = completed ? NO_ERROR : GetLastError();
        CloseHandle(event);
        if (!completed) { SetLastError(error); return false; }
        if (transferred == 0) {
            SetLastError(ERROR_BROKEN_PIPE);
            return false;
        }
        total += transferred;
    }
    return true;
}

struct ScopedService final {
    SC_HANDLE value;
    explicit ScopedService(SC_HANDLE handle) : value(handle) {}
    ScopedService(const ScopedService&) = delete;
    ScopedService& operator=(const ScopedService&) = delete;
    ~ScopedService() {
        const DWORD error = GetLastError();
        if (value != nullptr) CloseServiceHandle(value);
        SetLastError(error);
    }
};

bool isExpectedServer(const HANDLE pipe, CallDiagnostics* const diagnostics) {
    const auto step = [diagnostics](const wchar_t* name) {
        if (diagnostics != nullptr) diagnostics->serverCheck = name;
    };
    const auto mismatch = []() {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    };
    ULONG pid = 0;
    step(L"pipe-server-pid");
    if (!GetNamedPipeServerProcessId(pipe, &pid)) return false;
    step(L"scm-connect");
    ScopedService manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (manager.value == nullptr) return false;
    step(L"scm-open-service");
    ScopedService service(OpenServiceW(manager.value, kServiceName,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
    if (service.value == nullptr) return false;
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    step(L"scm-running-pid");
    if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes)) return false;
    if (status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId != pid ||
        status.dwServiceType != SERVICE_WIN32_OWN_PROCESS) return mismatch();

    DWORD configBytes = 0;
    step(L"scm-config-size");
    if (QueryServiceConfigW(service.value, nullptr, 0, &configBytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        configBytes < sizeof(QUERY_SERVICE_CONFIGW) || configBytes > 64 * 1024) return mismatch();
    std::vector<std::uint8_t> configBuffer(configBytes);
    const auto config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data());
    step(L"scm-config");
    if (!QueryServiceConfigW(service.value, config, configBytes, &configBytes)) return false;

    step(L"system-directory");
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT systemSize = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (systemSize == 0) return false;
    if (systemSize >= MAX_PATH) return mismatch();
    const auto expectedImage = std::wstring(systemDirectory) + L"\\" + unlock::components::kSavedCredentialServiceFile;
    const auto expectedCommand = L"\"" + expectedImage + L"\"";
    step(L"scm-service-identity");
    if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        config->lpServiceStartName == nullptr ||
        _wcsicmp(config->lpServiceStartName, L"LocalSystem") != 0 ||
        config->lpBinaryPathName == nullptr ||
        _wcsicmp(config->lpBinaryPathName, expectedCommand.c_str()) != 0) return mismatch();
    ULONG session = 0xffffffff;
    step(L"pipe-server-session");
    if (!GetNamedPipeServerSessionId(pipe, &session)) return false;
    if (session != 0) return mismatch();
    ULONG currentPid = 0;
    step(L"pipe-recheck-pid");
    if (!GetNamedPipeServerProcessId(pipe, &currentPid)) return false;
    step(L"scm-recheck-pid");
    if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes)) return false;
    if (currentPid != pid || status.dwProcessId != pid ||
        status.dwCurrentState != SERVICE_RUNNING ||
        status.dwServiceType != SERVICE_WIN32_OWN_PROCESS) return mismatch();
    step(L"");
    return true;
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

bool encodeCredentialSummary(const CredentialSummary& status, SensitiveBytes& output) {
    SensitiveBytes identity;
    if ((status.credentialMatches && !status.credentialPresent) || !encodeIdentity(status.identity, identity)) return false;
    output.clear();
    const std::uint8_t present = (status.credentialPresent ? kCredentialPresentFlag : 0) |
        (status.credentialMatches ? kCredentialMatchesFlag : 0);
    append(output, &present, 1);
    append(output, identity.value.data(), identity.value.size());
    return true;
}

bool decodeCredentialSummary(const std::uint8_t* data, const std::size_t size, CredentialSummary& output) {
    if (data == nullptr || size < 1) return false;
    const auto flags = data[0];
    if ((flags & ~kCredentialStatusFlags) != 0 ||
        ((flags & kCredentialMatchesFlag) && !(flags & kCredentialPresentFlag))) return false;
    output.credentialPresent = (flags & kCredentialPresentFlag) != 0;
    output.credentialMatches = (flags & kCredentialMatchesFlag) != 0;
    return decodeIdentity(data + 1, size - 1, output.identity);
}

bool encodeStatus(const StatusPayload& status, SensitiveBytes& output) {
    SensitiveBytes summary;
    if (!encodeCredentialSummary(status, summary)) return false;
    output.clear();
    append(output, status.snapshotNonce.data(), status.snapshotNonce.size());
    append(output, summary.value.data(), summary.value.size());
    return true;
}

bool decodeStatus(const std::uint8_t* data, const std::size_t size, StatusPayload& output) {
    if (data == nullptr || size < kNonceSize + 1) return false;
    std::copy_n(data, kNonceSize, output.snapshotNonce.begin());
    return decodeCredentialSummary(data + kNonceSize, size - kNonceSize, output);
}

bool connectPipe(const HANDLE pipe, const HANDLE stopEvent) {
    const PipeIoContext context{(std::numeric_limits<std::uint64_t>::max)(), stopEvent};
    if (!ioAllowed(context)) return false;
    const HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event) return false;
    OVERLAPPED pending{};
    pending.hEvent = event;
    const BOOL started = ConnectNamedPipe(pipe, &pending);
    const bool alreadyConnected = !started && GetLastError() == ERROR_PIPE_CONNECTED;
    DWORD ignored = 0;
    const bool completed = alreadyConnected ? ioAllowed(context)
        : finishPipeIo(pipe, pending, started, context, ignored);
    const DWORD error = completed ? NO_ERROR : GetLastError();
    CloseHandle(event);
    SetLastError(error);
    return completed;
}

bool writePacket(const HANDLE pipe, const Packet& packet, const PipeIoContext& context) {
    if (packet.payload.value.size() > kMaxPacket) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    Header header{kMagic, kVersion, static_cast<std::uint16_t>(packet.operation),
        static_cast<std::uint32_t>(packet.result), static_cast<std::uint32_t>(packet.payload.value.size())};
    return transferExact(pipe, &header, sizeof(header), true, context) && (header.size == 0 ||
        transferExact(pipe, const_cast<std::uint8_t*>(packet.payload.value.data()), header.size, true, context));
}

bool readPacket(const HANDLE pipe, Packet& packet, const PipeIoContext& context) {
    packet.payload.clear();
    Header header{};
    if (!transferExact(pipe, &header, sizeof(header), false, context)) return false;
    if (header.magic != kMagic || header.version != kVersion || header.size > kMaxPacket ||
        !isKnownOperation(header.operation) || header.result > static_cast<std::uint32_t>(Result::busy)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    packet.payload.value.resize(header.size);
    if (header.size != 0 && !transferExact(pipe, packet.payload.value.data(), header.size, false, context)) {
        packet.payload.clear();
        return false;
    }
    packet.operation = static_cast<Operation>(header.operation);
    packet.result = static_cast<Result>(header.result);
    return true;
}

bool awaitReplyAcknowledgment(const HANDLE pipe, const Operation operation, const PipeIoContext& context) {
    ReplyAcknowledgment acknowledgment{};
    if (!transferExact(pipe, &acknowledgment, sizeof(acknowledgment), false, context)) return false;
    if (acknowledgment.magic != kAckMagic || acknowledgment.version != kVersion ||
        acknowledgment.operation != static_cast<std::uint16_t>(operation)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

bool writeReplyAcknowledgment(const HANDLE pipe, const Operation operation, const PipeIoContext& context) {
    ReplyAcknowledgment acknowledgment{kAckMagic, kVersion, static_cast<std::uint16_t>(operation)};
    return transferExact(pipe, &acknowledgment, sizeof(acknowledgment), true, context);
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

bool callOnPipe(const wchar_t* const pipeName, const Operation operation,
                SensitiveBytes&& request, Packet& reply, const DWORD waitMs,
                CallDiagnostics* const diagnostics) {
    if (diagnostics != nullptr) *diagnostics = {};
    const auto failed = [diagnostics](const CallStage stage, const DWORD error) {
        if (diagnostics != nullptr) {
            diagnostics->stage = stage;
            diagnostics->win32Error = error;
        }
        SetLastError(error);
        return false;
    };
    if (request.value.size() > kMaxPacket || !isKnownOperation(static_cast<std::uint16_t>(operation))) {
        return failed(CallStage::requestValidation, ERROR_INVALID_PARAMETER);
    }
    const PipeIoContext context{GetTickCount64() + waitMs};
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (;;) {
        if (!ioAllowed(context)) return failed(CallStage::waitForPipe, GetLastError());
        const ULONGLONG now = GetTickCount64();
        if (now >= context.deadline) return failed(CallStage::waitForPipe, ERROR_TIMEOUT);
        const DWORD remaining = static_cast<DWORD>(context.deadline - now);
        if (!WaitNamedPipeW(pipeName, remaining)) {
            return failed(CallStage::waitForPipe, GetLastError());
        }
        pipe = CreateFileW(pipeName, 0x0012019B, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY || GetTickCount64() >= context.deadline) {
            return failed(CallStage::openPipe, error);
        }
    }
    if (!isExpectedServer(pipe, diagnostics)) {
        const DWORD error = GetLastError();
        CloseHandle(pipe);
        return failed(CallStage::serverVerification, error);
    }
    Packet outbound;
    outbound.operation = operation;
    outbound.payload = std::move(request);
    CallStage failureStage = CallStage::none;
    DWORD failureError = NO_ERROR;
    if (!writePacket(pipe, outbound, context)) {
        failureStage = CallStage::requestWrite;
        failureError = GetLastError();
    } else if (!readPacket(pipe, reply, context)) {
        failureStage = CallStage::replyRead;
        failureError = GetLastError();
    } else if (reply.operation != operation) {
        failureStage = CallStage::replyValidation;
        failureError = ERROR_INVALID_DATA;
    } else {
        if (!writeReplyAcknowledgment(pipe, operation, context)) {
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

bool sameIdentity(const Identity& left, const Identity& right) noexcept {
    return left.sid == right.sid && left.qualifiedUserName == right.qualifiedUserName &&
        IsEqualGUID(left.providerId, right.providerId);
}

bool encodeUnlockResult(const UnlockResult& result, SensitiveBytes& output) {
    output.clear();
    append(output, result.nonce.data(), result.nonce.size());
    append(output, &result.status, sizeof(result.status));
    append(output, &result.substatus, sizeof(result.substatus));
    return true;
}

bool decodeUnlockResult(const std::uint8_t* data, const std::size_t size, UnlockResult& output) {
    if (!data || size != kNonceSize + 2 * sizeof(NTSTATUS)) return false;
    UnlockResult result;
    std::memcpy(result.nonce.data(), data, kNonceSize);
    std::memcpy(&result.status, data + kNonceSize, sizeof(result.status));
    std::memcpy(&result.substatus, data + kNonceSize + sizeof(result.status), sizeof(result.substatus));
    output = result;
    return true;
}

bool encodeLastUnlock(const std::optional<LastUnlockSummary>& summary, SensitiveBytes& output) {
    output.clear();
    if (summary && (!summary->completedAt || summary->rssi < system_ble::kMinimumThreshold || summary->rssi >= 0))
        return false;
    const std::uint8_t present = summary.has_value();
    append(output, &present, sizeof(present));
    if (summary) {
        append(output, &summary->completedAt, sizeof(summary->completedAt));
        append(output, &summary->rssi, sizeof(summary->rssi));
    }
    return true;
}

bool decodeLastUnlock(const std::uint8_t* data, const std::size_t size, std::optional<LastUnlockSummary>& output) {
    if (!data || !size || data[0] > 1) return false;
    std::optional<LastUnlockSummary> summary;
    if (data[0]) {
        LastUnlockSummary value;
        if (size != 1 + sizeof(value.completedAt) + sizeof(value.rssi)) return false;
        std::memcpy(&value.completedAt, data + 1, sizeof(value.completedAt));
        std::memcpy(&value.rssi, data + 1 + sizeof(value.completedAt), sizeof(value.rssi));
        summary = value;
    } else if (size != 1) return false;
    SensitiveBytes canonical;
    if (!encodeLastUnlock(summary, canonical)) return false;
    output = summary;
    return true;
}

bool encodeAutoSubmitOffer(const AutoSubmitOffer& offer, SensitiveBytes& output) {
    output.clear();
    if (offer.expiresAt == 0) return false;
    append(output, offer.nonce.data(), offer.nonce.size());
    append(output, &offer.expiresAt, sizeof(offer.expiresAt));
    return true;
}

bool encodeBinding(const system_ble::BindingRecord& record, SensitiveBytes& output) {
    output.clear();
    if (!system_ble::validThreshold(record.threshold)) return false;
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(record.accountSid.c_str(), &sid)) return false;
    LocalFree(sid);
    append(output, &record.containerId, sizeof(record.containerId));
    const auto threshold = static_cast<std::int32_t>(record.threshold);
    append(output, &threshold, sizeof(threshold));
    for (const auto* value : {&record.accountSid, &record.classicId, &record.bleId, &record.displayName}) {
        if ((value->empty() && value != &record.displayName && value != &record.classicId) || value->size() > 2048 || value->find(L'\0') != std::wstring::npos) return false;
        const auto length = static_cast<std::uint16_t>(value->size());
        append(output, &length, sizeof(length));
        append(output, value->data(), value->size() * sizeof(wchar_t));
    }
    return output.value.size() <= kMaxPacket;
}

bool decodeBinding(const std::uint8_t* data, std::size_t size, system_ble::BindingRecord& output) {
    if (!data || size > kMaxPacket) return false;
    auto cursor = data;
    auto left = size;
    system_ble::BindingRecord record;
    std::int32_t threshold = 0;
    if (!take(cursor, left, &record.containerId, sizeof(record.containerId)) ||
        !take(cursor, left, &threshold, sizeof(threshold))) return false;
    record.threshold = threshold;
    for (auto* value : {&record.accountSid, &record.classicId, &record.bleId, &record.displayName}) {
        std::uint16_t length = 0;
        if (!take(cursor, left, &length, sizeof(length)) ||
            (length == 0 && value != &record.displayName && value != &record.classicId) || length > 2048) return false;
        value->resize(length);
        if (!take(cursor, left, value->data(), length * sizeof(wchar_t))) return false;
    }
    SensitiveBytes canonical;
    if (left != 0 || !encodeBinding(record, canonical)) return false;
    output = std::move(record);
    return true;
}

bool encodeBindingSummary(const BindingSummary& summary, SensitiveBytes& output) {
    output.clear();
    if (summary.state > system_ble::BindingState::bound) return false;
    SensitiveBytes record;
    if (summary.state == system_ble::BindingState::bound && !encodeBinding(summary.record, record)) return false;
    const auto state = static_cast<std::uint8_t>(summary.state);
    append(output, &state, sizeof(state));
    if (!record.value.empty()) append(output, record.value.data(), record.value.size());
    return true;
}

bool decodeBindingSummary(const std::uint8_t* data, std::size_t size, BindingSummary& output) {
    if (!data || !size || data[0] > static_cast<std::uint8_t>(system_ble::BindingState::bound)) return false;
    BindingSummary summary;
    summary.state = static_cast<system_ble::BindingState>(data[0]);
    if (summary.state == system_ble::BindingState::bound ?
        !decodeBinding(data + 1, size - 1, summary.record) : size != 1) return false;
    output = std::move(summary);
    return true;
}

bool encodeBindingChange(const BindingChange& change, SensitiveBytes& output) {
    SensitiveBytes expected, candidate;
    if (!encodeBindingSummary(change.expected, expected) || !encodeBinding(change.candidate, candidate) ||
        change.cancelEvent.size() > 128 || change.cancelEvent.find(L'\0') != std::wstring::npos ||
        expected.value.size() + candidate.value.size() + change.cancelEvent.size() * sizeof(wchar_t) + 12 > kMaxPacket) return false;
    output.clear();
    const std::array<std::uint32_t, 3> sizes{static_cast<std::uint32_t>(expected.value.size()),
        static_cast<std::uint32_t>(candidate.value.size()), static_cast<std::uint32_t>(change.cancelEvent.size())};
    append(output, sizes.data(), sizeof(sizes));
    append(output, expected.value.data(), expected.value.size());
    append(output, candidate.value.data(), candidate.value.size());
    if (!change.cancelEvent.empty()) append(output, change.cancelEvent.data(), change.cancelEvent.size() * sizeof(wchar_t));
    return true;
}

bool decodeBindingChange(const std::uint8_t* data, std::size_t size, BindingChange& output) {
    if (!data || size < 12 || size > kMaxPacket) return false;
    std::array<std::uint32_t, 3> sizes{};
    std::memcpy(sizes.data(), data, sizeof(sizes));
    if (sizes[0] > kMaxPacket || sizes[1] > kMaxPacket || sizes[2] > 128 ||
        size != 12 + sizes[0] + sizes[1] + sizes[2] * sizeof(wchar_t)) return false;
    BindingChange change;
    if (!decodeBindingSummary(data + 12, sizes[0], change.expected) ||
        !decodeBinding(data + 12 + sizes[0], sizes[1],
            change.candidate)) return false;
    change.cancelEvent.resize(sizes[2]);
    if (sizes[2]) std::memcpy(change.cancelEvent.data(), data + 12 + sizes[0] + sizes[1], sizes[2] * sizeof(wchar_t));
    if (change.cancelEvent.find(L'\0') != std::wstring::npos) return false;
    output = std::move(change);
    return true;
}

bool encodeBindingRemoval(const BindingRemoval& removal, SensitiveBytes& output) {
    SensitiveBytes expected;
    if (!encodeBindingSummary(removal.expected, expected) || removal.cancelEvent.empty() ||
        removal.cancelEvent.size() > 128 || removal.cancelEvent.find(L'\0') != std::wstring::npos) return false;
    output.clear();
    const auto size = static_cast<std::uint32_t>(expected.value.size());
    append(output, &size, sizeof(size));
    append(output, expected.value.data(), expected.value.size());
    append(output, removal.cancelEvent.data(), removal.cancelEvent.size() * sizeof(wchar_t));
    return output.value.size() <= kMaxPacket;
}

bool decodeBindingRemoval(const std::uint8_t* data, std::size_t size, BindingRemoval& output) {
    if (!data || size < 4 || size > kMaxPacket) return false;
    std::uint32_t expectedSize = 0;
    std::memcpy(&expectedSize, data, sizeof(expectedSize));
    if (expectedSize > size - 4) return false;
    const auto eventBytes = size - 4 - expectedSize;
    if (!eventBytes || eventBytes % sizeof(wchar_t) || eventBytes > 128 * sizeof(wchar_t)) return false;
    BindingRemoval removal;
    if (!decodeBindingSummary(data + 4, expectedSize, removal.expected)) return false;
    removal.cancelEvent.resize(eventBytes / sizeof(wchar_t));
    std::memcpy(removal.cancelEvent.data(), data + 4 + expectedSize, eventBytes);
    if (removal.cancelEvent.find(L'\0') != std::wstring::npos) return false;
    output = std::move(removal);
    return true;
}

bool decodeAutoSubmitOffer(const std::uint8_t* data, const std::size_t size, AutoSubmitOffer& output) {
    if (data == nullptr || size != kNonceSize + sizeof(ULONGLONG)) return false;
    AutoSubmitOffer decoded;
    std::memcpy(decoded.nonce.data(), data, kNonceSize);
    std::memcpy(&decoded.expiresAt, data + kNonceSize, sizeof(decoded.expiresAt));
    if (decoded.expiresAt == 0) return false;
    output = decoded;
    return true;
}

const wchar_t* authenticationStatusText(const AuthenticationStatus& status) noexcept {
    switch (status.failure) {
    case AuthenticationFailure::none: break;
    case AuthenticationFailure::rssiTooLow: return L"Move your iPhone closer and try again.";
    case AuthenticationFailure::rssiUnavailable: return L"No fresh proximity sample. Try again.";
    case AuthenticationFailure::connectionLost: return L"The Bluetooth connection was lost. Try again.";
    case AuthenticationFailure::protectedOperationFailed: return L"Protected Bluetooth verification failed. Try again.";
    case AuthenticationFailure::expired: return L"Verification timed out. Try again.";
    case AuthenticationFailure::sessionChanged: return L"Your Windows session changed. Start again.";
    case AuthenticationFailure::associationInvalid: return L"The selected BLE endpoint is unavailable or no longer paired. Pair again.";
    case AuthenticationFailure::bondRejected: return L"Authenticated Secure Connections pairing is required.";
    case AuthenticationFailure::cancelled: return L"Verification cancelled.";
    case AuthenticationFailure::bindingChanged: return L"The app pairing changed. Start again.";
    case AuthenticationFailure::storageFailed: return L"The app pairing could not be saved. The previous pairing is retained.";
    case AuthenticationFailure::evidenceExpired: return L"Bluetooth evidence expired. Click Unlock again.";
    case AuthenticationFailure::internalError: return L"Verification failed. See diagnostics.";
    }
    switch (status.stage) {
    case AuthenticationStage::verifying: return L"Checking your iPhone's presence\u2026";
    case AuthenticationStage::approved: return L"Presence verified. Unlocking this PC\u2026";
    case AuthenticationStage::consumed: return L"This authorization has already been used. Start again.";
    case AuthenticationStage::completed: return L"App pairing saved.";
    default: return UNLOCK_PRODUCT_DISPLAY_NAME;
    }
}
bool encodeAuthenticationStatus(const AuthenticationStatus& status, SensitiveBytes& output) {
    output.clear();
    if (status.stage > AuthenticationStage::completed || status.failure > AuthenticationFailure::internalError ||
        (status.stage == AuthenticationStage::idle ? !status.requestId.empty() : status.requestId.size() != 36) ||
        (status.stage == AuthenticationStage::idle ? status.deadline != 0 : status.deadline == 0) ||
        ((status.stage == AuthenticationStage::failed) != (status.failure != AuthenticationFailure::none))) return false;
    for (std::size_t index = 0; index < status.requestId.size(); ++index) {
        const char ch = status.requestId[index];
        const bool separator = index == 8 || index == 13 || index == 18 || index == 23;
        if (separator ? ch != '-' : !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    const std::array<std::uint8_t, 4> fields{1, static_cast<std::uint8_t>(status.stage),
        static_cast<std::uint8_t>(status.failure), static_cast<std::uint8_t>(status.requestId.size())};
    append(output, fields.data(), fields.size());
    append(output, &status.deadline, sizeof(status.deadline));
    std::array<char, 36> requestId{};
    std::copy(status.requestId.begin(), status.requestId.end(), requestId.begin());
    append(output, requestId.data(), requestId.size());
    return true;
}

bool decodeAuthenticationStatus(const std::uint8_t* data, const std::size_t size, AuthenticationStatus& output) {
    if (data == nullptr || size != 48 || data[0] != 1 || (data[3] != 0 && data[3] != 36)) return false;
    AuthenticationStatus decoded;
    decoded.stage = static_cast<AuthenticationStage>(data[1]);
    decoded.failure = static_cast<AuthenticationFailure>(data[2]);
    std::memcpy(&decoded.deadline, data + 4, sizeof(decoded.deadline));
    decoded.requestId.assign(reinterpret_cast<const char*>(data + 12), data[3]);
    SensitiveBytes canonical;
    if (!encodeAuthenticationStatus(decoded, canonical) ||
        !std::equal(canonical.value.begin(), canonical.value.end(), data)) return false;
    output = std::move(decoded);
    return true;
}

bool call(const Operation operation, SensitiveBytes&& request, Packet& reply, const DWORD waitMs,
          CallDiagnostics* const diagnostics) {
    return callOnPipe(kPipeName, operation, std::move(request), reply, waitMs, diagnostics);
}

} // namespace unlock_windows::saved_credential
