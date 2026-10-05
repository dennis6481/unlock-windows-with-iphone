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

namespace unlock_windows::saved_credential {
namespace {

constexpr std::uint32_t kMagic = 0x31434347;
constexpr std::uint16_t kVersion = 2;
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

template<class Transfer>
bool writePacketUsing(const Packet& packet, Transfer transfer) {
    if (packet.payload.value.size() > kMaxPacket) return false;
    Header header{kMagic, kVersion, static_cast<std::uint16_t>(packet.operation),
        static_cast<std::uint32_t>(packet.result), static_cast<std::uint32_t>(packet.payload.value.size())};
    return transfer(&header, sizeof(header)) && (header.size == 0 ||
        transfer(const_cast<std::uint8_t*>(packet.payload.value.data()), header.size));
}

template<class Transfer>
bool readPacketUsing(Packet& packet, Transfer transfer) {
    Header header{};
    if (!transfer(&header, sizeof(header))) return false;
    if (header.magic != kMagic || header.version != kVersion || header.size > kMaxPacket ||
        !isKnownOperation(header.operation)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    packet.payload.clear();
    packet.payload.value.resize(header.size);
    if (header.size != 0 && !transfer(packet.payload.value.data(), header.size)) return false;
    packet.operation = static_cast<Operation>(header.operation);
    packet.result = static_cast<Result>(header.result);
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

bool encodeStatus(const StatusPayload& status, SensitiveBytes& output) {
    SensitiveBytes identity;
    if ((status.credentialMatches && !status.credentialPresent) || !encodeIdentity(status.identity, identity)) return false;
    output.clear();
    append(output, status.snapshotNonce.data(), status.snapshotNonce.size());
    const std::uint8_t present = (status.credentialPresent ? kCredentialPresentFlag : 0) |
        (status.credentialMatches ? kCredentialMatchesFlag : 0);
    append(output, &present, 1);
    append(output, identity.value.data(), identity.value.size());
    return true;
}

bool decodeStatus(const std::uint8_t* data, const std::size_t size, StatusPayload& output) {
    if (data == nullptr || size < kNonceSize + 1) return false;
    std::copy_n(data, kNonceSize, output.snapshotNonce.begin());
    const auto flags = data[kNonceSize];
    if ((flags & ~kCredentialStatusFlags) != 0 ||
        ((flags & kCredentialMatchesFlag) && !(flags & kCredentialPresentFlag))) return false;
    output.credentialPresent = (flags & kCredentialPresentFlag) != 0;
    output.credentialMatches = (flags & kCredentialMatchesFlag) != 0;
    return decodeIdentity(data + kNonceSize + 1, size - kNonceSize - 1, output.identity);
}

bool writePacket(const HANDLE pipe, const Packet& packet) {
    return writePacketUsing(packet, [pipe](void* data, DWORD size) { return writeExact(pipe, data, size); });
}

bool readPacket(const HANDLE pipe, Packet& packet) {
    return readPacketUsing(packet, [pipe](void* data, DWORD size) { return readExact(pipe, data, size); });
}

bool writePacket(const HANDLE pipe, const Packet& packet, const DWORD waitMs) {
    return writePacketUsing(packet, [pipe, waitMs](void* data, DWORD size) {
        return transferExactWithTimeout(pipe, data, size, true, waitMs);
    });
}

bool readPacket(const HANDLE pipe, Packet& packet, const DWORD waitMs) {
    return readPacketUsing(packet, [pipe, waitMs](void* data, DWORD size) {
        return transferExactWithTimeout(pipe, data, size, false, waitMs);
    });
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
    if (request.value.size() > kMaxPacket) {
        return failed(CallStage::requestValidation, ERROR_INVALID_PARAMETER);
    }
    const ULONGLONG deadline = GetTickCount64() + waitMs;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        const DWORD remaining = now < deadline ? static_cast<DWORD>(deadline - now) : 0;
        if (!WaitNamedPipeW(pipeName, remaining)) {
            return failed(CallStage::waitForPipe, GetLastError());
        }
        pipe = CreateFileW(pipeName, 0x0012019B, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY || GetTickCount64() >= deadline) {
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
    if (!writePacket(pipe, outbound, waitMs)) {
        failureStage = CallStage::requestWrite;
        failureError = GetLastError();
    } else if (!readPacket(pipe, reply, waitMs)) {
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

bool encodeAutoSubmitOffer(const AutoSubmitOffer& offer, SensitiveBytes& output) {
    output.clear();
    if (offer.expiresAt == 0) return false;
    append(output, offer.nonce.data(), offer.nonce.size());
    append(output, &offer.expiresAt, sizeof(offer.expiresAt));
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
    case AuthenticationFailure::rssiTooLow: return L"Move your iPhone closer and try again.";
    case AuthenticationFailure::automaticDisabled: return L"Enable automatic approval in the iPhone app.";
    case AuthenticationFailure::rssiUnavailable: return L"Couldn't check your iPhone's proximity. Try again.";
    case AuthenticationFailure::subscriptionLost: return L"Connection to your iPhone was interrupted. Try again.";
    case AuthenticationFailure::deliveryFailed: return L"Couldn't send the request to your iPhone. Try again.";
    case AuthenticationFailure::signingFailed: return L"Couldn't verify approval from your iPhone. Try again.";
    case AuthenticationFailure::expired: return L"Your iPhone didn't respond in time. Try again.";
    case AuthenticationFailure::sessionChanged: return L"Your Windows session changed. Start again.";
    case AuthenticationFailure::invalidAssertion: return L"Couldn't verify approval from your iPhone. Try again.";
    case AuthenticationFailure::none: break;
    }
    switch (status.stage) {
    case AuthenticationStage::waitingPhone: return L"Waiting for your iPhone\u2026";
    case AuthenticationStage::awaitingAssertion: return L"Waiting for approval from your iPhone\u2026";
    case AuthenticationStage::approved: return L"Approved by your iPhone. Unlocking this PC\u2026";
    case AuthenticationStage::consumed: return L"This approval has already been used. Start again for a new approval.";
    default: return UNLOCK_PRODUCT_DISPLAY_NAME;
    }
}

bool encodeAuthenticationStatus(const AuthenticationStatus& status, SensitiveBytes& output) {
    output.clear();
    if (status.stage > AuthenticationStage::consumed || status.failure > AuthenticationFailure::invalidAssertion ||
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

bool encodePhoneChallenge(const PhoneChallengePayload& challenge, SensitiveBytes& output) {
    if (!encodeAuthenticationStatus(challenge.status, output) || challenge.json.size() > 4096 ||
        (!challenge.json.empty() && challenge.status.stage != AuthenticationStage::awaitingAssertion)) return false;
    const auto size = static_cast<std::uint32_t>(challenge.json.size());
    append(output, &size, sizeof(size));
    if (size != 0) append(output, challenge.json.data(), size);
    return true;
}

bool decodePhoneChallenge(const std::uint8_t* data, const std::size_t size, PhoneChallengePayload& output) {
    if (data == nullptr || size < 52 || size > 52 + 4096) return false;
    PhoneChallengePayload decoded;
    if (!decodeAuthenticationStatus(data, 48, decoded.status)) return false;
    std::uint32_t jsonSize = 0;
    std::memcpy(&jsonSize, data + 48, sizeof(jsonSize));
    if (jsonSize != size - 52 || (jsonSize != 0 && decoded.status.stage != AuthenticationStage::awaitingAssertion)) return false;
    decoded.json.assign(reinterpret_cast<const char*>(data + 52), jsonSize);
    output = std::move(decoded);
    return true;
}

bool call(const Operation operation, SensitiveBytes&& request, Packet& reply, const DWORD waitMs,
          CallDiagnostics* const diagnostics) {
    return callOnPipe(kPipeName, operation, std::move(request), reply, waitMs, diagnostics);
}

bool callPhone(const Operation operation, SensitiveBytes&& request, Packet& reply, const DWORD waitMs,
               CallDiagnostics* const diagnostics) {
    if (!isPhoneOperation(operation)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        if (diagnostics != nullptr) *diagnostics = {CallStage::requestValidation, ERROR_INVALID_PARAMETER};
        return false;
    }
    return callOnPipe(kPhonePipeName, operation, std::move(request), reply, waitMs, diagnostics);
}

} // namespace unlock_windows::saved_credential
