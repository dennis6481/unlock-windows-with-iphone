// Created by Rui MA on 30 Sep 2026

#include "SavedCredentialIpc.h"
#include "SavedCredentialVault.h"

#include <WtsApi32.h>
#include <bcrypt.h>
#include <sddl.h>

#include <array>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace unlock_windows::saved_credential;
constexpr ULONGLONG kSnapshotLifetimeMs = 5 * 60 * 1000;
constexpr ULONGLONG kGrantLifetimeMs = 120 * 1000;
constexpr ACCESS_MASK kClientPipeRights = 0x0012019B;

std::atomic_bool gStopping{false};
SERVICE_STATUS_HANDLE gStatusHandle = nullptr;
SERVICE_STATUS gStatus{};

void fail(const char* message) { throw std::runtime_error(message); }

struct Handle final {
    HANDLE value = nullptr;
    explicit Handle(HANDLE handle = nullptr) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) { other.value = nullptr; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            if (value != nullptr && value != INVALID_HANDLE_VALUE) CloseHandle(value);
            value = other.value;
            other.value = nullptr;
        }
        return *this;
    }
    ~Handle() { if (value != nullptr && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

std::vector<std::uint8_t> tokenInfo(const HANDLE token, const TOKEN_INFORMATION_CLASS field) {
    DWORD bytes = 0;
    GetTokenInformation(token, field, nullptr, 0, &bytes);
    if (bytes == 0 || bytes > 64 * 1024) fail("saved credential token information size invalid");
    std::vector<std::uint8_t> result(bytes);
    if (!GetTokenInformation(token, field, result.data(), bytes, &bytes)) {
        fail("saved credential token information query failed");
    }
    return result;
}

std::wstring sidText(PSID sid) {
    LPWSTR raw = nullptr;
    if (!ConvertSidToStringSidW(sid, &raw)) fail("saved credential SID conversion failed");
    const std::wstring result(raw);
    LocalFree(raw);
    return result;
}

std::wstring tokenSid(const HANDLE token) {
    const auto bytes = tokenInfo(token, TokenUser);
    if (bytes.size() < sizeof(TOKEN_USER)) fail("saved credential token SID missing");
    return sidText(reinterpret_cast<const TOKEN_USER*>(bytes.data())->User.Sid);
}

DWORD tokenSession(const HANDLE token) {
    const auto bytes = tokenInfo(token, TokenSessionId);
    if (bytes.size() < sizeof(DWORD)) fail("saved credential token session missing");
    DWORD value = 0;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return value;
}

LUID tokenLogonId(const HANDLE token) {
    const auto bytes = tokenInfo(token, TokenStatistics);
    if (bytes.size() < sizeof(TOKEN_STATISTICS)) fail("saved credential token statistics missing");
    return reinterpret_cast<const TOKEN_STATISTICS*>(bytes.data())->AuthenticationId;
}

bool elevatedAdmin(const HANDLE token) {
    const auto bytes = tokenInfo(token, TokenElevation);
    if (bytes.size() < sizeof(TOKEN_ELEVATION) ||
        reinterpret_cast<const TOKEN_ELEVATION*>(bytes.data())->TokenIsElevated == 0) return false;
    PSID administrators = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &administrators)) fail("saved credential Administrators SID unavailable");
    BOOL member = FALSE;
    const BOOL checked = CheckTokenMembership(token, administrators, &member);
    LocalFree(administrators);
    if (!checked) fail("saved credential administrator membership check failed");
    return member != FALSE;
}

std::wstring processImage(const HANDLE process) {
    std::wstring path(32768, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &length)) {
        fail("saved credential client image query failed");
    }
    path.resize(length);
    return path;
}

std::wstring expectedLogonUi() {
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) fail("saved credential System32 path unavailable");
    return std::wstring(systemDirectory) + L"\\LogonUI.exe";
}

struct Client final {
    Handle process;
    ULONG pid = 0;
    std::wstring userSid;
    DWORD session = 0xffffffff;
    bool logonUi = false;
    bool admin = false;
};

Client inspectClient(const HANDLE pipe) {
    ULONG pid = 0;
    ULONG pipeSession = 0xffffffff;
    if (!GetNamedPipeClientProcessId(pipe, &pid) ||
        !GetNamedPipeClientSessionId(pipe, &pipeSession)) fail("saved credential pipe client identity unavailable");
    Client client;
    client.pid = pid;
    client.process.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (client.process.value == nullptr) fail("saved credential client process cannot be pinned");
    Handle processToken;
    if (!OpenProcessToken(client.process.value, TOKEN_QUERY, &processToken.value)) {
        fail("saved credential process token unavailable");
    }
    DWORD processSession = 0xffffffff;
    if (!ProcessIdToSessionId(pid, &processSession)) fail("saved credential process session unavailable");

    if (!ImpersonateNamedPipeClient(pipe)) fail("saved credential pipe impersonation failed");
    Handle pipeToken;
    const bool opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &pipeToken.value);
    const DWORD openError = opened ? ERROR_SUCCESS : GetLastError();
    if (!RevertToSelf()) std::terminate();
    if (!opened) {
        SetLastError(openError);
        fail("saved credential actual pipe client token unavailable");
    }
    const auto processSid = tokenSid(processToken.value);
    client.userSid = tokenSid(pipeToken.value);
    const LUID processLogon = tokenLogonId(processToken.value);
    const LUID pipeLogon = tokenLogonId(pipeToken.value);
    client.session = tokenSession(pipeToken.value);
    if (processSid != client.userSid || processSession != pipeSession ||
        client.session != processSession ||
        processLogon.LowPart != pipeLogon.LowPart ||
        processLogon.HighPart != pipeLogon.HighPart) {
        fail("saved credential process and pipe token identity differ");
    }
    client.logonUi = client.userSid == L"S-1-5-18" &&
        _wcsicmp(processImage(client.process.value).c_str(), expectedLogonUi().c_str()) == 0;
    client.admin = client.userSid != L"S-1-5-18" && elevatedAdmin(pipeToken.value);
    return client;
}

std::wstring wtsString(const DWORD session, const WTS_INFO_CLASS field) {
    LPWSTR raw = nullptr;
    DWORD bytes = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, field, &raw, &bytes)) {
        fail("saved credential console account query failed");
    }
    if (raw == nullptr || bytes < sizeof(wchar_t) || bytes % sizeof(wchar_t) != 0 ||
        raw[0] == L'\0' || raw[bytes / sizeof(wchar_t) - 1] != L'\0') {
        if (raw != nullptr) WTSFreeMemory(raw);
        fail("saved credential console account query malformed");
    }
    const std::wstring value(raw);
    WTSFreeMemory(raw);
    return value;
}

struct Console final {
    DWORD session = 0xffffffff;
    std::wstring sid;
    bool locked = false;
};

Console currentConsole() {
    Console result;
    result.session = WTSGetActiveConsoleSessionId();
    if (result.session == 0xffffffff) fail("saved credential physical console unavailable");
    const auto user = wtsString(result.session, WTSUserName);
    const auto domain = wtsString(result.session, WTSDomainName);
    const auto account = domain + L"\\" + user;
    DWORD sidBytes = 0;
    DWORD domainChars = 0;
    SID_NAME_USE use{};
    const BOOL sized = LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidBytes,
        nullptr, &domainChars, &use);
    if (sized || GetLastError() != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0) {
        fail("saved credential console SID size query failed");
    }
    std::vector<std::uint8_t> sid(sidBytes);
    std::vector<wchar_t> referencedDomain(domainChars == 0 ? 1 : domainChars);
    if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sidBytes,
            referencedDomain.data(), &domainChars, &use) || use != SidTypeUser) {
        fail("saved credential console SID lookup failed");
    }
    result.sid = sidText(sid.data());
    LPWSTR raw = nullptr;
    DWORD bytes = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, result.session,
            WTSSessionInfoEx, &raw, &bytes)) fail("saved credential console lock-state query failed");
    if (raw == nullptr || bytes < sizeof(WTSINFOEXW)) {
        if (raw != nullptr) WTSFreeMemory(raw);
        fail("saved credential console lock-state malformed");
    }
    const auto* info = reinterpret_cast<const WTSINFOEXW*>(raw);
    if (info->Level != 1 || info->Data.WTSInfoExLevel1.SessionId != result.session ||
        info->Data.WTSInfoExLevel1.SessionState != WTSActive ||
        (info->Data.WTSInfoExLevel1.SessionFlags != WTS_SESSIONSTATE_LOCK &&
         info->Data.WTSInfoExLevel1.SessionFlags != WTS_SESSIONSTATE_UNLOCK)) {
        WTSFreeMemory(raw);
        fail("saved credential console state is not an active known lock state");
    }
    result.locked = info->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK;
    WTSFreeMemory(raw);
    return result;
}

struct Snapshot final {
    Identity identity;
    DWORD session = 0xffffffff;
    ULONGLONG expiresAt = 0;
    std::array<std::uint8_t, kNonceSize> nonce{};
};

struct Grant final {
    Identity identity;
    DWORD session = 0xffffffff;
    ULONGLONG expiresAt = 0;
    std::array<std::uint8_t, kNonceSize> nonce{};
};

class Handler final {
public:
    Handler() : vault_() {}

    Packet process(const HANDLE pipe, Packet& request) {
        Packet response;
        response.operation = request.operation;
        response.result = Result::rejected;
        try {
            const auto client = inspectClient(pipe);
            const auto console = currentConsole();
            if (client.session != console.session) return response;
            if (removing_ && request.operation != Operation::clearForRemoval) return response;
            if (request.operation == Operation::captureIdentity) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                const ULONGLONG now = GetTickCount64();
                if (!snapshot_ || snapshot_->session != console.session ||
                    !sameIdentity(snapshot_->identity, identity) || now >= snapshot_->expiresAt) {
                    snapshot_ = Snapshot{identity, console.session, now + kSnapshotLifetimeMs, {}};
                    if (BCryptGenRandom(nullptr, snapshot_->nonce.data(), kNonceSize,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                        snapshot_.reset();
                        fail("saved credential snapshot RNG failed");
                    }
                    grant_.reset();
                } else {
                    snapshot_->expiresAt = now + kSnapshotLifetimeMs;
                }
                response.payload.value.assign(snapshot_->nonce.begin(), snapshot_->nonce.end());
            } else if (request.operation == Operation::status) {
                if (!client.admin || console.locked || !request.payload.value.empty() ||
                    !freshSnapshot(console)) return response;
                StatusPayload status{snapshot_->identity, snapshot_->nonce,
                    vault_.storedIdentity().has_value()};
                if (!encodeStatus(status, response.payload)) fail("saved credential status encoding failed");
            } else if (request.operation == Operation::setCredential ||
                       request.operation == Operation::updateCredential) {
                if (!client.admin || console.locked || !freshSnapshot(console) ||
                    request.payload.value.size() < kNonceSize + sizeof(std::uint32_t)) return response;
                if (std::memcmp(request.payload.value.data(), snapshot_->nonce.data(), kNonceSize) != 0) {
                    return response;
                }
                std::uint32_t passwordBytes = 0;
                std::memcpy(&passwordBytes, request.payload.value.data() + kNonceSize, sizeof(passwordBytes));
                if (passwordBytes == 0 || passwordBytes > 2048 || passwordBytes % sizeof(wchar_t) != 0 ||
                    request.payload.value.size() != kNonceSize + sizeof(passwordBytes) + passwordBytes) {
                    return response;
                }
                vault_.save(snapshot_->identity,
                    request.payload.value.data() + kNonceSize + sizeof(passwordBytes),
                    passwordBytes, request.operation == Operation::updateCredential);
                grant_.reset();
            } else if (request.operation == Operation::clearCredential) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                vault_.clear();
                grant_.reset();
            } else if (request.operation == Operation::clearForRemoval) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                vault_.clear();
                grant_.reset();
                snapshot_.reset();
                removing_ = true;
            } else if (request.operation == Operation::armTest) {
                if (!client.admin || console.locked || !freshSnapshot(console) ||
                    request.payload.value.size() != kNonceSize ||
                    std::memcmp(request.payload.value.data(), snapshot_->nonce.data(), kNonceSize) != 0) {
                    return response;
                }
                const auto stored = vault_.storedIdentity();
                if (!stored || !sameIdentity(*stored, snapshot_->identity)) return response;
                grant_ = Grant{*stored, console.session, GetTickCount64() + kGrantLifetimeMs,
                    snapshot_->nonce};
            } else if (request.operation == Operation::claimCredential) {
                if (!client.logonUi || !console.locked || !grant_ ||
                    grant_->session != console.session || GetTickCount64() >= grant_->expiresAt) return response;
                Identity identity;
                if (request.payload.value.size() <= kNonceSize ||
                    !decodeIdentity(request.payload.value.data(),
                        request.payload.value.size() - kNonceSize, identity) ||
                    std::memcmp(request.payload.value.data() +
                        request.payload.value.size() - kNonceSize,
                        grant_->nonce.data(), kNonceSize) != 0 ||
                    identity.sid != console.sid || !sameIdentity(identity, grant_->identity)) return response;
                ULONG currentPipePid = 0;
                if (!GetNamedPipeClientProcessId(pipe, &currentPipePid) ||
                    currentPipePid != client.pid ||
                    WaitForSingleObject(client.process.value, 0) != WAIT_TIMEOUT) return response;
                grant_.reset();
                response.payload = vault_.release(identity);
            } else {
                response.result = Result::invalidRequest;
                return response;
            }
            response.result = Result::success;
        } catch (const std::exception& error) {
            OutputDebugStringA(error.what());
            response.result = Result::internalError;
            response.payload.clear();
        }
        return response;
    }

private:
    bool freshSnapshot(const Console& console) const {
        return snapshot_ && snapshot_->session == console.session &&
            snapshot_->identity.sid == console.sid && GetTickCount64() < snapshot_->expiresAt;
    }

    Vault vault_;
    std::optional<Snapshot> snapshot_;
    std::optional<Grant> grant_;
    bool removing_ = false;
};

void reportServiceState(const DWORD state, const DWORD error = NO_ERROR) {
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    gStatus.dwWin32ExitCode = error;
    gStatus.dwWaitHint = state == SERVICE_STOP_PENDING ? 5000 : 0;
    SetServiceStatus(gStatusHandle, &gStatus);
}

DWORD WINAPI serviceControl(const DWORD control, DWORD, void*, void*) {
    if (control == SERVICE_CONTROL_STOP) {
        gStopping = true;
        reportServiceState(SERVICE_STOP_PENDING);
        const HANDLE wake = CreateFileW(kPipeName, kClientPipeRights, 0, nullptr,
            OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (wake != INVALID_HANDLE_VALUE) CloseHandle(wake);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, serviceControl, nullptr);
    if (gStatusHandle == nullptr) return;
    reportServiceState(SERVICE_START_PENDING);
    try {
        Handler handler;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;0x0012019B;;;BA)", SDDL_REVISION_1,
                &descriptor, nullptr)) fail("saved credential pipe ACL creation failed");
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        const HANDLE rawPipe = CreateNamedPipeW(kPipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, kMaxPacket + 16, kMaxPacket + 16, 0, &attributes);
        LocalFree(descriptor);
        Handle pipe(rawPipe);
        if (pipe.value == INVALID_HANDLE_VALUE) fail("saved credential pipe creation failed");
        reportServiceState(SERVICE_RUNNING);
        while (!gStopping) {
            const bool connected = ConnectNamedPipe(pipe.value, nullptr) ||
                GetLastError() == ERROR_PIPE_CONNECTED;
            if (!connected) fail("saved credential pipe connection failed");
            if (!gStopping) {
                Packet request;
                if (readPacket(pipe.value, request) && request.result == Result::success) {
                    auto response = handler.process(pipe.value, request);
                    if (!writePacket(pipe.value, response)) OutputDebugStringW(L"saved credential response write failed");
                } else {
                    OutputDebugStringW(L"saved credential request read failed");
                }
            }
            DisconnectNamedPipe(pipe.value);
        }
        reportServiceState(SERVICE_STOPPED);
    } catch (const std::exception& error) {
        OutputDebugStringA(error.what());
        reportServiceState(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    }
}

} // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceName), serviceMain}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : 1;
}
