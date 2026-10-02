// Created by Rui MA on 30 Sep 2026

#include "SavedCredentialIpc.h"
#include "SavedCredentialVault.h"
#include "EnrollmentStore.h"
#include "PhoneApprovalCore.h"

#include <WtsApi32.h>
#include <bcrypt.h>
#include <sddl.h>

#include <array>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <winrt/base.h>

namespace {

using namespace unlock_windows::saved_credential;
constexpr ULONGLONG kSnapshotLifetimeMs = 5 * 60 * 1000;
constexpr ULONGLONG kGrantLifetimeMs = 120 * 1000;
constexpr ACCESS_MASK kClientPipeRights = 0x0012019B;

std::atomic_bool gStopping{false};
std::atomic<ULONGLONG> gConsoleGeneration{0};
std::atomic_bool gPipeFailed{false};
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
    ULONGLONG consoleGeneration = 0;
    bool phone = false;
    bool autoSubmitOffered = false;
};

struct PhoneChallenge final {
    Identity identity;
    DWORD session = 0xffffffff;
    ULONGLONG consoleGeneration = 0;
    ULONGLONG deadline = 0;
    std::string requestId;
    std::string json;
    bool delivered = false;
};

std::int64_t nowMilliseconds() {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = now.dwLowDateTime;
    ticks.HighPart = now.dwHighDateTime;
    constexpr std::uint64_t offset = 116444736000000000ULL;
    return static_cast<std::int64_t>((ticks.QuadPart - offset) / 10000ULL);
}

void setText(SensitiveBytes& target, const std::string& value) {
    target.value.assign(value.begin(), value.end());
}

std::string phoneResult(const char* const status, const bool authenticated = false) {
    return std::string("{\"authenticated\":") + (authenticated ? "true" : "false") +
        ",\"status\":\"" + status + "\"}";
}

enum class Endpoint { credential, phone };

class Handler final {
public:
    Handler() : vault_() { reloadEnrollment(); }

    Packet process(const HANDLE pipe, Packet& request, const Endpoint endpoint) {
        std::lock_guard lock(mutex_);
        Packet response;
        response.operation = request.operation;
        response.result = Result::rejected;
        try {
            const auto client = inspectClient(pipe);
            const auto console = currentConsole();
            if (client.session != console.session) return response;
            if (removing_ && request.operation != Operation::clearForRemoval) return response;
            expirePhoneRequest(console);
            if (endpoint == Endpoint::phone) {
                if (client.logonUi || client.userSid != console.sid || !console.locked) return response;
                if (request.operation != Operation::takePhoneChallenge &&
                    request.operation != Operation::reportPhoneFailure &&
                    request.operation != Operation::submitPhoneAssertion) return response;
                processPhone(request, console, response);
                return response;
            }
            if (request.operation == Operation::takePhoneChallenge ||
                request.operation == Operation::reportPhoneFailure ||
                request.operation == Operation::submitPhoneAssertion) return response;
            if (request.operation == Operation::beginPhoneAuthentication) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid || !enrollmentMatches()) return response;
                const auto stored = vault_.storedIdentity();
                if (!stored || !sameIdentity(*stored, identity)) return response;
                if (phoneChallenge_ || (grant_ && GetTickCount64() < grant_->expiresAt &&
                    grant_->consoleGeneration == gConsoleGeneration.load())) {
                    setText(response.payload, "Authentication already pending or approved.");
                    return response;
                }
                grant_.reset();
                const auto generation = gConsoleGeneration.load();
                const auto issued = phoneCore_.issueChallenge(nowMilliseconds());
                if (generation != gConsoleGeneration.load()) return response;
                authenticationIdentity_ = identity;
                authenticationFailure_.clear();
                phoneChallenge_ = PhoneChallenge{identity, console.session, generation,
                    GetTickCount64() + 5000, phoneCore_.requestIdString(issued.challenge), issued.json, false};
                setText(response.payload, phoneChallenge_->requestId);
                authenticationRequestId_ = phoneChallenge_->requestId;
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::phoneAuthenticationStatus) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                if (authenticationIdentity_ && sameIdentity(identity, *authenticationIdentity_))
                    setText(response.payload, authenticationRequestId_ + authenticationFailure_);
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::captureIdentity) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                const ULONGLONG now = GetTickCount64();
                const bool reuseAuthorizedNonce = grant_ &&
                    grant_->session == console.session &&
                    sameIdentity(grant_->identity, identity) &&
                    grant_->consoleGeneration == gConsoleGeneration.load() &&
                    now < grant_->expiresAt;
                if (!snapshot_ || snapshot_->session != console.session ||
                    !sameIdentity(snapshot_->identity, identity) || now >= snapshot_->expiresAt) {
                    snapshot_ = Snapshot{identity, console.session, now + kSnapshotLifetimeMs, {}};
                    if (reuseAuthorizedNonce) {
                        snapshot_->nonce = grant_->nonce;
                    } else {
                        if (BCryptGenRandom(nullptr, snapshot_->nonce.data(), kNonceSize,
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                            snapshot_.reset();
                            fail("saved credential snapshot RNG failed");
                        }
                        grant_.reset();
                    }
                } else {
                    snapshot_->expiresAt = now + kSnapshotLifetimeMs;
                    if (reuseAuthorizedNonce) snapshot_->nonce = grant_->nonce;
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
                phoneChallenge_.reset();
            } else if (request.operation == Operation::clearCredential) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                vault_.clear();
                grant_.reset();
                phoneChallenge_.reset();
            } else if (request.operation == Operation::clearForRemoval) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                vault_.clear();
                grant_.reset();
                snapshot_.reset();
                phoneChallenge_.reset();
                removing_ = true;
            } else if (request.operation == Operation::reloadPhoneEnrollment) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                reloadEnrollment();
                grant_.reset();
                phoneChallenge_.reset();
            } else if (request.operation == Operation::takeAutoSubmitOffer) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                if (grant_ && grant_->phone && !grant_->autoSubmitOffered &&
                    grant_->session == console.session && GetTickCount64() < grant_->expiresAt &&
                    grant_->consoleGeneration == gConsoleGeneration.load() &&
                    sameIdentity(identity, grant_->identity) && enrollmentMatches()) {
                    grant_->autoSubmitOffered = true;
                    if (!encodeAutoSubmitOffer({grant_->nonce, grant_->expiresAt}, response.payload)) {
                        fail("automatic submission offer encoding failed");
                    }
                }
            } else if (request.operation == Operation::claimCredential) {
                if (!client.logonUi || !console.locked || !grant_ ||
                    grant_->session != console.session || GetTickCount64() >= grant_->expiresAt ||
                    grant_->consoleGeneration != gConsoleGeneration.load()) return response;
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
                    WaitForSingleObject(client.process.value, 0) != WAIT_TIMEOUT ||
                    grant_->consoleGeneration != gConsoleGeneration.load() ||
                    (grant_->phone && !enrollmentMatches())) return response;
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
    void reloadEnrollment() {
        phoneCore_.clearEnrolledPublicKey();
        enrolledSid_.clear();
        enrolledKey_.clear();
        const auto record = enrollmentStore_.load();
        if (!record) return;
        phoneCore_.setEnrolledPublicKey(record->publicKey);
        enrolledKey_ = record->publicKey;
        enrolledSid_ = record->accountSid;
        std::string sidAscii;
        sidAscii.reserve(enrolledSid_.size());
        for (const wchar_t character : enrolledSid_) {
            if (character < L'!' || character > L'~') fail("enrollment SID is not ASCII");
            sidAscii.push_back(static_cast<char>(character));
        }
        phoneCore_.setEnrolledAccountSid(std::move(sidAscii));
    }

    bool enrollmentMatches() const {
        const auto current = enrollmentStore_.load();
        return current && !enrolledSid_.empty() && current->accountSid == enrolledSid_ &&
            current->publicKey == enrolledKey_;
    }

    void processPhone(Packet& request, const Console& console, Packet& response) {
        const ULONGLONG generation = gConsoleGeneration.load();
        if (request.operation == Operation::takePhoneChallenge) {
            if (!request.payload.value.empty()) return;
            if (phoneChallenge_ && !phoneChallenge_->delivered) {
                phoneChallenge_->delivered = true;
                setText(response.payload, phoneChallenge_->requestId + phoneChallenge_->json);
            }
            response.result = Result::success;
            return;
        }
        if (request.operation == Operation::reportPhoneFailure) {
            if (!phoneChallenge_ || !phoneChallenge_->delivered || request.payload.value.size() != 37 ||
                std::memcmp(request.payload.value.data(), phoneChallenge_->requestId.data(), 36) != 0) return;
            const auto reason = request.payload.value[36];
            const char* text = reason == 1 ? "iPhone signal is below the configured RSSI threshold." :
                reason == 2 ? "Automatic approval is disabled on iPhone." :
                reason == 3 ? "iPhone could not read a fresh RSSI value." :
                reason == 4 ? "iPhone is not connected with both notifications subscribed." :
                reason == 5 ? "Bluetooth challenge delivery failed." :
                reason == 6 ? "iPhone rejected or could not sign the challenge." : nullptr;
            if (!text) return;
            authenticationFailure_ = text;
            phoneChallenge_.reset();
            setText(response.payload, phoneResult("phone_rejected"));
            response.result = Result::success;
            return;
        }
        if (request.payload.value.empty() || request.payload.value.size() > 4096 ||
            !phoneChallenge_ || !phoneChallenge_->delivered || phoneChallenge_->session != console.session ||
            phoneChallenge_->consoleGeneration != generation ||
            phoneChallenge_->identity.sid != enrolledSid_ || !enrollmentMatches() ||
            phoneChallenge_->identity.sid != console.sid) return;
        const auto stored = vault_.storedIdentity();
        if (!stored || !sameIdentity(*stored, phoneChallenge_->identity)) return;
        const std::string assertion(request.payload.value.begin(), request.payload.value.end());
        const auto result = phoneCore_.verifyAssertion(assertion, nowMilliseconds());
        if (!result.unlockApproved()) {
            if (result.code == unlock_windows::phone_approval::AssertionCode::request_mismatch) {
                setText(response.payload, phoneResult("request_mismatch"));
                response.result = Result::success;
                return;
            }
            authenticationFailure_ = unlock_windows::phone_approval::assertionCodeName(result.code);
            phoneChallenge_.reset();
            setText(response.payload, phoneResult(unlock_windows::phone_approval::assertionCodeName(result.code)));
            response.result = Result::success;
            return;
        }
        if (GetTickCount64() >= phoneChallenge_->deadline || generation != gConsoleGeneration.load()) {
            authenticationFailure_ = "Phone authentication expired or the console session changed.";
            phoneChallenge_.reset();
            setText(response.payload, phoneResult("challenge_expired"));
            response.result = Result::success;
            return;
        }
        const auto approved = phoneCore_.consumeUnlockApproval(nowMilliseconds());
        if (!approved || std::wstring(approved->accountSid.begin(), approved->accountSid.end()) !=
                phoneChallenge_->identity.sid || generation != gConsoleGeneration.load()) {
            phoneChallenge_.reset();
            return;
        }
        std::array<std::uint8_t, kNonceSize> nonce{};
        if (BCryptGenRandom(nullptr, nonce.data(), kNonceSize,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            fail("phone grant nonce RNG failed");
        }
        grant_ = Grant{*stored, console.session, GetTickCount64() + kGrantLifetimeMs,
            nonce, generation, true};
        phoneChallenge_.reset();
        setText(response.payload, phoneResult("unlock_approved", true));
        response.result = Result::success;
    }

    void expirePhoneRequest(const Console& console) {
        if (phoneChallenge_ && (GetTickCount64() >= phoneChallenge_->deadline || !console.locked ||
            console.session != phoneChallenge_->session || console.sid != phoneChallenge_->identity.sid ||
            gConsoleGeneration.load() != phoneChallenge_->consoleGeneration)) {
            authenticationFailure_ = "Phone authentication expired or the console session changed. Click the arrow again.";
            phoneChallenge_.reset();
        }
    }

    bool freshSnapshot(const Console& console) const {
        return snapshot_ && snapshot_->session == console.session &&
            snapshot_->identity.sid == console.sid && GetTickCount64() < snapshot_->expiresAt;
    }

    Vault vault_;
    unlock_windows::phone_approval::EnrollmentStore enrollmentStore_;
    unlock_windows::phone_approval::PhoneApprovalCore phoneCore_;
    std::wstring enrolledSid_;
    std::vector<std::uint8_t> enrolledKey_;
    std::optional<Snapshot> snapshot_;
    std::optional<Grant> grant_;
    std::optional<PhoneChallenge> phoneChallenge_;
    std::optional<Identity> authenticationIdentity_;
    std::string authenticationFailure_;
    std::string authenticationRequestId_;
    std::mutex mutex_;
    bool removing_ = false;
};

void reportServiceState(const DWORD state, const DWORD error = NO_ERROR) {
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwControlsAccepted = state == SERVICE_RUNNING
        ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE : 0;
    gStatus.dwWin32ExitCode = error;
    gStatus.dwWaitHint = state == SERVICE_STOP_PENDING ? 5000 : 0;
    SetServiceStatus(gStatusHandle, &gStatus);
}

void wakePipe(const wchar_t* const name) {
    const HANDLE wake = CreateFileW(name, kClientPipeRights, 0, nullptr,
        OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (wake != INVALID_HANDLE_VALUE) CloseHandle(wake);
}

DWORD WINAPI serviceControl(const DWORD control, const DWORD eventType, void*, void*) {
    if (control == SERVICE_CONTROL_STOP) {
        gStopping = true;
        reportServiceState(SERVICE_STOP_PENDING);
        wakePipe(kPipeName);
        wakePipe(kPhonePipeName);
        return NO_ERROR;
    }
    if (control == SERVICE_CONTROL_SESSIONCHANGE) {
        if (eventType == WTS_SESSION_LOCK || eventType == WTS_SESSION_UNLOCK || eventType == WTS_SESSION_LOGOFF ||
            eventType == WTS_CONSOLE_DISCONNECT || eventType == WTS_REMOTE_DISCONNECT) {
            ++gConsoleGeneration;
        }
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void servePipe(const HANDLE pipe, Handler& handler, const Endpoint endpoint) {
    while (!gStopping) {
        const bool connected = ConnectNamedPipe(pipe, nullptr) ||
            GetLastError() == ERROR_PIPE_CONNECTED;
        if (!connected) {
            if (!gStopping) gPipeFailed = true;
            gStopping = true;
            wakePipe(endpoint == Endpoint::phone ? kPipeName : kPhonePipeName);
            return;
        }
        if (!gStopping) {
            Packet request;
            if (readPacket(pipe, request) && request.result == Result::success) {
                auto response = handler.process(pipe, request, endpoint);
                if (!writePacket(pipe, response)) {
                    OutputDebugStringW(L"saved credential response write failed");
                } else if (!awaitReplyAcknowledgment(pipe, request.operation, 2000)) {
                    const std::wstring message = L"saved credential reply acknowledgment failed; win32=" +
                        std::to_wstring(GetLastError());
                    OutputDebugStringW(message.c_str());
                }
            } else {
                OutputDebugStringW(L"saved credential request read failed");
            }
        }
        DisconnectNamedPipe(pipe);
    }
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
        descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;0x0012019B;;;AU)", SDDL_REVISION_1,
                &descriptor, nullptr)) fail("phone approval pipe ACL creation failed");
        attributes.lpSecurityDescriptor = descriptor;
        const HANDLE rawPhonePipe = CreateNamedPipeW(kPhonePipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, kMaxPacket + 16, kMaxPacket + 16, 0, &attributes);
        LocalFree(descriptor);
        Handle phonePipe(rawPhonePipe);
        if (phonePipe.value == INVALID_HANDLE_VALUE) fail("phone approval pipe creation failed");
        reportServiceState(SERVICE_RUNNING);
        std::thread phoneThread([&]() {
            try {
                winrt::init_apartment(winrt::apartment_type::multi_threaded);
                servePipe(phonePipe.value, handler, Endpoint::phone);
                winrt::uninit_apartment();
            } catch (...) {
                gPipeFailed = true;
                gStopping = true;
                wakePipe(kPipeName);
            }
        });
        servePipe(pipe.value, handler, Endpoint::credential);
        gStopping = true;
        wakePipe(kPhonePipeName);
        phoneThread.join();
        reportServiceState(SERVICE_STOPPED,
            gPipeFailed.load() ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR);
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
