// Created by Rui MA on 30 Sep 2026

#include <initguid.h>
#include "SavedCredentialIpc.h"
#include "SavedCredentialVault.h"
#include "LastUnlock.h"
#include "EnrollmentStore.h"
#include "../Bluetooth/SystemBleSession.h"
#include "../Bluetooth/PresenceAuthorization.h"
#include "../Setup/SetupIdentity.h"

#include <WtsApi32.h>
#include <lm.h>
#include <bcrypt.h>
#include <sddl.h>
#include <identitystore.h>
#include <propsys.h>
#include <propkey.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <exception>
#include <memory>
#include <mutex>
#include <condition_variable>
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

std::atomic_bool gStopping{false};
std::atomic<ULONGLONG> gConsoleGeneration{0};
std::atomic<ULONGLONG> gIdentityGeneration{0};
std::atomic<ULONGLONG> gUnlockHistoryGeneration{0};
std::atomic<ULONGLONG> gConnectionGeneration{0};
std::atomic_bool gSuspended{false};
std::atomic<DWORD> gObservedConsoleSession{0xffffffff};
std::atomic_bool gPipeFailed{false};
SERVICE_STATUS_HANDLE gStatusHandle = nullptr;
SERVICE_STATUS gStatus{};
HANDLE gPipeStopEvent = nullptr;
void stopPipe();

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

struct Console final {
    DWORD session = 0xffffffff;
    std::wstring sid;
    bool locked = false;
    LUID logonId{};
};

Console currentConsole() {
    Console result;
    result.session = WTSGetActiveConsoleSessionId();
    if (result.session == 0xffffffff) fail("saved credential physical console unavailable");
    Handle userToken;
    if (!WTSQueryUserToken(result.session, &userToken.value)) fail("existing console user token unavailable");
    if (tokenSession(userToken.value) != result.session) fail("console user token session differs");
    result.sid = tokenSid(userToken.value);
    result.logonId = tokenLogonId(userToken.value);
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
    if (WTSGetActiveConsoleSessionId() != result.session) fail("physical console changed during token validation");
    return result;
}

Identity consoleIdentity(const Console& console) {
    PSID rawSid = nullptr;
    winrt::check_bool(ConvertStringSidToSidW(console.sid.c_str(), &rawSid));
    struct Sid final { PSID value; ~Sid() { LocalFree(value); } } ownedSid{rawSid};
    DWORD nameChars = 0, domainChars = 0;
    SID_NAME_USE use{};
    if (LookupAccountSidW(nullptr, rawSid, nullptr, &nameChars, nullptr, &domainChars, &use) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || nameChars == 0)
        fail("Windows console account name lookup failed");
    std::vector<wchar_t> accountName(nameChars), domainName(domainChars);
    winrt::check_bool(LookupAccountSidW(nullptr, rawSid, accountName.data(), &nameChars,
        domainName.data(), &domainChars, &use));
    struct UserInfo final {
        LPBYTE value = nullptr;
        ~UserInfo() { if (value) NetApiBufferFree(value); }
    } userInfo;
    const auto status = NetUserGetInfo(nullptr, accountName.data(), 24, &userInfo.value);
    if (status != NERR_Success)
        throw std::runtime_error("Windows online identity query failed (Win32 " + std::to_string(status) + ").");
    if (!userInfo.value) fail("Windows online identity query returned no account information");
    const auto* online = reinterpret_cast<const USER_INFO_24*>(userInfo.value);
    if (!online->usri24_internet_identity)
        fail("Windows console account is not connected to an online identity");
    if (!online->usri24_user_sid || sidText(online->usri24_user_sid) != console.sid ||
        !online->usri24_internet_provider_name || !*online->usri24_internet_provider_name ||
        !online->usri24_internet_principal_name || !*online->usri24_internet_principal_name)
        fail("Windows online identity is incomplete or does not match the console token");
    const std::wstring qualifiedName = std::wstring(online->usri24_internet_provider_name) +
        L"\\" + online->usri24_internet_principal_name;

    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    struct Apartment final { ~Apartment() { winrt::uninit_apartment(); } } apartment;
    winrt::com_ptr<IIdentityStore> store;
    winrt::check_hresult(CoCreateInstance(__uuidof(CoClassIdentityStore), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IIdentityStore), store.put_void()));
    winrt::com_ptr<IEnumUnknown> identities;
    winrt::check_hresult(store->EnumerateIdentities(IDENTITIES_ALL, nullptr, nullptr, identities.put()));
    struct Property final {
        PROPVARIANT value{};
        ~Property() { PropVariantClear(&value); }
    };
    std::optional<Identity> result;
    for (;;) {
        winrt::com_ptr<IUnknown> item;
        const HRESULT next = identities->Next(1, item.put(), nullptr);
        winrt::check_hresult(next);
        if (next == S_FALSE) break;
        const auto properties = item.as<IPropertyStore>();
        Property sid, provider;
        winrt::check_hresult(properties->GetValue(PKEY_Identity_PrimarySid, &sid.value));
        if (sid.value.vt != VT_LPWSTR || !sid.value.pwszVal)
            fail("Windows identity store returned an invalid primary SID");
        if (console.sid != sid.value.pwszVal) continue;
        winrt::check_hresult(properties->GetValue(PKEY_Identity_ProviderID, &provider.value));
        if (provider.value.vt != VT_CLSID || !provider.value.puuid)
            fail("Windows console identity provider ID is unavailable");
        Identity identity{console.sid, qualifiedName, *provider.value.puuid};
        SensitiveBytes encoded;
        if (!encodeIdentity(identity, encoded)) fail("Windows identity properties are invalid");
        if (result && !sameIdentity(*result, identity)) fail("Windows console identity is ambiguous");
        result = std::move(identity);
    }
    if (!result) fail("Windows identity store has no identity for the physical console user");
    return std::move(*result);
}

struct Snapshot final {
    Identity identity;
    DWORD session = 0xffffffff;
    ULONGLONG expiresAt = 0;
    std::array<std::uint8_t, kNonceSize> nonce{};
};

struct ProvisioningIdentity final {
    Identity identity;
    DWORD session = 0xffffffff;
    ULONGLONG generation = 0;
    std::optional<LUID> logonId;
};

struct Grant final {
    Identity identity;
    DWORD session = 0xffffffff;
    ULONGLONG expiresAt = 0;
    std::array<std::uint8_t, kNonceSize> nonce{};
    ULONGLONG consoleGeneration = 0;
    bool autoSubmitOffered = false;
    unlock_windows::system_ble::PresenceAuthorization authorization;
};

struct BleTask final {
    Handle cancelEvent;
    Identity identity;
    DWORD session = 0xffffffff;
    ULONGLONG consoleGeneration = 0;
    ULONGLONG identityGeneration = 0;
    LUID logonId{};
    ULONGLONG started = 0;
    AuthenticationStatus status;
    BindingChange change;
    bool binding = false;
    std::atomic<bool> cancelled{false};
    std::shared_ptr<unlock_windows::system_ble::Session> connection;
};
void setText(SensitiveBytes& target, const std::string& value) {
    target.value.assign(value.begin(), value.end());
}

class Handler final {
public:
    Handler() : worker_([this] { workerMain(); }) {}
    ~Handler() {
        { std::lock_guard lock(mutex_); stopping_ = true; if (task_) task_->cancelled = true; }
        wake_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    Packet process(const HANDLE pipe, Packet& request) {
        std::lock_guard lock(mutex_);
        Packet response;
        response.operation = request.operation;
        response.result = Result::rejected;
        try {
            auto client = inspectClient(pipe);
            if (requiresLogonUi(request.operation) && !client.logonUi) {
                if (request.operation == Operation::reportUnlockResult) appendDiagnostic("unlock result rejected: caller is not LogonUI");
                return response;
            }
            if (request.operation == Operation::captureProvisioningIdentity) {
                const DWORD session = WTSGetActiveConsoleSessionId();
                if (!client.logonUi || session == 0xffffffff || client.session != session || removing_)
                    return response;
                Identity identity;
                std::wstring targetSid;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    FAILED(unlock::components::readSetupTargetSid(targetSid)) || identity.sid != targetSid)
                    return response;
                if (WTSGetActiveConsoleSessionId() != session) return response;
                gObservedConsoleSession = session;
                const auto generation = gIdentityGeneration.load();
                if (!provisioning_ || provisioning_->session != session || provisioning_->generation != generation ||
                    !sameIdentity(provisioning_->identity, identity))
                    provisioning_ = ProvisioningIdentity{identity, session, generation, std::nullopt};
                response.result = Result::success;
                return response;
            }
            const auto console = currentConsole();
            if (provisioning_ && (provisioning_->session != console.session ||
                provisioning_->generation != gIdentityGeneration.load() || provisioning_->identity.sid != console.sid ||
                (provisioning_->logonId && (provisioning_->logonId->LowPart != console.logonId.LowPart ||
                    provisioning_->logonId->HighPart != console.logonId.HighPart)))) {
                provisioning_.reset();
                snapshot_.reset();
            }
            gObservedConsoleSession = console.session;
            if (unlockHistory_.pending() || unlockHistory_.summary())
                refreshUnlockHistory(console, bindingSummary(), vault_.storedIdentity());
            expireRequest(console);
            if (client.session != console.session) return response;
            if (removing_ && request.operation != Operation::clearForRemoval) return response;
            if (request.operation == Operation::reportUnlockResult) {
                UnlockResult result;
                if (!decodeUnlockResult(request.payload.value.data(), request.payload.value.size(), result)) {
                    appendDiagnostic("unlock result rejected: malformed payload");
                    response.result = Result::invalidRequest;
                    return response;
                }
                const auto processState = unlockProcess_.value ? WaitForSingleObject(unlockProcess_.value, 0) : WAIT_OBJECT_0;
                if (processState == WAIT_FAILED) fail("unlock result process wait failed");
                const bool processAlive = processState == WAIT_TIMEOUT;
                if (!unlockHistory_.report(result, client.pid, client.logonUi, processAlive,
                                           consoleIdentity(console), GetTickCount64())) {
                    appendDiagnostic("unlock result rejected: no matching pending claim/process/context");
                    if (!unlockHistory_.pending()) unlockProcess_ = Handle{};
                    return response;
                }
                unlockProcess_ = Handle{};
                appendDiagnostic("native unlock result status=" + std::to_string(result.status) +
                    " substatus=" + std::to_string(result.substatus));
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::lastUnlockStatus) {
                if (client.logonUi || console.locked || client.userSid != console.sid ||
                    !request.payload.value.empty() || !verifiedManagementIdentity(console)) return response;
                refreshUnlockHistory(console, bindingSummary(), provisioning_->identity);
                if (!encodeLastUnlock(unlockHistory_.summary(), response.payload)) fail("last unlock encoding failed");
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::unlockEligibility) {
                Identity identity;
                if (!client.logonUi || !console.locked ||
                    !decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                const auto stored = vault_.storedIdentity();
                if (stored && !sameIdentity(*stored, identity)) return response;
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::bindingStatus) {
                if (client.logonUi || console.locked || client.userSid != console.sid ||
                    !request.payload.value.empty() || !verifiedManagementIdentity(console)) return response;
                if (!encodeBindingSummary(bindingSummary(), response.payload)) fail("binding status encoding failed");
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::beginBinding || request.operation == Operation::saveThreshold ||
                request.operation == Operation::removeBinding) {
                if (!client.admin || console.locked || !verifiedManagementIdentity(console)) return response;
                if (task_) { response.result = Result::busy; return response; }
                const auto original = bindingSummary();
                if (request.operation == Operation::removeBinding) {
                    BindingRemoval removal;
                    if (!decodeBindingRemoval(request.payload.value.data(), request.payload.value.size(), removal) ||
                        removal.expected != original) return response;
                    auto cancellation = openCancellation(removal.cancelEvent);
                    if (WaitForSingleObject(cancellation.value, 0) != WAIT_TIMEOUT || !verifiedManagementIdentity(console)) return response;
                    enrollmentStore_.remove();
                    clearUnlockHistory();
                    ++gConnectionGeneration;
                    wake_.notify_one();
                    response.result = Result::success;
                    return response;
                }
                BindingChange change;
                if (!decodeBindingChange(request.payload.value.data(), request.payload.value.size(), change) ||
                    change.expected != original || change.candidate.accountSid != provisioning_->identity.sid) return response;
                const auto stored = vault_.storedIdentity();
                if (!stored || !sameIdentity(*stored, provisioning_->identity)) return response;
                if (request.operation == Operation::saveThreshold) {
                    auto cancellation = openCancellation(change.cancelEvent);
                    auto candidate = change.candidate;
                    candidate.threshold = original.record.threshold;
                    if (original.state != unlock_windows::system_ble::BindingState::bound || candidate != original.record)
                        return response;
                    enrollmentStore_.save(change.candidate, [&] {
                        if (WaitForSingleObject(cancellation.value, 0) != WAIT_TIMEOUT || bindingSummary() != original ||
                            !verifiedManagementIdentity(console)) fail("Threshold cancelled or binding/account changed before commit");
                    });
                    ++gConnectionGeneration;
                    wake_.notify_one();
                    response.result = Result::success;
                    return response;
                }
                queueTask(provisioning_->identity, console, std::move(change), true);
                if (!encodeAuthenticationStatus(managementStatus_, response.payload)) fail("binding task status encoding failed");
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::bindingTaskStatus) {
                if (client.logonUi || console.locked || client.userSid != console.sid ||
                    !request.payload.value.empty() || !verifiedManagementIdentity(console)) return response;
                if (!encodeAuthenticationStatus(managementStatus_, response.payload)) fail("binding task status encoding failed");
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::serviceDiagnostics) {
                if (client.logonUi || console.locked || client.userSid != console.sid ||
                    !request.payload.value.empty() || !verifiedManagementIdentity(console)) return response;
                if (diagnosticSid_ == console.sid) setText(response.payload, diagnostic_);
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::cancelVerification) {
                if (!task_ || request.payload.value.size() != task_->status.requestId.size() ||
                    std::string(request.payload.value.begin(), request.payload.value.end()) != task_->status.requestId ||
                    (task_->binding ? client.logonUi || client.userSid != task_->identity.sid || console.locked :
                        !client.logonUi || !console.locked)) return response;
                rejectTask(AuthenticationFailure::cancelled);
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::beginVerification) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                std::wstring targetSid;
                const auto original = bindingSummary();
                if (FAILED(unlock::components::readSetupTargetSid(targetSid)) || identity.sid != targetSid ||
                    original.state != unlock_windows::system_ble::BindingState::bound ||
                    original.record.accountSid != identity.sid) return response;
                const auto stored = vault_.storedIdentity();
                if (!stored || !sameIdentity(*stored, identity)) return response;
                if (task_) { response.result = Result::busy; setText(response.payload, "Bluetooth verification is still finishing. Try again."); return response; }
                queueTask(identity, console, {original, original.record}, false);
                if (!encodeAuthenticationStatus(authenticationStatus_, response.payload)) fail("authentication status encoding failed");
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::verificationStatus) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                if (authenticationIdentity_ && sameIdentity(identity, *authenticationIdentity_)) {
                    if (!encodeAuthenticationStatus(authenticationStatus_, response.payload)) fail("authentication status encoding failed");
                } else if (!encodeAuthenticationStatus({}, response.payload)) fail("idle status encoding failed");
                response.result = Result::success;
                return response;
            }
            if (request.operation == Operation::captureIdentity) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                std::wstring targetSid;
                if (FAILED(unlock::components::readSetupTargetSid(targetSid)) || identity.sid != targetSid)
                    return response;
                provisioning_ = ProvisioningIdentity{identity, console.session, gIdentityGeneration.load(), console.logonId};
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
            } else if (request.operation == Operation::credentialSummary) {
                if (console.locked || client.userSid != console.sid || !request.payload.value.empty() ||
                    !verifiedManagementIdentity(console)) return response;
                const auto stored = vault_.storedIdentity();
                CredentialSummary summary{provisioning_->identity, stored.has_value(),
                    stored && sameIdentity(*stored, provisioning_->identity)};
                if (!encodeCredentialSummary(summary, response.payload)) fail("credential summary encoding failed");
            } else if (request.operation == Operation::status) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                if (!refreshManagementSnapshot(console)) return response;
                const auto stored = vault_.storedIdentity();
                StatusPayload status{{snapshot_->identity, stored.has_value(),
                    stored && sameIdentity(*stored, snapshot_->identity)}, snapshot_->nonce};
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
                if (passwordBytes == 0 || passwordBytes > kMaxPasswordChars * sizeof(wchar_t) || passwordBytes % sizeof(wchar_t) != 0 ||
                    request.payload.value.size() != kNonceSize + sizeof(passwordBytes) + passwordBytes) {
                    return response;
                }
                vault_.save(snapshot_->identity,
                    request.payload.value.data() + kNonceSize + sizeof(passwordBytes),
                    passwordBytes, request.operation == Operation::updateCredential);
                unlockHistory_.cancelPending();
                unlockProcess_ = Handle{};
                ++gConnectionGeneration;
                wake_.notify_one();
                grant_.reset();
                rejectTask(AuthenticationFailure::bindingChanged);
            } else if (request.operation == Operation::clearCredential) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                vault_.clear();
                clearUnlockHistory();
                ++gConnectionGeneration;
                wake_.notify_one();
                grant_.reset();
                rejectTask(AuthenticationFailure::bindingChanged);
            } else if (request.operation == Operation::clearForRemoval) {
                if (!client.admin || console.locked || !request.payload.value.empty()) return response;
                vault_.clear();
                clearUnlockHistory();
                grant_.reset();
                snapshot_.reset();
                provisioning_.reset();
                rejectTask(AuthenticationFailure::bindingChanged);
                removing_ = true;
                ++gConnectionGeneration;
                wake_.notify_one();
            } else if (request.operation == Operation::takeAutoSubmitOffer) {
                if (!client.logonUi || !console.locked) return response;
                Identity identity;
                if (!decodeIdentity(request.payload.value.data(), request.payload.value.size(), identity) ||
                    identity.sid != console.sid) return response;
                if (grant_ && !grant_->autoSubmitOffered &&
                    grant_->session == console.session && GetTickCount64() < grant_->expiresAt &&
                    grant_->consoleGeneration == gConsoleGeneration.load() &&
                    sameIdentity(identity, grant_->identity) && bindingMatches()) {
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
                    !bindingMatches()) return response;
                const auto latest = currentConsole();
                const bool contextMatches = sameIdentity(consoleIdentity(latest), identity) && latest.locked &&
                    latest.session == console.session && latest.sid == console.sid &&
                    latest.logonId.LowPart == task_->logonId.LowPart && latest.logonId.HighPart == task_->logonId.HighPart &&
                    grant_->consoleGeneration == gConsoleGeneration.load() && !task_->cancelled &&
                    task_->change.expected == bindingSummary();
                const auto evidence = task_->connection->evidence();
                const auto claimedNonce = grant_->nonce;
                UnlockContext context{identity, console.session, console.logonId, task_->change.candidate,
                    gUnlockHistoryGeneration.load(), task_->identityGeneration};
                if (!grant_->authorization.consume(contextMatches, evidence, task_->started,
                    GetTickCount64(), task_->status.deadline, task_->change.candidate.threshold)) {
                    rejectTask(AuthenticationFailure::evidenceExpired);
                    return response;
                }
                grant_.reset();
                if (!authenticationStatus_.requestId.empty()) {
                    authenticationStatus_.stage = AuthenticationStage::consumed;
                    authenticationStatus_.failure = AuthenticationFailure::none;
                    logAuthentication();
                }
                if (task_) task_->cancelled = true;
                response.payload = vault_.release(identity);
                unlockProcess_ = std::move(client.process);
                unlockHistory_.beginClaim(std::move(context), claimedNonce, client.pid, evidence.rssi);
            } else {
                response.result = Result::invalidRequest;
                return response;
            }
            response.result = Result::success;
        } catch (...) {
            const auto message = winrt::to_message();
            OutputDebugStringW(message.c_str());
            response.result = Result::internalError;
            response.payload.clear();
            if (request.operation == Operation::beginBinding || request.operation == Operation::saveThreshold ||
                request.operation == Operation::removeBinding || request.operation == Operation::bindingStatus ||
                request.operation == Operation::bindingTaskStatus) setText(response.payload, winrt::to_string(message));
        }
        return response;
    }

private:
    void clearUnlockHistory() {
        unlockHistory_.clear();
        unlockProcess_ = Handle{};
    }

    void refreshUnlockHistory(const Console& console, const BindingSummary& binding,
                             const std::optional<Identity>& stored) {
        if (!stored || stored->sid != console.sid || binding.state != unlock_windows::system_ble::BindingState::bound) {
            clearUnlockHistory();
            return;
        }
        unlockHistory_.refreshContext({*stored, console.session, console.logonId, binding.record,
            gUnlockHistoryGeneration.load(), gIdentityGeneration.load()});
        if (unlockHistory_.pending()) {
            const auto processState = WaitForSingleObject(unlockProcess_.value, 0);
            if (processState == WAIT_FAILED) fail("pending unlock process wait failed");
            if (processState != WAIT_TIMEOUT) {
                unlockHistory_.cancelPending();
                unlockProcess_ = Handle{};
            }
        } else unlockProcess_ = Handle{};
    }

    Handle openCancellation(const std::wstring& name) {
        if (!name.starts_with(kBindingCancelPrefix)) fail("Binding cancellation event required");
        Handle event(OpenEventW(SYNCHRONIZE, FALSE, name.c_str()));
        if (!event.value || WaitForSingleObject(event.value, 0) != WAIT_TIMEOUT)
            fail("Binding cancelled or cancellation event inaccessible");
        return event;
    }
    void logAuthentication() const {
        const auto now = GetTickCount64();
        const auto remaining = authenticationStatus_.deadline > now ? authenticationStatus_.deadline - now : 0;
        const std::wstring text = L"[SavedCredential] authentication stage=" +
            std::to_wstring(static_cast<unsigned>(authenticationStatus_.stage)) + L" reason=" +
            std::to_wstring(static_cast<unsigned>(authenticationStatus_.failure)) + L" remainingMs=" +
            std::to_wstring(remaining) + L" consoleSession=" + std::to_wstring(gObservedConsoleSession.load()) + L"\n";
        OutputDebugStringW(text.c_str());
    }

    BindingSummary bindingSummary() const {
        BindingSummary summary;
        auto record = enrollmentStore_.load();
        if (record) { summary.state = unlock_windows::system_ble::BindingState::bound; summary.record = std::move(*record); }
        return summary;
    }

    bool bindingMatches() const {
        return task_ && !task_->binding && task_->change.expected == bindingSummary() && task_->connection &&
            task_->connection->evidence().failure == AuthenticationFailure::none && !task_->cancelled;
    }

    void appendDiagnostic(const std::string& message) {
        const auto line = "tickMs=" + std::to_string(GetTickCount64()) + " " + message + "\n";
        if (line.size() > kMaxPacket) fail("Service diagnostic entry exceeds IPC limit");
        if (diagnostic_.size() + line.size() > kMaxPacket) {
            diagnostic_.erase(0, diagnostic_.find('\n', diagnostic_.size() + line.size() - kMaxPacket - 1) + 1);
        }
        diagnostic_ += line;
        OutputDebugStringA(line.c_str());
    }

    void rejectTask(AuthenticationFailure reason, const std::string& detail = {}) {
        grant_.reset();
        if (!task_) return;
        task_->cancelled = true;
        auto& status = task_->binding ? managementStatus_ : authenticationStatus_;
        if (status.stage == AuthenticationStage::consumed || status.stage == AuthenticationStage::completed) return;
        status.stage = AuthenticationStage::failed;
        status.failure = reason;
        diagnosticSid_ = task_->identity.sid;
        appendDiagnostic(std::string(task_->binding ? "binding" : "authentication") + " request=" + status.requestId +
            " failure=" + std::to_string(static_cast<unsigned>(reason)) + ": " +
            (detail.empty() ? winrt::to_string(authenticationStatusText(status)) : detail));
        if (!task_->binding) logAuthentication();
    }

    void expireRequest(const Console& console) {
        if (!task_ || task_->cancelled) return;
        if (task_->cancelEvent.value && WaitForSingleObject(task_->cancelEvent.value, 0) != WAIT_TIMEOUT) {
            rejectTask(AuthenticationFailure::cancelled);
            return;
        }
        auto reason = authenticationExpiry(GetTickCount64(), task_->status.deadline,
            console.session == task_->session && console.sid == task_->identity.sid &&
            console.logonId.LowPart == task_->logonId.LowPart && console.logonId.HighPart == task_->logonId.HighPart &&
            gConsoleGeneration.load() == task_->consoleGeneration && gIdentityGeneration.load() == task_->identityGeneration,
            task_->binding ? !console.locked : console.locked);
        if (reason == AuthenticationFailure::none && task_->change.expected != bindingSummary())
            reason = AuthenticationFailure::bindingChanged;
        if (reason == AuthenticationFailure::none && grant_ && task_->connection)
            reason = task_->connection->evidence().failure;
        if (reason != AuthenticationFailure::none) rejectTask(reason);
    }

    void queueTask(const Identity& identity, const Console& console, BindingChange change, bool binding) {
        auto task = std::make_shared<BleTask>();
        if (binding) {
            task->cancelEvent = openCancellation(change.cancelEvent);
        }
        task->identity = identity;
        task->session = console.session;
        task->consoleGeneration = gConsoleGeneration.load();
        task->identityGeneration = gIdentityGeneration.load();
        task->logonId = console.logonId;
        task->started = GetTickCount64();
        GUID id{};
        winrt::check_hresult(CoCreateGuid(&id));
        auto text = winrt::to_string(winrt::to_hstring(winrt::guid{id}));
        if (text.size() == 38) text = text.substr(1, 36);
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        task->status = {text, AuthenticationStage::verifying, AuthenticationFailure::none,
            task->started + unlock_windows::system_ble::kOperationLifetimeMs};
        task->change = std::move(change);
        task->binding = binding;
        diagnosticSid_ = identity.sid;
        diagnostic_.clear();
        appendDiagnostic(std::string(binding ? "binding" : "authentication") + " request=" + task->status.requestId +
            " BEGIN deadlineMs=" + std::to_string(task->status.deadline));
        if (binding) managementStatus_ = task->status;
        else { authenticationIdentity_ = identity; authenticationStatus_ = task->status; }
        task_ = std::move(task);
        grant_.reset();
        unlockHistory_.cancelPending();
        unlockProcess_ = Handle{};
        wake_.notify_one();
    }

    void workerMain() noexcept {
        try {
            winrt::init_apartment(winrt::apartment_type::multi_threaded);
            struct Apartment final { ~Apartment() { winrt::uninit_apartment(); } } apartment;
            std::shared_ptr<unlock_windows::system_ble::Session> retained;
            std::optional<unlock_windows::system_ble::BindingRecord> retainedBinding;
            std::optional<Console> retainedConsole;
            ULONGLONG retainedGeneration = 0;
            bool preparationFailed = false;
            std::uint64_t preparationRevision = 0;
            std::string backgroundError;
            const auto closeRetained = [&] {
                if (retained) {
                    retained->close();
                    retained.reset();
                }
                retainedBinding.reset();
                retainedConsole.reset();
                preparationFailed = false;
            };
            const auto report = [this](const std::string& message) {
                std::lock_guard lock(mutex_);
                appendDiagnostic(task_ ? std::string(task_->binding ? "binding" : "authentication") +
                    " request=" + task_->status.requestId + " " + message : "BLE connection " + message);
            };
            for (;;) {
                std::shared_ptr<BleTask> task;
                bool stopping;
                {
                    std::lock_guard lock(mutex_);
                    task = task_;
                    stopping = stopping_;
                }
                if (gStopping || stopping) {
                    closeRetained();
                    return;
                }
                if (preparationFailed && retained && retained->healthy() && retained->revision() != preparationRevision)
                    preparationFailed = false;
                if (!task) {
                    std::optional<unlock_windows::system_ble::BindingRecord> desired;
                    std::optional<Console> console;
                    const auto generation = gConnectionGeneration.load();
                    try {
                        {
                            std::lock_guard lock(mutex_);
                            if (!removing_ && !gSuspended) {
                                const auto binding = bindingSummary();
                                const auto stored = vault_.storedIdentity();
                                if (binding.state == unlock_windows::system_ble::BindingState::bound && stored) {
                                    console = currentConsole();
                                    gObservedConsoleSession = console->session;
                                    refreshUnlockHistory(*console, binding, stored);
                                    std::wstring targetSid;
                                    winrt::check_hresult(unlock::components::readSetupTargetSid(targetSid));
                                    if (console->sid == targetSid && binding.record.accountSid == targetSid && stored->sid == targetSid) {
                                        if (sameIdentity(*stored, consoleIdentity(*console))) desired = binding.record;
                                        else fail("BLE connection target online identity differs from saved identity");
                                    }
                                }
                            }
                        }
                        const bool sameContext = desired && retainedBinding == desired && retainedConsole && console &&
                            retainedGeneration == generation && retainedConsole->session == console->session &&
                            retainedConsole->sid == console->sid && retainedConsole->logonId.LowPart == console->logonId.LowPart &&
                            retainedConsole->logonId.HighPart == console->logonId.HighPart;
                        if (!sameContext) {
                            closeRetained();
                            if (desired) {
                                retainedBinding = desired;
                                retainedConsole = console;
                                retainedGeneration = generation;
                                retained = std::make_shared<unlock_windows::system_ble::Session>(*desired, report);
                                { std::lock_guard lock(mutex_); diagnosticSid_ = desired->accountSid; }
                                report("Maintain selected phone after native sign-in; no authorization created");
                            }
                        }
                        backgroundError.clear();
                        if (retained && !preparationFailed) {
                            try {
                                retained->prepare(GetTickCount64(), [this, generation] {
                                    std::lock_guard lock(mutex_);
                                    return !stopping_ && !gStopping && !gSuspended && !task_ &&
                                        generation == gConnectionGeneration.load();
                                });
                            } catch (const unlock_windows::system_ble::VerificationError& error) {
                                if (error.reason != AuthenticationFailure::cancelled) {
                                    preparationFailed = true;
                                    preparationRevision = retained->revision();
                                    report(std::string("Preparation failed; next explicit request may prepare again: ") + error.what());
                                }
                            } catch (...) {
                                preparationFailed = true;
                                preparationRevision = retained->revision();
                                report("Preparation failed: " + winrt::to_string(winrt::to_message()));
                            }
                            if (!retained->healthy()) {
                                retained->close();
                                retained.reset();
                                preparationFailed = true;
                            }
                        }
                    } catch (...) {
                        const auto error = winrt::to_string(winrt::to_message());
                        closeRetained();
                        if (error != backgroundError) { report("Preparation unavailable: " + error); backgroundError = error; }
                    }
                    std::unique_lock lock(mutex_);
                    wake_.wait_for(lock, std::chrono::seconds(1), [&] { return stopping_ || gStopping || task_; });
                    continue;
                }
                std::shared_ptr<unlock_windows::system_ble::Session> connection;
                try {
                    if (preparationFailed || !retainedBinding || *retainedBinding != task->change.candidate ||
                        !retainedConsole || retainedConsole->session != task->session ||
                        retainedConsole->sid != task->identity.sid || retainedConsole->logonId.LowPart != task->logonId.LowPart ||
                        retainedConsole->logonId.HighPart != task->logonId.HighPart ||
                        retainedGeneration != gConnectionGeneration.load()) closeRetained();
                    if (!retained) {
                        retainedBinding = task->change.candidate;
                        retainedConsole = Console{task->session, task->identity.sid, !task->binding, task->logonId};
                        retainedGeneration = gConnectionGeneration.load();
                        retained = std::make_shared<unlock_windows::system_ble::Session>(*retainedBinding, report);
                    }
                    connection = retained;
                    const auto connectionGeneration = retainedGeneration;
                    connection->beginRequest(task->started, [task, connectionGeneration] {
                        return !task->cancelled && !gStopping && !gSuspended &&
                            connectionGeneration == gConnectionGeneration.load() &&
                            (!task->cancelEvent.value || WaitForSingleObject(task->cancelEvent.value, 0) == WAIT_TIMEOUT) &&
                            task->consoleGeneration == gConsoleGeneration.load() &&
                            task->identityGeneration == gIdentityGeneration.load();
                    });
                    connection->verify();
                    {
                        std::lock_guard lock(mutex_);
                        const auto console = currentConsole();
                        expireRequest(console);
                        if (task->cancelled) throw unlock_windows::system_ble::VerificationError(AuthenticationFailure::cancelled, "Task invalidated");
                        const auto stored = vault_.storedIdentity();
                        if (!stored || !sameIdentity(*stored, task->identity) || !sameIdentity(consoleIdentity(console), task->identity))
                            throw unlock_windows::system_ble::VerificationError(AuthenticationFailure::sessionChanged, "Full account identity changed");
                        task->connection = connection;
                        if (task->binding) {
                            enrollmentStore_.save(task->change.candidate, [&] {
                                const auto latest = currentConsole();
                                expireRequest(latest);
                                if (task->cancelled || connection->evidence().failure != AuthenticationFailure::none ||
                                    !verifiedManagementIdentity(latest) || !sameIdentity(provisioning_->identity, task->identity))
                                    fail("Binding invalidated before atomic commit");
                            });
                            clearUnlockHistory();
                            managementStatus_.stage = AuthenticationStage::completed;
                            appendDiagnostic("binding request=" + task->status.requestId + " COMPLETED binding saved");
                            task->cancelled = true;
                        } else {
                            const auto proof = connection->evidence();
                            if (proof.failure != AuthenticationFailure::none)
                                throw unlock_windows::system_ble::VerificationError(proof.failure, "Evidence expired before approval");
                            std::array<std::uint8_t, kNonceSize> nonce{};
                            if (BCryptGenRandom(nullptr, nonce.data(), kNonceSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
                                fail("BLE grant nonce RNG failed");
                            const auto expires = (std::min)(task->status.deadline, proof.communicationAt + unlock_windows::system_ble::kEvidenceLifetimeMs);
                            grant_ = Grant{task->identity, task->session, expires, nonce, task->consoleGeneration};
                            authenticationStatus_.stage = AuthenticationStage::approved;
                            logAuthentication();
                        }
                    }
                    while (!task->cancelled && !gStopping) {
                        connection->refresh();
                        {
                            std::lock_guard lock(mutex_);
                            expireRequest(currentConsole());
                            if (!task->cancelled && connection->evidence().failure != AuthenticationFailure::none)
                                rejectTask(connection->evidence().failure);
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    }
                } catch (const unlock_windows::system_ble::VerificationError& error) {
                    OutputDebugStringA(error.what());
                    if (error.reason == AuthenticationFailure::associationInvalid || error.reason == AuthenticationFailure::bondRejected ||
                        error.reason == AuthenticationFailure::internalError) preparationFailed = true;
                    std::lock_guard lock(mutex_);
                    if (!task->cancelled) rejectTask(error.reason, error.what());
                } catch (...) {
                    const auto error = winrt::to_message();
                    OutputDebugStringW(error.c_str());
                    preparationFailed = true;
                    std::lock_guard lock(mutex_);
                    if (!task->cancelled) rejectTask(task->binding ? AuthenticationFailure::storageFailed : AuthenticationFailure::internalError, winrt::to_string(error));
                }
                if (connection) {
                    try { connection->endRequest(); }
                    catch (...) {
                        const auto error = winrt::to_string(winrt::to_message());
                        {
                            std::lock_guard lock(mutex_);
                            appendDiagnostic("BLE request cleanup failed: " + error);
                            if ((!task->binding || managementStatus_.stage != AuthenticationStage::completed) &&
                                (task->binding ? managementStatus_ : authenticationStatus_).stage != AuthenticationStage::failed)
                                rejectTask(AuthenticationFailure::protectedOperationFailed, error);
                        }
                        closeRetained();
                    }
                    if (retained && (preparationFailed || !retained->healthy())) {
                        retained->close();
                        retained.reset();
                        preparationFailed = true;
                    }
                }
                {
                    std::lock_guard lock(mutex_);
                    task->connection.reset();
                    task_.reset();
                }
            }
        } catch (...) {
            OutputDebugStringW(winrt::to_message().c_str());
            gPipeFailed = true;
            gStopping = true;
            stopPipe();
        }
    }
    bool verifiedManagementIdentity(const Console& console) {
        std::wstring targetSid;
        if (console.locked || FAILED(unlock::components::readSetupTargetSid(targetSid)) || targetSid != console.sid)
            return false;
        const auto generation = gIdentityGeneration.load();
        auto identity = consoleIdentity(console);
        const auto current = currentConsole();
        if (current.locked || current.session != console.session || current.sid != console.sid ||
            current.logonId.LowPart != console.logonId.LowPart || current.logonId.HighPart != console.logonId.HighPart ||
            generation != gIdentityGeneration.load()) return false;
        if (!provisioning_ || !sameIdentity(provisioning_->identity, identity)) snapshot_.reset();
        provisioning_ = ProvisioningIdentity{std::move(identity), console.session, generation, console.logonId};
        return true;
    }

    bool refreshManagementSnapshot(const Console& console) {
        if (!verifiedManagementIdentity(console)) return false;
        provisioning_->logonId = console.logonId;
        if (!freshSnapshot(console) || !sameIdentity(snapshot_->identity, provisioning_->identity)) {
            Snapshot snapshot{provisioning_->identity, console.session, GetTickCount64() + kSnapshotLifetimeMs, {}};
            if (BCryptGenRandom(nullptr, snapshot.nonce.data(), kNonceSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
                fail("saved credential management snapshot RNG failed");
            snapshot_ = std::move(snapshot);
        }
        return freshSnapshot(console);
    }

    bool freshSnapshot(const Console& console) const {
        return snapshot_ && provisioning_ && provisioning_->logonId &&
            provisioning_->session == console.session && provisioning_->generation == gIdentityGeneration.load() &&
            provisioning_->logonId->LowPart == console.logonId.LowPart &&
            provisioning_->logonId->HighPart == console.logonId.HighPart &&
            sameIdentity(snapshot_->identity, provisioning_->identity) && snapshot_->session == console.session &&
            snapshot_->identity.sid == console.sid && GetTickCount64() < snapshot_->expiresAt;
    }

    Vault vault_;
    unlock_windows::system_ble::EnrollmentStore enrollmentStore_;
    std::optional<Snapshot> snapshot_;
    std::optional<ProvisioningIdentity> provisioning_;
    std::optional<Grant> grant_;
    LastUnlockHistory unlockHistory_;
    Handle unlockProcess_;
    std::shared_ptr<BleTask> task_;
    AuthenticationStatus managementStatus_;
    std::string diagnostic_;
    std::wstring diagnosticSid_;
    std::optional<Identity> authenticationIdentity_;
    AuthenticationStatus authenticationStatus_;
    std::mutex mutex_;
    bool removing_ = false;
    bool stopping_ = false;
    std::condition_variable wake_;
    std::thread worker_;
};

void reportServiceState(const DWORD state, const DWORD error = NO_ERROR) {
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwControlsAccepted = state == SERVICE_RUNNING
        ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_POWEREVENT : 0;
    gStatus.dwWin32ExitCode = error;
    gStatus.dwWaitHint = state == SERVICE_STOP_PENDING ? 5000 : 0;
    SetServiceStatus(gStatusHandle, &gStatus);
}

void stopPipe() {
    if (!SetEvent(gPipeStopEvent)) {
        gPipeFailed = true;
        const auto message = L"saved credential pipe stop event failed; win32=" + std::to_wstring(GetLastError());
        OutputDebugStringW(message.c_str());
    }
}

DWORD WINAPI serviceControl(const DWORD control, const DWORD eventType, void* eventData, void*) {
    if (control == SERVICE_CONTROL_STOP) {
        gStopping = true;
        reportServiceState(SERVICE_STOP_PENDING);
        stopPipe();

        return NO_ERROR;
    }
    if (control == SERVICE_CONTROL_POWEREVENT) {
        ++gConsoleGeneration;
        if (eventType == PBT_APMSUSPEND) { gSuspended = true; ++gConnectionGeneration; }
        else if (eventType == PBT_APMRESUMEAUTOMATIC || eventType == PBT_APMRESUMESUSPEND || eventType == PBT_APMRESUMECRITICAL) {
            gSuspended = false;
            ++gConnectionGeneration;
        }
        return NO_ERROR;
    }
    if (control == SERVICE_CONTROL_SESSIONCHANGE) {
        const auto* notification = static_cast<const WTSSESSION_NOTIFICATION*>(eventData);
        if (notification != nullptr && isObservedConsoleEvent(notification->dwSessionId, gObservedConsoleSession.load()) &&
            (eventType == WTS_SESSION_LOCK || eventType == WTS_SESSION_UNLOCK || eventType == WTS_SESSION_LOGON || eventType == WTS_SESSION_LOGOFF ||
            eventType == WTS_CONSOLE_CONNECT ||
            eventType == WTS_CONSOLE_DISCONNECT || eventType == WTS_REMOTE_DISCONNECT)) {
            ++gConsoleGeneration;
            if (eventType != WTS_SESSION_UNLOCK) ++gIdentityGeneration;
            if (eventType != WTS_SESSION_LOCK && eventType != WTS_SESSION_UNLOCK) {
                ++gConnectionGeneration;
                ++gUnlockHistoryGeneration;
            }
        }
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void servePipe(const HANDLE pipe, Handler& handler) {
    const auto reportIoFailure = [](const wchar_t* stage) {
        const auto message = std::wstring(L"saved credential pipe ") + stage + L" failed; win32=" +
            std::to_wstring(GetLastError()) + L"\n";
        OutputDebugStringW(message.c_str());
    };
    while (!gStopping) {
        if (!connectPipe(pipe, gPipeStopEvent)) {
            const DWORD error = GetLastError();
            reportIoFailure(L"connect");
            if (!gStopping && (error == ERROR_NO_DATA || error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED)) {
                if (!DisconnectNamedPipe(pipe) && GetLastError() != ERROR_PIPE_NOT_CONNECTED)
                    fail("saved credential abandoned connection disconnect failed");
                continue;
            }
            if (!gStopping) gPipeFailed = true;
            gStopping = true;
            return;
        }
        const PipeIoContext context{GetTickCount64() + kPipeTransferLifetimeMs, gPipeStopEvent};
        if (!gStopping) {
            Packet request;
            if (!readPacket(pipe, request, context)) {
                reportIoFailure(L"request read");
            } else if (request.result != Result::success) {
                SetLastError(ERROR_INVALID_DATA);
                reportIoFailure(L"request validation");
            } else if (!gStopping) {
                auto response = handler.process(pipe, request);
                if (!writePacket(pipe, response, context)) {
                    reportIoFailure(L"response write");
                } else if (!awaitReplyAcknowledgment(pipe, request.operation, context)) {
                    reportIoFailure(L"reply acknowledgment");
                }
            }
        }
        if (!DisconnectNamedPipe(pipe)) {
            const DWORD error = GetLastError();
            reportIoFailure(L"disconnect");
            if (error != ERROR_PIPE_NOT_CONNECTED) fail("saved credential pipe disconnect failed");
        }
    }
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, serviceControl, nullptr);
    if (gStatusHandle == nullptr) return;
    reportServiceState(SERVICE_START_PENDING);
    try {
        {
            Handler handler;
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    L"D:P(A;;GA;;;SY)(A;;0x0012019B;;;AU)", SDDL_REVISION_1,
                    &descriptor, nullptr)) fail("saved credential pipe ACL creation failed");
            SECURITY_ATTRIBUTES attributes{};
            attributes.nLength = sizeof(attributes);
            attributes.lpSecurityDescriptor = descriptor;
            const HANDLE rawPipe = CreateNamedPipeW(kPipeName,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1, kMaxPacket + 16, kMaxPacket + 16, 0, &attributes);
            LocalFree(descriptor);
            Handle pipe(rawPipe);
            if (pipe.value == INVALID_HANDLE_VALUE) fail("saved credential pipe creation failed");
            reportServiceState(SERVICE_RUNNING);
            servePipe(pipe.value, handler);
            gStopping = true;
        }
        reportServiceState(SERVICE_STOPPED,
            gPipeFailed.load() ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR);
    } catch (...) {
        OutputDebugStringW(winrt::to_message().c_str());
        reportServiceState(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    }
}

} // namespace

int wmain() {
    Handle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent.value) {
        const auto message = L"saved credential pipe stop event creation failed; win32=" + std::to_wstring(GetLastError());
        OutputDebugStringW(message.c_str());
        return 1;
    }
    gPipeStopEvent = stopEvent.value;
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceName), serviceMain}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : 1;
}
