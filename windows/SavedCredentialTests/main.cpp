// Created by Rui MA on 30 Sep 2026

#include "../SavedCredential/SavedCredentialIpc.h"
#include "../DesktopApp/DesktopApp.h"
#include "../Bluetooth/PresenceAuthorization.h"

#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <string>

using namespace unlock_windows::saved_credential;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

void testIdentityRoundTrip() {
    Identity identity{L"S-1-5-21-100-200-300-1001", L"MicrosoftAccount\\user@example.com",
        {0x12345678, 0xabcd, 0x4567, {1, 2, 3, 4, 5, 6, 7, 8}}};
    SensitiveBytes bytes;
    require(encodeIdentity(identity, bytes), "identity should encode");
    Identity decoded;
    require(decodeIdentity(bytes.value.data(), bytes.value.size(), decoded), "identity should decode");
    require(decoded.sid == identity.sid && decoded.qualifiedUserName == identity.qualifiedUserName &&
        IsEqualGUID(decoded.providerId, identity.providerId), "identity round trip changed data");
    bytes.value.push_back(0);
    require(!decodeIdentity(bytes.value.data(), bytes.value.size(), decoded), "trailing data must be rejected");
}

void testStatusRoundTrip() {
    StatusPayload status;
    status.identity = {L"S-1-5-21-1-2-3-4", L"Windows-provided-name", GUID{}};
    status.snapshotNonce[0] = 42;
    status.credentialPresent = true;
    SensitiveBytes bytes;
    require(encodeStatus(status, bytes), "status should encode");
    StatusPayload decoded;
    require(decodeStatus(bytes.value.data(), bytes.value.size(), decoded), "status should decode");
    require(decoded.identity.sid == status.identity.sid && decoded.snapshotNonce == status.snapshotNonce &&
        decoded.credentialPresent && !decoded.credentialMatches, "status round trip changed data");
    status.credentialMatches = true;
    require(encodeStatus(status, bytes) && decodeStatus(bytes.value.data(), bytes.value.size(), decoded) &&
        decoded.credentialPresent && decoded.credentialMatches, "matching identity readiness must survive transport");
    bytes.value[kNonceSize] = 2;
    require(!decodeStatus(bytes.value.data(), bytes.value.size(), decoded), "matching without a saved copy must fail");
    bytes.value[kNonceSize] = 4;
    require(!decodeStatus(bytes.value.data(), bytes.value.size(), decoded), "unknown credential state must fail");
    status.credentialPresent = false;
    require(!encodeStatus(status, bytes), "encoder must reject matching identity without a saved copy");
}


void testCredentialSummary() {
    CredentialSummary summary{{L"S-1-5-21-1-2-3-4", L"MicrosoftAccount\\user@example.invalid", GUID{}}, true, true};
    SensitiveBytes bytes;
    require(encodeCredentialSummary(summary, bytes), "credential summary must encode");
    CredentialSummary decoded;
    require(decodeCredentialSummary(bytes.value.data(), bytes.value.size(), decoded) &&
        decoded.identity.sid == summary.identity.sid && decoded.identity.qualifiedUserName == summary.identity.qualifiedUserName &&
        decoded.credentialPresent && decoded.credentialMatches, "summary must preserve verified identity and state");
    StatusPayload status{summary, {}};
    status.snapshotNonce.fill(42);
    SensitiveBytes management;
    require(encodeStatus(status, management) && management.value.size() == bytes.value.size() + kNonceSize &&
        std::equal(bytes.value.begin(), bytes.value.end(), management.value.begin() + kNonceSize),
        "summary must reuse the existing management encoding without its nonce");
    require(!decodeStatus(bytes.value.data(), bytes.value.size(), status), "summary must not be a management snapshot");
    require(!decodeCredentialSummary(nullptr, 0, decoded) &&
        !decodeCredentialSummary(bytes.value.data(), bytes.value.size() - 1, decoded), "empty and truncated summary must fail");
    bytes.value.push_back(0);
    require(!decodeCredentialSummary(bytes.value.data(), bytes.value.size(), decoded), "summary must reject trailing data");
    bytes.value.pop_back();
    bytes.value[0] = 2;
    require(!decodeCredentialSummary(bytes.value.data(), bytes.value.size(), decoded), "matching without a saved copy must fail");
    bytes.value[0] = 4;
    require(!decodeCredentialSummary(bytes.value.data(), bytes.value.size(), decoded), "unknown summary flags must fail");
    summary.credentialPresent = false;
    require(!encodeCredentialSummary(summary, bytes), "summary encoder must reject matching without presence");
    summary.credentialMatches = false;
    require(encodeCredentialSummary(summary, bytes) && decodeCredentialSummary(bytes.value.data(), bytes.value.size(), decoded) &&
        !decoded.credentialPresent && !decoded.credentialMatches, "absent credential state must round trip");
}

void testAuthenticationOperationPackets() {
    for (const std::uint16_t operation : {std::uint16_t{12}, std::uint16_t{6},
            std::uint16_t{9}, std::uint16_t{13}, std::uint16_t{14}, std::uint16_t{15},
            std::uint16_t{16}, std::uint16_t{17}, std::uint16_t{18}, std::uint16_t{19}, std::uint16_t{20}, std::uint16_t{26}, std::uint16_t{0}, std::uint16_t{65535}}) {
        HANDLE reader = INVALID_HANDLE_VALUE;
        HANDLE writer = INVALID_HANDLE_VALUE;
        require(CreatePipe(&reader, &writer, nullptr, 0) != FALSE, "test pipe must open");
        Packet outbound;
        outbound.operation = static_cast<Operation>(operation);
        outbound.payload.value = {17, 91};
        require(writePacket(writer, outbound), "test operation packet must write");
        Packet inbound;
        const bool accepted = readPacket(reader, inbound);
        const DWORD error = GetLastError();
        require(CloseHandle(writer) && CloseHandle(reader), "test pipe handles must close");
        const bool known = operation == 9 || operation == 12 || operation == 15 || operation == 16 || (operation >= 18 && operation <= 26);
        require(isKnownOperation(operation) == known, "operation whitelist rejected new operation or accepted unknown operation");
        require(accepted == known, "packet parser must accept authentication operations and reject unknown operations");
        if (accepted) {
            require(inbound.operation == outbound.operation && inbound.payload.value == outbound.payload.value,
                "authentication operation packet changed in transit");
        } else {
            require(error == ERROR_INVALID_DATA, "invalid packet operation must report invalid data explicitly");
        }
    }
}

void testSetupLaunchArguments() {
    using namespace unlock_windows::desktop_app;
    wchar_t executable[] = L"UnlockWithIPhone.exe";
    std::wstring setup(kSetupRole), password(kSavedPasswordRole);
    wchar_t* trayArguments[]{executable, setup.data()};
    require(parseLaunch(2, trayArguments).role == Role::setup, "setup must enter the ordinary tray role");
    wchar_t* passwordArguments[]{executable, password.data(), setup.data()};
    const auto launch = parseLaunch(3, passwordArguments);
    require(launch.role == Role::savedPassword && launch.setup, "setup must reuse the elevated password role");
    for (const auto operation : {Operation::setCredential, Operation::updateCredential, Operation::clearCredential}) {
        std::wstring option(passwordOperationArgument(operation));
        wchar_t* arguments[]{executable, password.data(), option.data()};
        const auto action = parseLaunch(3, arguments);
        require(action.role == Role::savedPassword && !action.setup && action.passwordOperation == operation,
            "password action must enter the matching elevated UI role");
        wchar_t* mixed[]{executable, password.data(), setup.data(), option.data()};
        bool mixedRejected = false;
        try { static_cast<void>(parseLaunch(4, mixed)); }
        catch (const std::invalid_argument&) { mixedRejected = true; }
        require(mixedRejected, "setup and explicit password actions must not be combined");
    }
    wchar_t* conflicting[]{executable, setup.data(), password.data()};
    bool rejected = false;
    try { static_cast<void>(parseLaunch(3, conflicting)); }
    catch (const std::invalid_argument&) { rejected = true; }
    require(rejected, "conflicting ordinary/elevated role arguments must be rejected");
}

void testProvisioningIdentityTransport() {
    const Identity identity{L"S-1-5-21-100-200-300-1001", L"MicrosoftAccount\\setup@example.invalid",
        {0x12345678, 0x1234, 0x5678, {1, 2, 3, 4, 5, 6, 7, 8}}};
    Packet request;
    request.operation = Operation::captureProvisioningIdentity;
    require(encodeIdentity(identity, request.payload), "provisioning must preserve a system identity");
    Identity decoded;
    require(decodeIdentity(request.payload.value.data(), request.payload.value.size(), decoded) &&
        decoded.sid == identity.sid && decoded.qualifiedUserName == identity.qualifiedUserName &&
        IsEqualGUID(decoded.providerId, identity.providerId), "provisioning must not reconstruct or discard online identity fields");
}

void testPacketTransportParity() {
    const auto name = L"\\\\.\\pipe\\unlock-packet-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    const HANDLE server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, kMaxPacket, kMaxPacket, 0, nullptr);
    require(server != INVALID_HANDLE_VALUE, "packet test server must open");
    const HANDLE client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, nullptr);
    require(client != INVALID_HANDLE_VALUE, "overlapped packet test client must open");
    require(ConnectNamedPipe(server, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED, "test pipe must connect");
    for (auto operation : {std::uint16_t{9}, std::uint16_t{12}, std::uint16_t{17}, std::uint16_t{18}, std::uint16_t{19}, std::uint16_t{6}, std::uint16_t{65535}}) {
        Packet outbound;
        outbound.operation = static_cast<Operation>(operation);
        outbound.payload.value = {17, 91};
        require(writePacket(server, outbound), "synchronous writer must write");
        Packet inbound;
        const bool timedAccepted = readPacket(client, inbound, 250);
        const DWORD timedError = GetLastError();
        if (!timedAccepted) {
            std::uint8_t discarded[2]{};
            OVERLAPPED pending{};
            pending.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            require(pending.hEvent != nullptr, "drain event must open");
            DWORD read = 0;
            const BOOL started = ReadFile(client, discarded, sizeof(discarded), &read, &pending);
            require(started || (GetLastError() == ERROR_IO_PENDING && GetOverlappedResult(client, &pending, &read, TRUE)), "reject payload must drain");
            require(read == sizeof(discarded) && CloseHandle(pending.hEvent), "reject drain must complete");
        }
        require(writePacket(client, outbound, 250), "timed writer must write");
        Packet synchronous;
        const bool syncAccepted = readPacket(server, synchronous);
        const DWORD syncError = GetLastError();
        if (!syncAccepted) {
            std::uint8_t discarded[2]{};
            DWORD read = 0;
            require(ReadFile(server, discarded, sizeof(discarded), &read, nullptr) && read == sizeof(discarded), "reject payload must drain");
        }
        require(timedAccepted == isKnownOperation(operation) && syncAccepted == timedAccepted,
            "timed and synchronous packet validation disagree");
        if (timedAccepted) {
            require(inbound.operation == outbound.operation && synchronous.operation == outbound.operation &&
                inbound.payload.value == outbound.payload.value && synchronous.payload.value == outbound.payload.value,
                "packet codec round-trip mismatch");
        } else require(timedError == ERROR_INVALID_DATA && syncError == ERROR_INVALID_DATA,
            "both transports must report the same rejection");
    }
    require(CloseHandle(client) && CloseHandle(server), "packet test handles must close");
}

void testAutoSubmitOffer() {
    AutoSubmitOffer offer;
    offer.nonce[0] = 17;
    offer.nonce[kNonceSize - 1] = 91;
    offer.expiresAt = 0x123456789abcdef0ULL;
    SensitiveBytes bytes;
    require(encodeAutoSubmitOffer(offer, bytes), "automatic submission offer must encode");
    AutoSubmitOffer decoded;
    require(decodeAutoSubmitOffer(bytes.value.data(), bytes.value.size(), decoded) &&
        decoded.nonce == offer.nonce && decoded.expiresAt == offer.expiresAt,
        "automatic submission offer lost its grant identity or deadline");
    require(!decodeAutoSubmitOffer(bytes.value.data(), bytes.value.size() - 1, decoded),
        "truncated automatic submission offer must fail");
    bytes.value.push_back(0);
    require(!decodeAutoSubmitOffer(bytes.value.data(), bytes.value.size(), decoded),
        "automatic submission offer must reject trailing data");
    offer.expiresAt = 0;
    require(!encodeAutoSubmitOffer(offer, bytes), "an offer must have an expiration");
}


} // namespace

void testPresenceContracts() {
    using namespace unlock_windows::system_ble;
    require(kProtocolVersion == 3, "only IPC v3 is supported");
    for (const auto removed : {10, 11, 13, 14, 17}) require(!isKnownOperation(static_cast<std::uint16_t>(removed)), "old phone operation must be unknown");
    for (auto operation : {Operation::claimCredential, Operation::beginVerification, Operation::takeAutoSubmitOffer,
            Operation::captureIdentity, Operation::captureProvisioningIdentity, Operation::verificationStatus})
        require(requiresLogonUi(operation), "desktop must not reach LogonUI operations");
    require(!requiresLogonUi(Operation::bindingStatus), "non-sensitive binding status must remain separate");
    BindingRecord record{L"S-1-5-21-1-2-3-1001", L"classic-id", L"ble-id",
        winrt::guid{L"01234567-89ab-cdef-0123-456789abcdef"}, L"Same name", kDefaultThreshold};
    SensitiveBytes bytes;
    BindingRecord decoded;
    require(encodeBinding(record, bytes) && decodeBinding(bytes.value.data(), bytes.value.size(), decoded) && decoded == record,
        "binding codec must preserve SID, both IDs, container, display text and threshold");
    for (std::size_t size = 0; size < bytes.value.size(); ++size)
        require(!decodeBinding(bytes.value.data(), size, decoded), "all truncated binding packets must fail");
    bytes.value.push_back(0);
    require(!decodeBinding(bytes.value.data(), bytes.value.size(), decoded), "binding trailing data must fail");
    record.threshold = kMinimumThreshold - 1;
    require(!encodeBinding(record, bytes), "threshold below range must fail");
    record.threshold = kMaximumThreshold + 1;
    require(!encodeBinding(record, bytes), "threshold above range must fail");
    record.threshold = kDefaultThreshold;
    BindingChange change{{BindingState::rebindRequired, {}}, record, L"Global\\test-cancellation"};
    BindingChange restored;
    require(encodeBindingChange(change, bytes) && decodeBindingChange(bytes.value.data(), bytes.value.size(), restored) &&
        restored.expected == change.expected && restored.candidate == change.candidate && restored.cancelEvent == change.cancelEvent,
        "management request must preserve the expected record and cancellation event");
    bytes.value[0] = 255;
    require(!decodeBindingChange(bytes.value.data(), bytes.value.size(), restored), "malformed expected-length must fail");
    BindingRemoval removal{{BindingState::bound, record}, L"Global\\test-cancellation"};
    BindingRemoval removed;
    require(encodeBindingRemoval(removal, bytes) && decodeBindingRemoval(bytes.value.data(), bytes.value.size(), removed) &&
        removed.expected == removal.expected && removed.cancelEvent == removal.cancelEvent, "removal must bind its expected state and cancellation");
    require(!decodeBindingRemoval(bytes.value.data(), bytes.value.size() - 1, removed), "truncated removal must fail");
    for (auto state : {BindingState::absent, BindingState::rebindRequired}) {
        BindingSummary summary{state, {}};
        BindingSummary read;
        require(encodeBindingSummary(summary, bytes) && decodeBindingSummary(bytes.value.data(), bytes.value.size(), read) && read == summary,
            "unbound and rebind-required must remain distinct");
    }
    AuthenticationStatus status{"01234567-89ab-cdef-0123-456789abcdef", AuthenticationStage::verifying, AuthenticationFailure::none, 30'000};
    AuthenticationStatus parsed;
    require(encodeAuthenticationStatus(status, bytes) && decodeAuthenticationStatus(bytes.value.data(), bytes.value.size(), parsed) &&
        parsed.requestId == status.requestId && parsed.deadline == status.deadline && parsed.stage == status.stage, "request status must round trip");
    bytes.value[1] = 255;
    require(!decodeAuthenticationStatus(bytes.value.data(), bytes.value.size(), parsed), "unknown state must fail");
    status.stage = AuthenticationStage::failed;
    require(!encodeAuthenticationStatus(status, bytes), "failed state must have a reason");
    status.failure = AuthenticationFailure::expired;
    require(encodeAuthenticationStatus(status, bytes), "timeout reason must encode");
    require(authenticationExpiry(30'000, 30'000, true, true) == AuthenticationFailure::expired &&
        authenticationExpiry(1, 30'000, false, true) == AuthenticationFailure::sessionChanged &&
        authenticationExpiry(1, 30'000, true, false) == AuthenticationFailure::sessionChanged, "deadline and console boundary must reject");
    const Evidence fresh{Failure::none, 10'000, 10'000, kDefaultThreshold};
    PresenceAuthorization oneTime;
    require(!oneTime.consume(false, fresh, 9'000, 10'001, 39'000, kDefaultThreshold), "wrong request/registration/connection/account/session context must reject");
    require(oneTime.consume(true, fresh, 9'000, 10'001, 39'000, kDefaultThreshold), "current evidence at threshold must authorize once");
    require(!oneTime.consume(true, fresh, 9'000, 10'002, 39'000, kDefaultThreshold), "duplicate credential claim must reject");
    for (auto proof : {Evidence{Failure::none, 8'999, 10'000, -50}, Evidence{Failure::none, 10'000, 8'999, -50},
            Evidence{Failure::none, 10'000, 0, -50}, Evidence{Failure::none, 10'000, 10'000, kDefaultThreshold - 1},
            Evidence{Failure::connectionLost, 10'000, 10'000, -50}}) {
        PresenceAuthorization rejected;
        require(!rejected.consume(true, proof, 9'000, 10'001, 39'000, kDefaultThreshold), "cached, missing, low or disconnected evidence must reject");
    }
    PresenceAuthorization expired;
    require(!expired.consume(true, fresh, 9'000, 13'001, 39'000, kDefaultThreshold), "communication and RSSI older than three seconds must reject");
    require(!expired.consume(true, fresh, 9'000, 10'001, 10'001, kDefaultThreshold), "request deadline must not extend");
    require(!freshEvidence(10'002, 9'000, 10'001), "future/late evidence must reject");
    require(!freshEvidence(0, 0, 1), "missing evidence must reject even at the clock origin");
    HANDLE reader = INVALID_HANDLE_VALUE, writer = INVALID_HANDLE_VALUE;
    require(CreatePipe(&reader, &writer, nullptr, 0), "version rejection pipe must open");
    Packet packet;
    require(writePacket(writer, packet), "canonical version packet must write");
    std::array<std::uint8_t, 16> header{};
    DWORD count = 0;
    require(ReadFile(reader, header.data(), static_cast<DWORD>(header.size()), &count, nullptr) && count == header.size(), "packet header must read");
    header[4] = 2; header[5] = 0;
    require(WriteFile(writer, header.data(), static_cast<DWORD>(header.size()), &count, nullptr) && count == header.size(), "old-version fixture must write");
    require(!readPacket(reader, packet) && GetLastError() == ERROR_INVALID_DATA, "version 2 packet must reject without fallback");
    require(CloseHandle(reader) && CloseHandle(writer), "version fixture handles must close");
}

int main() {
    testIdentityRoundTrip();
    testStatusRoundTrip();
    testCredentialSummary();
    testPacketTransportParity();
    testProvisioningIdentityTransport();
    testSetupLaunchArguments();
    testAutoSubmitOffer();
    testAuthenticationOperationPackets();
    testPresenceContracts();
    std::cout << "Saved credential protocol tests passed.\n";
    return EXIT_SUCCESS;
}
