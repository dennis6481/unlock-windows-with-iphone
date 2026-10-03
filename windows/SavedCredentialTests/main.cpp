// Created by Rui MA on 30 Sep 2026

#include "../SavedCredential/SavedCredentialIpc.h"

#include <cstdlib>
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
        decoded.credentialPresent, "status round trip changed data");
    bytes.value[kNonceSize] = 2;
    require(!decodeStatus(bytes.value.data(), bytes.value.size(), decoded), "invalid present flag must fail");
}

void testPhoneEndpointRejectsCredentialOperations() {
    Packet reply;
    require(!callPhone(Operation::claimCredential, SensitiveBytes{}, reply),
        "phone endpoint must not expose credential claims");
    require(GetLastError() == ERROR_INVALID_PARAMETER,
        "phone endpoint operation rejection must be local and explicit");
    CallDiagnostics diagnostics;
    require(!callPhone(Operation::beginPhoneAuthentication, SensitiveBytes{}, reply, 250, &diagnostics) &&
        GetLastError() == ERROR_INVALID_PARAMETER && diagnostics.stage == CallStage::requestValidation,
        "phone endpoint must not initiate authentication without a LogonUI click");
    require(!callPhone(Operation::phoneAuthenticationStatus, SensitiveBytes{}, reply) &&
        GetLastError() == ERROR_INVALID_PARAMETER,
        "phone endpoint must not expose LogonUI authentication status");
    require(!callPhone(Operation::takeAutoSubmitOffer, SensitiveBytes{}, reply) &&
        GetLastError() == ERROR_INVALID_PARAMETER,
        "phone endpoint must not expose automatic submission offers");
}

void testAuthenticationOperationPackets() {
    for (const std::uint16_t operation : {std::uint16_t{12}, std::uint16_t{6},
            std::uint16_t{9}, std::uint16_t{13}, std::uint16_t{14}, std::uint16_t{15},
            std::uint16_t{16}, std::uint16_t{0}, std::uint16_t{65535}}) {
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
        const bool known = operation == 9 || (operation >= 12 && operation <= 16);
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

void testPacketTransportParity() {
    const auto name = L"\\\\.\\pipe\\unlock-packet-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    const HANDLE server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, kMaxPacket, kMaxPacket, 0, nullptr);
    require(server != INVALID_HANDLE_VALUE, "packet test server must open");
    const HANDLE client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, nullptr);
    require(client != INVALID_HANDLE_VALUE, "overlapped packet test client must open");
    require(ConnectNamedPipe(server, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED, "test pipe must connect");
    for (auto operation : {std::uint16_t{9}, std::uint16_t{12}, std::uint16_t{6}, std::uint16_t{65535}}) {
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

void testAuthenticationState() {
    AuthenticationStatus status{"01234567-89ab-cdef-0123-456789abcdef",
        AuthenticationStage::waitingPhone, AuthenticationFailure::none, 30'000};
    SensitiveBytes bytes;
    AuthenticationStatus decoded;
    require(encodeAuthenticationStatus(status, bytes) &&
        decodeAuthenticationStatus(bytes.value.data(), bytes.value.size(), decoded) &&
        decoded.requestId == status.requestId && decoded.deadline == status.deadline &&
        decoded.stage == status.stage, "structured authentication status round trip failed");
    require(authenticationExpiry(29'999, 30'000, true, true) == AuthenticationFailure::none,
        "request expired before the service deadline");
    require(authenticationExpiry(30'000, 30'000, true, true) == AuthenticationFailure::expired,
        "deadline boundary must expire without reporting a session change");
    require(authenticationExpiry(1, 30'000, false, true) == AuthenticationFailure::sessionChanged &&
        authenticationExpiry(1, 30'000, true, false) == AuthenticationFailure::sessionChanged,
        "real console or lock state change must invalidate authentication");
    require(!isObservedConsoleEvent(2, 1) && !isObservedConsoleEvent(1, 0xffffffff) &&
        isObservedConsoleEvent(1, 1), "unrelated session notifications must not invalidate console requests");
    bytes.value[1] = 255;
    require(!decodeAuthenticationStatus(bytes.value.data(), bytes.value.size(), decoded),
        "unknown authentication stage must be rejected");
    status.stage = AuthenticationStage::failed;
    status.failure = AuthenticationFailure::rssiTooLow;
    require(encodeAuthenticationStatus(status, bytes), "RSSI failure should encode");
    require(std::wstring(authenticationStatusText(status)) == L"Move your iPhone closer and try again.",
        "distance rejection must use an actionable message without RSSI jargon");
    status.failure = AuthenticationFailure::none;
    require(!encodeAuthenticationStatus(status, bytes), "failed stage requires an explicit reason");
    status.stage = AuthenticationStage::awaitingAssertion;
    PhoneChallengePayload challenge{status, "{\"version\":1}"};
    PhoneChallengePayload decodedChallenge;
    require(encodePhoneChallenge(challenge, bytes) &&
        decodePhoneChallenge(bytes.value.data(), bytes.value.size(), decodedChallenge) &&
        decodedChallenge.status.deadline == status.deadline && decodedChallenge.json == challenge.json,
        "queued challenge must preserve the authoritative deadline");
    bytes.value.push_back(0);
    require(!decodePhoneChallenge(bytes.value.data(), bytes.value.size(), decodedChallenge),
        "challenge framing must reject trailing data");
    Packet reply;
    require(!callPhone(Operation::unlockEligibility, SensitiveBytes{}, reply),
        "transport must not expose unlock eligibility");
    require(encodeAuthenticationStatus({}, bytes) &&
        decodeAuthenticationStatus(bytes.value.data(), bytes.value.size(), decoded), "idle status must round trip");
    bytes.value[47] = 1;
    require(!decodeAuthenticationStatus(bytes.value.data(), bytes.value.size(), decoded), "idle padding must be canonical");
    HANDLE reader = INVALID_HANDLE_VALUE;
    HANDLE writer = INVALID_HANDLE_VALUE;
    require(CreatePipe(&reader, &writer, nullptr, 0) != FALSE, "legacy packet test pipe must open");
    const std::array<std::uint8_t, 16> oldHeader{0x47, 0x43, 0x43, 0x31, 1, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    DWORD written = 0;
    require(WriteFile(writer, oldHeader.data(), static_cast<DWORD>(oldHeader.size()), &written, nullptr) &&
        written == oldHeader.size(), "legacy packet header must write");
    require(!readPacket(reader, reply) && GetLastError() == ERROR_INVALID_DATA, "old IPC version must not be silently accepted");
    require(CloseHandle(reader) && CloseHandle(writer), "legacy packet pipe handles must close");
}

void testAuthenticationMessages() {
    struct Message { AuthenticationFailure failure; const wchar_t* text; };
    const Message failures[]{
        {AuthenticationFailure::rssiTooLow, L"Move your iPhone closer and try again."},
        {AuthenticationFailure::automaticDisabled, L"Enable automatic approval in the iPhone app."},
        {AuthenticationFailure::rssiUnavailable, L"Couldn't check your iPhone's proximity. Try again."},
        {AuthenticationFailure::subscriptionLost, L"Connection to your iPhone was interrupted. Try again."},
        {AuthenticationFailure::deliveryFailed, L"Couldn't send the request to your iPhone. Try again."},
        {AuthenticationFailure::signingFailed, L"Couldn't verify approval from your iPhone. Try again."},
        {AuthenticationFailure::expired, L"Your iPhone didn't respond in time. Try again."},
        {AuthenticationFailure::sessionChanged, L"Your Windows session changed. Start again."},
        {AuthenticationFailure::invalidAssertion, L"Couldn't verify approval from your iPhone. Try again."},
    };
    for (const auto& item : failures) {
        AuthenticationStatus status{"01234567-89ab-cdef-0123-456789abcdef",
            AuthenticationStage::failed, item.failure, 30'000};
        const auto before = status;
        const std::wstring text(authenticationStatusText(status));
        require(text == item.text, "authentication failure lost its user-facing message");
        require(text.find(L"RSSI") == std::wstring::npos && text.find(L"assertion") == std::wstring::npos &&
            text.find(L"subscription") == std::wstring::npos, "technical protocol terms leaked into the lock screen");
        require(status.stage == before.stage && status.failure == before.failure &&
            status.deadline == before.deadline && status.requestId == before.requestId,
            "presentation must not change the authentication state");
    }
    AuthenticationStatus status{};
    require(std::wstring(authenticationStatusText(status)) == L"Unlock with iPhone\u00ae", "idle title lost the registered mark");
    status.stage = AuthenticationStage::waitingPhone;
    require(std::wstring(authenticationStatusText(status)) == L"Waiting for your iPhone\u2026", "connection waiting message changed");
    status.stage = AuthenticationStage::awaitingAssertion;
    require(std::wstring(authenticationStatusText(status)) == L"Waiting for approval from your iPhone\u2026", "approval waiting message changed");
    status.stage = AuthenticationStage::approved;
    require(std::wstring(authenticationStatusText(status)).find(L"Unlocking") != std::wstring::npos &&
        std::wstring(authenticationStatusText(status)).find(L"unlocked") == std::wstring::npos,
        "phone approval must not claim that Windows is already unlocked");
    status.stage = AuthenticationStage::consumed;
    require(std::wstring(authenticationStatusText(status)).find(L"already been used") != std::wstring::npos,
        "consumed approval must ask for a new request");
}

} // namespace

int main() {
    testIdentityRoundTrip();
    testStatusRoundTrip();
    testPhoneEndpointRejectsCredentialOperations();
    testPacketTransportParity();
    testAutoSubmitOffer();
    testAuthenticationOperationPackets();
    testAuthenticationState();
    testAuthenticationMessages();
    std::cout << "Saved credential protocol tests passed.\n";
    return EXIT_SUCCESS;
}
