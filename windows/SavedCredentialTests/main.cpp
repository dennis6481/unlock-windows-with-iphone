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
        const bool known = operation == 9 || (operation >= 12 && operation <= 15);
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

int main() {
    testIdentityRoundTrip();
    testStatusRoundTrip();
    testPhoneEndpointRejectsCredentialOperations();
    testAutoSubmitOffer();
    testAuthenticationOperationPackets();
    std::cout << "Saved credential protocol tests passed.\n";
    return EXIT_SUCCESS;
}
