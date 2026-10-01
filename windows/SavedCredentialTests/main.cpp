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

} // namespace

int main() {
    testIdentityRoundTrip();
    testStatusRoundTrip();
    std::cout << "Saved credential protocol tests passed.\n";
    return EXIT_SUCCESS;
}
