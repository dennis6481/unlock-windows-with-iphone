// Created by Rui MA on 30 Sep 2026

#include "../SavedCredential/SavedCredentialIpc.h"
#include "../DesktopApp/DesktopApp.h"
#include "../Bluetooth/PresenceAuthorization.h"
#include "../SavedCredential/LastUnlock.h"
#include "../DesktopApp/Dashboard/Dashboard.h"
#include "../ConsoleSession.h"
#include <winrt/Windows.Foundation.Collections.h>
#include <sddl.h>

#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

using namespace unlock_windows::saved_credential;

namespace {

void require(const bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

PipeIoContext testContext(DWORD milliseconds = kPipeTransferLifetimeMs, HANDLE stopEvent = nullptr) {
    return {GetTickCount64() + milliseconds, stopEvent};
}

struct PipePair final {
    winrt::handle server, client;
    std::wstring name;
    explicit PipePair(bool connected = true) {
        static unsigned sequence = 0;
        name = L"\\\\.\\pipe\\unlock-packet-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++sequence);
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)",
            SDDL_REVISION_1, &descriptor, nullptr), "test pipe owner ACL must be created");
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
        server.attach(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 128, 128, 0, &attributes));
        LocalFree(descriptor);
        require(server.get() != INVALID_HANDLE_VALUE, "overlapped test server must open");
        if (connected) {
            openClient();
            require(connectPipe(server.get(), nullptr), "test connection must complete");
        }
    }
    void openClient() {
        client.attach(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED, nullptr));
        if (client.get() == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            std::wcerr << L"FAILED: overlapped test client must open: " << name << L"; Win32=" << error << L'\n';
            std::exit(EXIT_FAILURE);
        }
    }
    void reconnect() {
        client.close();
        require(DisconnectNamedPipe(server.get()) || GetLastError() == ERROR_PIPE_NOT_CONNECTED,
            "test connection must disconnect");
        std::thread listener([&] {
            require(connectPipe(server.get(), nullptr), "test reconnection must complete");
        });
        require(WaitNamedPipeW(name.c_str(), kPipeTransferLifetimeMs), "test server must listen before reopening the client");
        openClient();
        listener.join();
    }
};

void writeBytes(HANDLE pipe, const std::uint8_t* bytes, DWORD size) {
    winrt::handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(event), "raw writer event must open");
    OVERLAPPED pending{};
    pending.hEvent = event.get();
    DWORD count = 0;
    const auto started = WriteFile(pipe, bytes, size, &count, &pending);
    require(started || GetLastError() == ERROR_IO_PENDING, "raw bytes must start writing");
    const auto wait = WaitForSingleObject(event.get(), kPipeTransferLifetimeMs);
    if (wait != WAIT_OBJECT_0) {
        const auto cancelled = CancelIoEx(pipe, &pending);
        require(cancelled || GetLastError() == ERROR_NOT_FOUND, "raw writer cancellation must finish safely");
        require(GetOverlappedResult(pipe, &pending, &count, TRUE) || GetLastError() == ERROR_OPERATION_ABORTED,
            "raw writer cancellation must be drained");
    }
    require(wait == WAIT_OBJECT_0 && GetOverlappedResult(pipe, &pending, &count, FALSE) && count == size,
        "raw bytes must finish writing");
}

std::vector<std::uint8_t> packetBytes(const Packet& packet) {
    PipePair pipe;
    require(writePacket(pipe.server.get(), packet, testContext()), "fixture must use the product serializer");
    DWORD available = 0;
    require(PeekNamedPipe(pipe.client.get(), nullptr, 0, nullptr, &available, nullptr) && available != 0,
        "serialized fixture must be available");
    std::vector<std::uint8_t> bytes(available);
    winrt::handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(event), "fixture reader event must open");
    OVERLAPPED pending{};
    pending.hEvent = event.get();
    DWORD count = 0;
    const auto started = ReadFile(pipe.client.get(), bytes.data(), available, &count, &pending);
    require(started || GetLastError() == ERROR_IO_PENDING, "fixture must start reading");
    require(WaitForSingleObject(event.get(), kPipeTransferLifetimeMs) == WAIT_OBJECT_0 &&
        GetOverlappedResult(pipe.client.get(), &pending, &count, FALSE) && count == available,
        "fixture must finish reading");
    return bytes;
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
            std::uint16_t{16}, std::uint16_t{17}, std::uint16_t{18}, std::uint16_t{19}, std::uint16_t{20}, std::uint16_t{26},
            std::uint16_t{27}, std::uint16_t{28}, std::uint16_t{29}, std::uint16_t{0}, std::uint16_t{65535}}) {
        PipePair pipe;
        Packet outbound;
        outbound.operation = static_cast<Operation>(operation);
        outbound.payload.value = {17, 91};
        const auto context = testContext();
        require(writePacket(pipe.client.get(), outbound, context), "test operation packet must write");
        Packet inbound;
        const bool accepted = readPacket(pipe.server.get(), inbound, context);
        const DWORD error = GetLastError();
        const bool known = operation == 9 || operation == 12 || operation == 15 || operation == 16 || (operation >= 18 && operation <= 28);
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

void testLastUnlockCodec() {
    require(requiresLogonUi(Operation::reportUnlockResult) && !requiresLogonUi(Operation::lastUnlockStatus),
        "unlock result writes must require LogonUI; history reads must not");
    SensitiveBytes bytes;
    UnlockResult result;
    result.nonce[0] = 91;
    result.status = -1;
    result.substatus = -2;
    require(encodeUnlockResult(result, bytes), "native unlock result must encode");
    UnlockResult decoded;
    require(decodeUnlockResult(bytes.value.data(), bytes.value.size(), decoded) && decoded.nonce == result.nonce &&
        decoded.status == result.status && decoded.substatus == result.substatus, "native result round trip changed data");
    require(!decodeUnlockResult(bytes.value.data(), bytes.value.size() - 1, decoded), "truncated native result must fail");
    bytes.value.push_back(0);
    require(!decodeUnlockResult(bytes.value.data(), bytes.value.size(), decoded), "native result trailing bytes must fail");

    std::optional<LastUnlockSummary> summary = LastUnlockSummary{10000, -58};
    std::optional<LastUnlockSummary> restored;
    require(encodeLastUnlock(summary, bytes) && decodeLastUnlock(bytes.value.data(), bytes.value.size(), restored) &&
        restored && restored->completedAt == summary->completedAt && restored->rssi == -58, "unlock summary must round trip");
    require(!decodeLastUnlock(bytes.value.data(), bytes.value.size() - 1, restored), "truncated history must fail");
    auto invalidTime = bytes.value;
    std::fill_n(invalidTime.begin() + 1, sizeof(ULONGLONG), std::uint8_t{0});
    require(!decodeLastUnlock(invalidTime.data(), invalidTime.size(), restored), "zero time on the wire must fail");
    auto invalidSignal = bytes.value;
    std::fill_n(invalidSignal.begin() + 1 + sizeof(ULONGLONG), sizeof(std::int32_t), std::uint8_t{0});
    require(!decodeLastUnlock(invalidSignal.data(), invalidSignal.size(), restored), "invalid RSSI on the wire must fail");
    bytes.value.push_back(0);
    require(!decodeLastUnlock(bytes.value.data(), bytes.value.size(), restored), "history trailing bytes must fail");
    summary->completedAt = 0;
    require(!encodeLastUnlock(summary, bytes), "zero success time must fail");
    summary = LastUnlockSummary{10000, 0};
    require(!encodeLastUnlock(summary, bytes), "missing RSSI cannot describe a successful unlock");
    summary->rssi = unlock_windows::system_ble::kMinimumThreshold - 1;
    require(!encodeLastUnlock(summary, bytes), "RSSI below every supported threshold cannot describe success");
    require(encodeLastUnlock(std::nullopt, bytes) && decodeLastUnlock(bytes.value.data(), bytes.value.size(), restored) &&
        !restored, "no history must clear a previously populated output");
    bytes.value[0] = 2;
    require(!decodeLastUnlock(bytes.value.data(), bytes.value.size(), restored), "invalid history presence flag must fail");
}

void testLastUnlockHistory() {
    UnlockContext context;
    context.identity = {L"S-1-5-21-1-2-3-4", L"MicrosoftAccount\\user@example.com", GUID{}};
    context.session = 1;
    context.logonId.LowPart = 7;
    context.binding.accountSid = context.identity.sid;
    context.binding.bleId = L"phone-ble";
    context.binding.classicId = L"phone-classic";
    context.binding.containerId = winrt::guid{L"12345678-abcd-4567-8123-456789abcdef"};
    context.historyGeneration = 1;
    context.identityGeneration = 2;
    UnlockResult result;
    result.nonce[0] = 42;
    LastUnlockHistory history;
    require(!history.summary() && !history.report(result, 100, true, true, context.identity, 10000),
        "BLE verification without a claim cannot record a native unlock");
    history.beginClaim(context, result.nonce, 100, -58);
    require(!history.summary(), "claiming a credential must not record success");
    require(!history.report(result, 100, false, true, context.identity, 10000), "ordinary callers cannot report success");
    require(!history.report(result, 101, true, true, context.identity, 10000), "another LogonUI process cannot report this claim");
    auto wrong = result;
    wrong.nonce[0]++;
    require(!history.report(wrong, 100, true, true, context.identity, 10000), "a different nonce must fail");
    require(history.pending() && history.report(result, 100, true, true, context.identity, 10000),
        "only the matching native success may complete the claim");
    require(history.summary() && history.summary()->completedAt == 10000 && history.summary()->rssi == -58,
        "native success must retain the claimed request RSSI and result time");
    require(!history.report(result, 100, true, true, context.identity, 20000) && history.summary()->completedAt == 10000,
        "duplicate result cannot advance the successful unlock time");

    history.beginClaim(context, result.nonce, 100, -40);
    auto failure = result;
    failure.status = -1;
    require(history.report(failure, 100, true, true, context.identity, 20000) && !history.pending() &&
        history.summary()->completedAt == 10000 && history.summary()->rssi == -58, "native failure must preserve previous success");
    require(!history.report(result, 100, true, true, context.identity, 30000), "failure must consume the pending result");
    history.beginClaim(context, result.nonce, 100, -40);
    require(!history.report(result, 100, true, false, context.identity, 20000) && !history.pending(),
        "an exited claiming process must invalidate the result");
    history.beginClaim(context, result.nonce, 100, -40);
    history.cancelPending();
    require(!history.report(result, 100, true, true, context.identity, 20000) && history.summary()->completedAt == 10000,
        "a new verification cancels pending reports but preserves last success");

    auto changedThreshold = context;
    changedThreshold.binding.threshold++;
    history.refreshContext(changedThreshold);
    require(history.summary().has_value(), "changing only the distance threshold must preserve history");
    history.beginClaim(context, result.nonce, 100, -40);
    auto lockedAgain = context;
    lockedAgain.identityGeneration++;
    history.refreshContext(lockedAgain);
    require(!history.pending() && history.summary(), "a new lock must cancel pending results but preserve history");

    for (unsigned change = 0; change != 8; ++change) {
        history.beginClaim(context, result.nonce, 100, -58);
        require(history.report(result, 100, true, true, context.identity, 10000), "success fixture must complete");
        auto current = context;
        switch (change) {
        case 0: current.identity.sid += L"1"; break;
        case 1: current.identity.qualifiedUserName += L"1"; break;
        case 2: current.identity.providerId.Data1++; break;
        case 3: current.session++; break;
        case 4: current.logonId.LowPart++; break;
        case 5: current.historyGeneration++; break;
        case 6: current.binding.bleId += L"1"; break;
        case 7: current.binding.containerId = winrt::guid{}; break;
        }
        history.beginClaim(context, result.nonce, 100, -40);
        history.refreshContext(current);
        require(!history.summary() && !history.pending() && !history.report(result, 100, true, true, context.identity, 20000),
            "account/session/binding changes must clear history and reject stale results");
    }
    history.beginClaim(context, result.nonce, 100, -40);
    auto otherIdentity = context.identity;
    otherIdentity.qualifiedUserName += L"1";
    require(!history.report(result, 100, true, true, otherIdentity, 20000) && !history.pending(),
        "native result from a changed full identity must fail");
    history.clear();
    require(!history.summary() && !history.pending(), "binding/password removal must clear history");
    auto newer = result;
    newer.nonce[0]++;
    history.beginClaim(context, newer.nonce, 100, -45);
    require(!history.report(result, 100, true, true, context.identity, 20000) &&
        history.report(newer, 100, true, true, context.identity, 21000) && history.summary()->rssi == -45,
        "an older claim result cannot be associated with a later claim");
    LastUnlockHistory restarted;
    require(!restarted.summary() && !restarted.pending(), "service restart must start with no history");
}

void testLastUnlockText() {
    using unlock_windows::desktop_app::lastUnlockText;
    const std::optional<LastUnlockSummary> summary = LastUnlockSummary{10000, -58};
    require(lastUnlockText(std::nullopt, 10000) == L"\u2014", "no history must display a dash");
    require(lastUnlockText(summary, 10000) == L"0 sec ago / -58 dBm", "new success must show seconds and claimed RSSI");
    require(lastUnlockText(summary, 69999) == L"59 sec ago / -58 dBm", "seconds must stop at a full minute");
    require(lastUnlockText(summary, 70000) == L"1 min ago / -58 dBm", "minute boundary must display correctly");
    require(lastUnlockText(summary, 130000) == L"2 min ago / -58 dBm", "requested display example must match");
    require(lastUnlockText(summary, 3609999) == L"59 min ago / -58 dBm", "minutes must stop at a full hour");
    require(lastUnlockText(summary, 3610000) == L"1 hr ago / -58 dBm", "hour boundary must display correctly");
    require(lastUnlockText(summary, 86409999) == L"23 hr ago / -58 dBm", "hours must stop at a full day");
    require(lastUnlockText(summary, 86410000) == L"1 day ago / -58 dBm", "day boundary must display correctly");
    require(lastUnlockText(summary, 172810000) == L"2 days ago / -58 dBm", "multiple days must display correctly");
}

void testSetupLaunchArguments() {
    using namespace unlock_windows::desktop_app;
    wchar_t executable[] = L"UnlockWithIPhone.exe";
    std::wstring setup(kSetupRole), password(kSavedPasswordRole);
    wchar_t* trayArguments[]{executable, setup.data()};
    require(parseLaunch(2, trayArguments).role == Role::setup, "setup must enter the ordinary tray role");
    std::wstring cancelArgument(kSetupCancelArgument);
    std::wstring eventName = std::wstring(kSetupCancelPrefix) + L"{01234567-89ab-cdef-0123-456789abcdef}";
    wchar_t* passwordArguments[]{executable, password.data(), setup.data(), cancelArgument.data(), eventName.data()};
    const auto launch = parseLaunch(5, passwordArguments);
    require(launch.role == Role::savedPassword && launch.setup && launch.setupCancelEvent == eventName,
        "setup must pass its cancellation event to the elevated password role");
    require(!validSetupCancelEvent(L"Global\\unrelated") &&
        !validSetupCancelEvent(std::wstring(kSetupCancelPrefix) + L"{invalid-guid}") &&
        !validSetupCancelEvent(std::wstring(kSetupCancelPrefix) + L"{z1234567-89ab-cdef-0123-456789abcdef}"),
        "setup must reject malformed or unrelated cancellation events");
    wchar_t* missingCancellation[]{executable, password.data(), setup.data()};
    bool missingRejected = false;
    try { static_cast<void>(parseLaunch(3, missingCancellation)); }
    catch (const std::invalid_argument&) { missingRejected = true; }
    require(missingRejected, "setup must not retain an uncancellable launch path");
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

void testPipeDeadlinesAndRecovery() {
    Packet outbound;
    outbound.operation = Operation::bindingStatus;
    outbound.payload.value = {17, 91, 42};
    const auto wire = packetBytes(outbound);
    const auto headerSize = wire.size() - outbound.payload.value.size();
    PipePair pipe;
    Packet inbound;
    require(!readPacket(pipe.server.get(), inbound, testContext(100)) && GetLastError() == ERROR_TIMEOUT,
        "an empty connection must time out");
    pipe.reconnect();
    writeBytes(pipe.client.get(), wire.data(), static_cast<DWORD>(headerSize / 2));
    require(!readPacket(pipe.server.get(), inbound, testContext(100)) && GetLastError() == ERROR_TIMEOUT,
        "an incomplete header must time out");
    pipe.reconnect();
    writeBytes(pipe.client.get(), wire.data(), static_cast<DWORD>(headerSize + 1));
    require(!readPacket(pipe.server.get(), inbound, testContext(100)) && GetLastError() == ERROR_TIMEOUT && inbound.payload.value.empty(),
        "an incomplete body must time out and clear partial data");
    pipe.reconnect();
    writeBytes(pipe.client.get(), wire.data(), static_cast<DWORD>(headerSize + 1));
    pipe.client.close();
    require(!readPacket(pipe.server.get(), inbound, testContext()) && GetLastError() == ERROR_BROKEN_PIPE && inbound.payload.value.empty(),
        "a disconnected truncated request must reject and clear partial data");
    pipe.reconnect();
    std::thread slowWriter([&] {
        for (auto byte : wire) {
            writeBytes(pipe.client.get(), &byte, 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }
    });
    const auto started = GetTickCount64();
    const bool read = readPacket(pipe.server.get(), inbound, testContext(100));
    const auto error = GetLastError();
    const auto elapsed = GetTickCount64() - started;
    slowWriter.join();
    require(!read && error == ERROR_TIMEOUT && elapsed < kPipeTransferLifetimeMs,
        "individual bytes must not renew the packet deadline");
    pipe.reconnect();
    Packet large;
    large.operation = outbound.operation;
    large.payload.value.resize(kMaxPacket, 42);
    require(!writePacket(pipe.server.get(), large, testContext(100)) && GetLastError() == ERROR_TIMEOUT,
        "a client that does not read the response must time out");
    pipe.reconnect();
    require(!awaitReplyAcknowledgment(pipe.server.get(), outbound.operation, testContext(100)) && GetLastError() == ERROR_TIMEOUT,
        "a client that sends no acknowledgment must time out");
    pipe.reconnect();
    const auto context = testContext();
    require(writePacket(pipe.client.get(), outbound, context) && readPacket(pipe.server.get(), inbound, context) &&
        inbound.operation == outbound.operation && inbound.payload.value == outbound.payload.value,
        "a normal request must work on the same server after abnormal clients");
    require(writePacket(pipe.server.get(), inbound, context) && readPacket(pipe.client.get(), outbound, context) &&
        writeReplyAcknowledgment(pipe.client.get(), outbound.operation, context) &&
        awaitReplyAcknowledgment(pipe.server.get(), outbound.operation, context),
        "response and acknowledgment must complete with the same deadline");
    const PipeIoContext expired{GetTickCount64()};
    require(!readPacket(pipe.server.get(), inbound, expired) && GetLastError() == ERROR_TIMEOUT,
        "an already-expired phase must not start another I/O");
    require(!writePacket(pipe.server.get(), outbound, expired) && GetLastError() == ERROR_TIMEOUT,
        "response writing must not renew an expired deadline");
    require(!awaitReplyAcknowledgment(pipe.server.get(), outbound.operation, expired) && GetLastError() == ERROR_TIMEOUT,
        "acknowledgment waiting must not renew an expired deadline");
    pipe.reconnect();
    require(writeReplyAcknowledgment(pipe.client.get(), Operation::status, testContext()), "invalid ACK fixture must write");
    require(!awaitReplyAcknowledgment(pipe.server.get(), outbound.operation, testContext()) && GetLastError() == ERROR_INVALID_DATA,
        "acknowledgment must match the request operation");
}

void testPipeStopCancellation() {
    winrt::handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(stop), "stop event must open");
    const auto cancels = [&](auto action) {
        require(ResetEvent(stop.get()), "stop event must reset");
        std::thread stopper([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            require(SetEvent(stop.get()), "stop event must signal");
        });
        const bool completed = action();
        const DWORD error = GetLastError();
        stopper.join();
        require(!completed && error == ERROR_OPERATION_ABORTED, "STOP must cancel pending pipe I/O");
    };
    PipePair listener(false);
    cancels([&] { return connectPipe(listener.server.get(), stop.get()); });
    PipePair pipe;
    Packet packet;
    packet.operation = Operation::bindingStatus;
    cancels([&] { return readPacket(pipe.server.get(), packet, testContext(kPipeTransferLifetimeMs, stop.get())); });
    pipe.reconnect();
    packet.payload.value = {1, 2, 3};
    const auto wire = packetBytes(packet);
    const auto headerSize = wire.size() - packet.payload.value.size();
    writeBytes(pipe.client.get(), wire.data(), static_cast<DWORD>(headerSize + 1));
    cancels([&] { return readPacket(pipe.server.get(), packet, testContext(kPipeTransferLifetimeMs, stop.get())); });
    require(packet.payload.value.empty(), "cancelled body must release partial data");
    pipe.reconnect();
    packet.payload.value.resize(kMaxPacket, 42);
    cancels([&] { return writePacket(pipe.server.get(), packet, testContext(kPipeTransferLifetimeMs, stop.get())); });
    pipe.reconnect();
    cancels([&] { return awaitReplyAcknowledgment(pipe.server.get(), packet.operation, testContext(kPipeTransferLifetimeMs, stop.get())); });
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
    for (const auto unknown : {10, 11, 13, 14, 17}) require(!isKnownOperation(static_cast<std::uint16_t>(unknown)), "unsupported operation must reject");
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
    // Fixed pre-change binding bytes: independent of the current encoder.
    const std::uint8_t legacy[] = {
        0x67,0x45,0x23,0x01,0xab,0x89,0xef,0xcd,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xc4,0xff,0xff,0xff,
        8,0, 'S',0, '-',0, '1',0, '-',0, '5',0, '-',0, '1',0, '8',0,
        1,0, 'c',0,
        6,0, 'b',0, 'l',0, 'e',0, '-',0, 'i',0, 'd',0,
        3,0, 'o',0, 'l',0, 'd',0
    };
    const BindingRecord legacyRecord{L"S-1-5-18", L"c", L"ble-id",
        winrt::guid{L"01234567-89ab-cdef-0123-456789abcdef"}, L"old", -60};
    require(decodeBinding(legacy, sizeof(legacy), decoded) && decoded == legacyRecord,
        "pre-change binding layout must remain readable without migration");
    auto newRecord = record; newRecord.classicId.clear(); newRecord.containerId = {};
    SensitiveBytes newBytes;
    require(encodeBinding(legacyRecord, newBytes) && newBytes.value.size() == sizeof(legacy) &&
        std::equal(newBytes.value.begin(), newBytes.value.end(), legacy),
        "legacy record encoding must retain the exact pre-change byte layout");
    require(encodeBinding(newRecord, newBytes) && decodeBinding(newBytes.value.data(), newBytes.value.size(), decoded) && decoded == newRecord,
        "new bindings must round trip with empty legacy fields");
    for (std::size_t size = 0; size < newBytes.value.size(); ++size)
        require(!decodeBinding(newBytes.value.data(), size, decoded), "truncated new bindings must reject");
    newBytes.value.push_back(0);
    require(!decodeBinding(newBytes.value.data(), newBytes.value.size(), decoded), "new binding trailing data must reject");
    auto invalidRecord = newRecord; invalidRecord.bleId.clear();
    require(!encodeBinding(invalidRecord, newBytes), "empty BLE ID must reject");
    invalidRecord = newRecord; invalidRecord.accountSid = L"invalid";
    require(!encodeBinding(invalidRecord, newBytes), "invalid target SID must reject");
    invalidRecord = newRecord; invalidRecord.classicId.assign(2049, L'x');
    require(!encodeBinding(invalidRecord, newBytes), "oversized legacy fields must reject");
    invalidRecord = newRecord; invalidRecord.bleId.push_back(L'\0');
    require(!encodeBinding(invalidRecord, newBytes), "embedded NUL in BLE ID must reject");
    for (std::size_t size = 0; size < bytes.value.size(); ++size)
        require(!decodeBinding(bytes.value.data(), size, decoded), "all truncated binding packets must fail");
    bytes.value.push_back(0);
    require(!decodeBinding(bytes.value.data(), bytes.value.size(), decoded), "binding trailing data must fail");
    record.threshold = kMinimumThreshold - 1;
    require(!encodeBinding(record, bytes), "threshold below range must fail");
    record.threshold = kMaximumThreshold + 1;
    require(!encodeBinding(record, bytes), "threshold above range must fail");
    record.threshold = kDefaultThreshold;
    BindingChange change{{BindingState::absent, {}}, record, L"Global\\test-cancellation"};
    BindingChange restored;
    require(encodeBindingChange(change, bytes) && decodeBindingChange(bytes.value.data(), bytes.value.size(), restored) &&
        restored.expected == change.expected && restored.candidate == change.candidate && restored.cancelEvent == change.cancelEvent,
        "management request must preserve the expected record and cancellation event");
    change.expected = {BindingState::bound, legacyRecord}; change.candidate = newRecord;
    require(encodeBindingChange(change, bytes) && decodeBindingChange(bytes.value.data(), bytes.value.size(), restored) &&
        restored.expected == change.expected && restored.candidate == newRecord,
        "management codec must preserve old expected state and new empty legacy fields");
    bytes.value[0] = 255;
    require(!decodeBindingChange(bytes.value.data(), bytes.value.size(), restored), "malformed expected-length must fail");
    BindingRemoval removal{{BindingState::bound, record}, L"Global\\test-cancellation"};
    BindingRemoval removed;
    require(encodeBindingRemoval(removal, bytes) && decodeBindingRemoval(bytes.value.data(), bytes.value.size(), removed) &&
        removed.expected == removal.expected && removed.cancelEvent == removal.cancelEvent, "removal must bind its expected state and cancellation");
    require(!decodeBindingRemoval(bytes.value.data(), bytes.value.size() - 1, removed), "truncated removal must fail");
    removal.expected.record = newRecord;
    require(encodeBindingRemoval(removal, bytes) && decodeBindingRemoval(bytes.value.data(), bytes.value.size(), removed) &&
        removed.expected == removal.expected, "new bindings must remain removable with empty legacy fields");
    for (auto state : {BindingState::absent, BindingState::bound}) {
        BindingSummary summary{state, state == BindingState::bound ? record : BindingRecord{}};
        BindingSummary read;
        require(encodeBindingSummary(summary, bytes) && decodeBindingSummary(bytes.value.data(), bytes.value.size(), read) && read == summary,
            "absent and bound summaries must round trip");
    }
    require(!encodeBindingSummary({static_cast<BindingState>(2), {}}, bytes), "invalid binding state must not encode");
    require(encodeBindingSummary({BindingState::absent, {}}, bytes), "absent summary fixture must encode");
    bytes.value[0] = 2;
    BindingSummary invalidSummary;
    require(!decodeBindingSummary(bytes.value.data(), bytes.value.size(), invalidSummary), "invalid binding state must not decode");
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
    Packet packet;
    auto wire = packetBytes(packet);
    wire[4] = static_cast<std::uint8_t>(kProtocolVersion + 1); wire[5] = 0;
    PipePair pipe;
    writeBytes(pipe.client.get(), wire.data(), static_cast<DWORD>(wire.size()));
    require(!readPacket(pipe.server.get(), packet, testContext()) && GetLastError() == ERROR_INVALID_DATA,
        "unsupported packet versions must reject");
}

struct EndpointFixture : winrt::implements<EndpointFixture, winrt::Windows::Devices::Enumeration::IDeviceInformation> {
    winrt::hstring endpointId;
    explicit EndpointFixture(winrt::hstring value) : endpointId(std::move(value)) {}
    winrt::hstring Id() { return endpointId; }
    winrt::hstring Name() { return L"fixture"; }
    bool IsEnabled() { return true; }
    bool IsDefault() { return false; }
    winrt::Windows::Devices::Enumeration::EnclosureLocation EnclosureLocation() { return nullptr; }
    winrt::Windows::Foundation::Collections::IMapView<winrt::hstring, winrt::Windows::Foundation::IInspectable> Properties() {
        auto properties = winrt::single_threaded_map<winrt::hstring, winrt::Windows::Foundation::IInspectable>();
        return properties.GetView();
    }
    void Update(winrt::Windows::Devices::Enumeration::DeviceInformationUpdate const&) { throw winrt::hresult_not_implemented(); }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail> GetThumbnailAsync() {
        throw winrt::hresult_not_implemented();
    }
    winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail> GetGlyphThumbnailAsync() {
        throw winrt::hresult_not_implemented();
    }
};

void testEndpointSelection() {
    using namespace winrt::Windows::Devices::Enumeration;
    using namespace unlock_windows::system_ble;
    winrt::init_apartment();
    {
        const winrt::hstring target{L"selected-ble-id"};
        const auto selected = winrt::make<EndpointFixture>(target).as<DeviceInformation>();
        const auto unrelated = winrt::make<EndpointFixture>(winrt::hstring{L"other-ble-id"}).as<DeviceInformation>();
        auto entries = winrt::single_threaded_vector<DeviceInformation>();
        const auto collection = entries.GetView().as<DeviceInformationCollection>();
        require(!findUniqueEndpoint(collection, target), "missing BLE ID returns no selected endpoint");
        try { (void)uniqueEndpoint(collection, target); require(false, "service must reject a missing BLE endpoint"); }
        catch (const VerificationError& error) { require(error.reason == Failure::associationInvalid, "missing BLE endpoint has the correct failure"); }
        entries.Append(unrelated);
        entries.Append(selected);
        require(!findUniqueEndpoint(collection, winrt::hstring{}), "empty BLE ID must not select a device");
        require(findUniqueEndpoint(collection, target) == selected && uniqueEndpoint(collection, target) == selected,
            "exact BLE ID selects its endpoint despite same-name unrelated devices");
        entries.Append(winrt::make<EndpointFixture>(target).as<DeviceInformation>());
        try { (void)findUniqueEndpoint(collection, target); require(false, "duplicate BLE ID must reject immediately"); }
        catch (const VerificationError& error) { require(error.reason == Failure::associationInvalid, "duplicate BLE ID has the correct failure"); }
    }
    winrt::uninit_apartment();
}

void testBindingSummaryReadback() {
    using namespace unlock_windows::system_ble;
    BindingSummary confirmed{BindingState::bound, {L"S-1-5-21-1-2-3-1001", L"classic", L"ble",
        winrt::guid{L"12345678-1234-1234-1234-123456789abc"}, L"iPhone", kDefaultThreshold}};
    const auto original = confirmed;
    const std::uint8_t truncated[] = {static_cast<std::uint8_t>(BindingState::bound)};
    for (unsigned query = 0; query < 2; ++query) {
        require(!decodeBindingSummary(truncated, sizeof(truncated), confirmed), "failed binding readback must reject a partial record");
        require(confirmed == original, "consecutive malformed readbacks must preserve the previously confirmed threshold");
    }
    auto updated = original;
    updated.record.threshold++;
    SensitiveBytes reply;
    require(encodeBindingSummary(updated, reply) && decodeBindingSummary(reply.value.data(), reply.value.size(), confirmed) &&
        confirmed == updated, "a valid service reply supplies the new confirmed threshold");
    require(encodeBindingSummary({}, reply) && decodeBindingSummary(reply.value.data(), reply.value.size(), confirmed) &&
        confirmed.state == BindingState::absent, "readback can confirm removal instead of inventing a bound candidate");
}

void testPreparationState() {
    unlock_windows::system_ble::PreparationState preparation;
    require(preparation.ready(false, 0), "initial context permits preparation");
    preparation.fail(4);
    for (unsigned poll = 0; poll < 5; ++poll) {
        require(!preparation.ready(false, 0), "closing a failed connection cannot permit background reconstruction");
        require(!preparation.ready(true, 4), "same healthy structure cannot retry a stable preparation failure");
    }
    require(!preparation.ready(false, 5), "an unhealthy connection cannot reset failure through a revision change");
    require(preparation.ready(true, 5), "changed healthy structure permits new preparation");
    preparation.fail(5);
    preparation.reset();
    require(preparation.ready(false, 0), "an explicit request or changed context permits preparation without a retained object");
}

void testConsoleLockState() {
    WTSINFOEXW info{};
    info.Level = 1;
    auto& level = info.Data.WTSInfoExLevel1;
    level.SessionId = 7;
    level.SessionState = WTSActive;
    level.SessionFlags = WTS_SESSIONSTATE_LOCK;
    require(unlock_windows::consoleLocked(&info, sizeof(info), 7), "known active locked console is accepted");
    level.SessionFlags = WTS_SESSIONSTATE_UNLOCK;
    require(!unlock_windows::consoleLocked(&info, sizeof(info), 7), "known active unlocked console is accepted");
    const auto rejects = [](const void* data, DWORD bytes, DWORD session) {
        try { (void)unlock_windows::consoleLocked(data, bytes, session); }
        catch (const std::runtime_error&) { return true; }
        return false;
    };
    require(rejects(nullptr, sizeof(info), 7), "missing WTS response rejects");
    require(rejects(&info, sizeof(info) - 1, 7), "truncated WTS response rejects");
    require(rejects(&info, sizeof(info), 8), "different console session rejects");
    info.Level = 2;
    require(rejects(&info, sizeof(info), 7), "unknown WTS response level rejects");
    info.Level = 1;
    level.SessionState = WTSDisconnected;
    require(rejects(&info, sizeof(info), 7), "inactive physical console rejects");
    level.SessionState = WTSActive;
    level.SessionFlags = static_cast<LONG>(-1);
    require(rejects(&info, sizeof(info), 7), "unknown console lock state rejects");
}

int main() {
    testBindingSummaryReadback();
    testEndpointSelection();
    testPreparationState();
    testConsoleLockState();
    testLastUnlockCodec();
    testLastUnlockHistory();
    testLastUnlockText();
    testIdentityRoundTrip();
    testStatusRoundTrip();
    testCredentialSummary();
    testPipeDeadlinesAndRecovery();
    testPipeStopCancellation();
    testProvisioningIdentityTransport();
    testSetupLaunchArguments();
    testAutoSubmitOffer();
    testAuthenticationOperationPackets();
    testPresenceContracts();
    std::cout << "Saved credential protocol tests passed.\n";
    return EXIT_SUCCESS;
}
