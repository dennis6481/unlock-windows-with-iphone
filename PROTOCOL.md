<!-- Created by Rui MA on 26 Sep 2026 -->

# Protocol and architecture

No iPhone app is used. Windows system pairing identifies the selected phone; the LocalSystem service owns its product binding and every presence authorization decision. Windows native authentication remains the final authority.

## Shared contracts

- [SystemBleContract.h](windows/Bluetooth/SystemBleContract.h): ANCS/Notification Source UUIDs, ContainerId property, RSSI range −100…−20 dBm, 1 dBm step, −60 dBm default, 30-second request deadline and 3-second evidence lifetime.
- [SavedCredentialIpc.h](windows/SavedCredential/SavedCredentialIpc.h): IPC version **3**, operations, status/failure enums, binding and packet codecs. Version 2 and removed phone operations are rejected.
- [SystemBleSession](windows/Bluetooth/SystemBleSession.cpp): reusable system relationship, protected GATT and address-associated RSSI operations, shared with the independent diagnostic.

## Setup and binding

1. Save the password for the complete Windows-verified target identity: SID, QualifiedUserName and ProviderID.
2. Windows Bluetooth settings owns pairing and numeric confirmation. Existing Windows pairing is reused; the app does not initiate a pairing ceremony.
3. The ordinary unlocked console user's Status page watches paired Classic and BLE endpoints when no iPhone is bound. Added, Updated and Removed events update the list; returning from Windows settings performs another enumeration. Entries share one named row per valid ContainerId; missing containers remain separate, with no name-based identity matching. The user selects the device and clicks **Bind selected device**.
4. Only a unique Windows ContainerId relationship links one paired Classic endpoint to one paired BLE endpoint. Display names and guessed MAC addresses do not select identity.
5. Explicit confirmation and UAC submit an expected-record/candidate change. The service independently verifies the system relationship, authenticated Secure Connections pairing record, protected communication and RSSI before atomic commit. Cancellation or failure retains the old binding.

Newly paired devices are never registered automatically. The UI offers removal only for an existing binding; remove it before binding another device. Removal deletes the product binding, not Windows pairing. Threshold dragging changes only the pending UI value; Save requires UAC and restores the saved value on refusal or failure.

The read-only `serviceDiagnostics` IPC operation returns the latest request's verification trace as UTF-8 text, restricted to the verified unlocked target console user and bounded by the IPC payload limit. The desktop pauses binding-status/diagnostics polling while the console is locked and resumes on its next unlocked poll. A rejected query is discarded only when the same console account is confirmed to have locked during that query; other failures remain errors. Diagnostics appends new lines to the desktop session history. Existing status payloads and persisted formats are unchanged; unsupported queries report an error.

## Registration storage

`%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat` retains machine-bound DPAPI encryption, protected pending-file creation, flushing and atomic replacement. SYSTEM and Administrators alone can write the file and its parent directory. The service owns storage; ordinary desktop clients read non-sensitive status over IPC.

The encrypted record stores target SID, Classic/BLE endpoint IDs, ContainerId, display name and threshold. The old public-key format is recognized only as **requires rebinding**. It is never decrypted, migrated or silently overwritten. Read/corruption/permission errors are distinct from an absent record. Password vault format and LocalSystem user-scope DPAPI remain unchanged.

## Request and one-time approval

1. Clicking **Unlock** lets an eligible LogonUI caller create a unique request for the locked physical console, with a fixed 30-second deadline. Selection and lock events alone do not start verification.
2. One MTA BLE worker maintains the bound phone's connection after native sign-in, rechecks system endpoints and authenticated Secure Connections bond metadata for each request, and clears request evidence at request end. IPC only validates, queues and reads state; it never waits for GATT. An active or still-finishing BLE task returns **busy**; an idle retained connection does not.
3. ANCS, Notification Source and CCCD structure queries use Windows Cached mode (which may query the device on a miss); valid objects are reused on the current connection. Each request performs authenticated/encrypted subscription, Uncached CCCD read and unsubscribe without reading notification contents. Service-list changes before the first complete protected subscribe/read/unsubscribe discard provisional structure and evidence within the original deadline; changes after that stability point invalidate the request.
4. RSSI must be sampled after request start, match the current Bluetooth address **and address type**, be at most 3 seconds old and reach the saved threshold. Missing/old samples wait within the original deadline; fresh low samples fail immediately. Expired communication evidence is renewed when an eligible sample arrives. Address changes discard samples until a current associated sample exists.
5. Request, binding, connection, full account identity, console session, logon identity and lock generation must still match before a one-time grant is made. Connection and invalidation listeners persist across requests; no historical request evidence is reused.
6. CP receives one auto-submit offer and notifies LogonUI through `CredentialsChanged`. Claim rechecks communication/RSSI freshness and all contexts, **consumes authorization before decrypting the password**, then CP submits through native Negotiate.

Disconnect, cancel, timeout, suspend/resume, unlock, logoff, account/console change, system relationship change or registration change invalidates the affected request/grant. Late callbacks cannot approve a cancelled or expired request; an unfinished native operation keeps the worker busy. No automatic retry creates another request or extends its deadline.

Unlock, request cancellation/expiry and credential consumption keep a valid connection. Disconnect clears old structure/evidence while Windows retains reconnection intent; reconnection creates no authorization. Logoff, account/binding change, suspend and service stop release the connection; native login/resume re-evaluates eligibility. Stable preparation errors are reported without a generic retry loop; an explicit request or changed context may prepare again. The independent diagnostic closes its one-shot session.

## IPC boundaries

| Caller | Permitted purpose |
| --- | --- |
| Ordinary target-console desktop | Non-sensitive account/binding summaries, binding-task status and cancellation. |
| Elevated administrator at the target's unlocked console | Existing password management, binding/replace/remove and threshold save. Full target identity remains service-verified. |
| Verified SYSTEM LogonUI in the locked physical console | Provisioning/capture, eligibility, verification start/status/cancel, one-time offer and credential claim. |

There is one saved-credential pipe. No phone pipe, signature submission, public-key reload, desktop approval operation or desktop credential claim exists. The service pins the client process and compares actual pipe/process tokens, sessions and expected LogonUI image. Client code checks SCM identity and server PID/session. Impersonation ends before LocalSystem DPAPI access.

## Limits and acceptance

Presence authorization does not require a fresh phone gesture. Pairing-history metadata and protected GATT success do not independently prove current-link LESC mode/key reuse. Advertisement RSSI is unauthenticated and is not secure distance or relay resistance. ANCS availability and long-standby/recovery behavior require hardware acceptance.

Existing MSA, single-user and local physical-console support is retained. Local accounts and remote sessions remain unsupported. A service **approved** status is not proof of Windows unlocking; acceptance requires the actual session to resume with no iPhone app, desktop app exited and both devices locked. See [Testing](docs/Testing.md) and [Security](SECURITY.md).
