<!-- Created by Rui MA on 26 Sep 2026 -->
<!-- Modified by Liam on 22 Oct 2026 -->

# Protocol and architecture

No iPhone app is used. Windows system pairing identifies the selected phone; the LocalSystem service owns its product binding and every presence authorization decision. Windows native authentication remains the final authority.

## Shared contracts

- [SystemBleContract.h](windows/Bluetooth/SystemBleContract.h): ANCS/Notification Source UUIDs, binding record layout, RSSI range −100…−20 dBm, 1 dBm step, −60 dBm default, 30-second request deadline and 3-second evidence lifetime.
- [SavedCredentialIpc.h](windows/SavedCredential/SavedCredentialIpc.h): IPC version **3**, operations, status/failure enums, binding and packet codecs. Unsupported versions and operations are rejected.
- [SystemBleSession](windows/Bluetooth/SystemBleSession.cpp): reusable paired BLE endpoint and protected GATT operations. [PresenceAuthorization](windows/Bluetooth/PresenceAuthorization.h) combines communication with request-local RSSI from [RssiSampler](windows/Bluetooth/RssiSampler.h), shared with the independent diagnostic.

## Setup and binding

1. Save the password for the complete Windows-verified target identity: SID, QualifiedUserName and ProviderID.
2. Windows Bluetooth settings owns pairing and numeric confirmation. Existing Windows pairing is reused; the app does not initiate a pairing ceremony.
3. The ordinary unlocked console user's Status page watches paired BLE endpoints when no iPhone is bound. Added, Updated and Removed events update the list; returning from Windows settings performs another enumeration. Each endpoint ID has its own named row, with no name-based identity matching. The user selects the device and clicks **Bind selected device**.
4. The selected BLE endpoint ID must still appear in the system paired BLE list. Display names and guessed MAC addresses do not select identity.
5. Explicit confirmation and UAC submit an expected-record/candidate change. The service independently verifies the selected paired BLE endpoint, authenticated Secure Connections pairing record and fresh protected communication before atomic commit; binding does not collect RSSI. Cancellation or failure retains the old binding.

Newly paired devices are never registered automatically. The UI offers removal only for an existing binding; remove it before binding another device. Removal deletes the product binding, not Windows pairing. Threshold dragging changes only the pending UI value; Save requires UAC and restores the saved value on refusal or failure.

The read-only `serviceDiagnostics` IPC operation returns the latest request's verification trace as UTF-8 text, restricted to the verified unlocked target console user and bounded by the IPC payload limit. The desktop pauses binding-status/diagnostics polling while the console is locked and resumes on its next unlocked poll. A rejected query is discarded only when the same console account is confirmed to have locked during that query; other failures remain errors. Diagnostics appends new lines to the desktop session history. Existing status payloads and persisted formats are unchanged; unsupported queries report an error.

## Registration storage

`%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat` retains machine-bound DPAPI encryption, protected pending-file creation, flushing and atomic replacement. SYSTEM and Administrators alone can write the file and its parent directory. The service owns storage; ordinary desktop clients read non-sensitive status over IPC.

The encrypted version-2 record retains its byte layout. It stores target SID, BLE endpoint ID, display name and threshold; legacy Classic ID and ContainerId slots are unused for identity verification. New bindings write empty/zero legacy values; old records remain readable without migration, and threshold edits preserve their values.

Deploy matching desktop/service binaries; older software cannot read new bindings. Unsupported formats, corruption and permission failures remain errors, distinct from an absent record. Password storage is unchanged.

## Request and one-time approval

1. Clicking **Unlock** lets an eligible LogonUI caller create a unique request for the locked physical console, with a fixed 30-second deadline. Selection and lock events alone do not start verification.
2. One MTA BLE worker maintains the bound phone's connection after native sign-in, rechecks the selected paired BLE endpoint and authenticated Secure Connections bond metadata for each request, and clears request evidence at request end. IPC only validates, queues and reads state; it never waits for GATT. An active or still-finishing BLE task returns **busy**; an idle retained connection does not.
3. ANCS, Notification Source and CCCD structure queries use Windows Cached mode (which may query the device on a miss); valid objects are reused on the current connection. Each request performs authenticated/encrypted subscription, Uncached CCCD read and unsubscribe without reading notification contents. Service-list changes before the first complete protected subscribe/read/unsubscribe discard provisional structure and evidence within the original deadline; changes after that stability point invalidate the request.
4. RSSI must be sampled after request start, match the current endpoint, Bluetooth address **and address type** and connection revision, be at most 3 seconds old and reach the saved threshold. After collection, the session rechecks the target and communication state under one lock. Missing/old samples wait within the original deadline; fresh low samples fail immediately. Time-expired communication evidence is renewed when an eligible sample arrives, within the same deadline. Address changes discard samples until a current associated sample exists.
5. Request, binding, connection, full account identity, console session, logon identity and lock generation must still match before a one-time grant is made. Connection and invalidation listeners persist across requests; no historical request evidence is reused.
6. CP receives one auto-submit offer and notifies LogonUI through `CredentialsChanged`. Claim rechecks communication/RSSI freshness and all contexts, **consumes authorization before decrypting the password**, then CP submits through native Negotiate.
7. `ReportResult` sends the claim nonce and native status through `reportUnlockResult`. Only the matching pinned LogonUI process and unchanged account/session/binding can complete it. Native success records monotonic time and claimed RSSI in service memory; failures and duplicates cannot advance history or restore authorization.

Disconnect, cancel, timeout, suspend/resume, unlock, logoff, account/console change, selected BLE pairing/removal or registration change invalidates the affected request/grant. Late callbacks cannot approve a cancelled or expired request; an unfinished native operation keeps the worker busy. No automatic retry creates another request or extends its deadline.

Unlock, request cancellation/expiry and credential consumption keep a valid connection. Disconnect clears old structure/evidence while Windows retains reconnection intent; reconnection creates no authorization. Logoff, account/binding change, suspend and service stop release the connection; native login/resume re-evaluates eligibility. Stable preparation errors remain attached to their target context after connection cleanup, without periodic reconstruction; an explicit request, changed context or changed healthy structure may prepare again. The independent diagnostic closes its one-shot session.

## IPC boundaries

| Caller | Permitted purpose |
| --- | --- |
| Ordinary target-console desktop | Non-sensitive account/binding/last-unlock summaries, binding-task status and cancellation. |
| Elevated administrator at the target's unlocked console | Existing password management, binding/replace/remove and threshold save. Full target identity remains service-verified. |
| Verified SYSTEM LogonUI in the locked physical console | Provisioning/capture, eligibility, verification start/status/cancel, one-time offer and credential claim. |
| Verified SYSTEM LogonUI completing its claim | Native result reporting before or after the same session unlocks; no new credential access. |

There is one saved-credential pipe. No phone pipe, signature submission, public-key reload, desktop approval operation or desktop credential claim exists. The service pins the client process and compares actual pipe/process tokens, sessions and expected LogonUI image. Client code checks SCM identity and server PID/session. Impersonation ends before LocalSystem DPAPI access.

Connection, reads, writes and reply acknowledgment use cancellable Overlapped I/O. Each connected client has one absolute 2000 ms transfer deadline; fragments and ACK do not renew it. Client `call` shares one deadline across the entire call. Service STOP signals an event, cancels pending I/O and drains completion before releasing its resources. Transport errors identify the stage and Win32 error; failed replies never restore consumed authorization.

`lastUnlockStatus` returns only optional success time/RSSI to the verified unlocked target user. History is not persisted or used for authentication. Service restart, account/session change, binding replacement/removal and password removal clear it; threshold changes retain it. New requests retire pending results. Reporting failure is diagnostic and never changes the native Windows result.

## Opt-in wake-based automatic verification

Administrator-approved Status control stores a machine-wide registry DWORD under `HKLM\SOFTWARE\UnlockWindowsWithIPhone\AutomaticUnlockAtLockScreen`. Only value 1 opts in; missing/invalid data is off, and the old `AutomaticUnlockOnResume` setting is not promoted automatically. The service requires an existing user's session lock (not initial sign-in) and either user resume (`PBT_APMRESUMESUSPEND`) after observed suspend, or a display-off/on transition through `GUID_CONSOLE_DISPLAY_STATE`. Sleep wake tickets survive delayed lock notifications; display-off observed before lock is retained until display-on. Locking alone (including Win+L), initial display-on and background resume alone cannot arm a ticket. Session unlock, logon, logoff or disconnect clears it. An explicit manual Unlock consumes the current activation, including its pending resume/display notifications. The service checks locked console/account, binding, credential and request identity, atomically consumes the ticket before BLE work and never automatically retries failures within the same activation. Duplicate user-resume/display-on notifications do not create another ticket. The Credential Provider watcher initiates verification when the sign-in UI is active and reuses the existing one-time offer and `CredentialsChanged` native submission. PIN/password fallback remains. Someone waking the locked PC with the trusted phone nearby may gain access. Real sleep/display-wake acceptance is pending.

## Limits and acceptance

Presence authorization does not require a fresh phone gesture. Pairing-history metadata and protected GATT success do not independently prove current-link LESC mode/key reuse. Advertisement RSSI is unauthenticated and is not secure distance or relay resistance. ANCS availability and long-standby/recovery behavior require hardware acceptance.

Existing MSA, single-user and local physical-console support is retained. Local accounts are experimental and require Windows validation; remote sessions remain unsupported. A service **approved** status is not proof of Windows unlocking; acceptance requires the actual session to resume with no iPhone app, desktop app exited and both devices locked. See [Security](SECURITY.md).
