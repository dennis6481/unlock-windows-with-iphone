<!-- Created by Rui MA on 01 Oct 2026 -->

# Saved credential service

The LocalSystem service is the Windows authority for bindings, presence verification and password release. Saved identity consists of SID, the Windows-qualified account name and ProviderID; a matching SID alone is insufficient when the online identity has changed.

## Password protection

The vault uses **LocalSystem user-scope DPAPI**, with `CRYPTPROTECT_UI_FORBIDDEN`, not `CRYPTPROTECT_LOCAL_MACHINE`. Password files/directories have SYSTEM-only ACLs. Controlled plaintext is cleared as early as practical. Credentials are packed by CP inside LogonUI, not by the service in Session 0.

This protection does not resist an administrator who obtains SYSTEM or a compromised kernel. Binding stores SID, system endpoints, ContainerId, display name and threshold using machine-scope DPAPI with SYSTEM/administrator-only writes. Read [SECURITY.md](../../SECURITY.md) for limits.

## Authentication and IPC

`unlockEligibility` checks an existing physical-console token, SID, session and explicit locked state. An eligible LogonUI caller can create a request only when its captured identity, saved identity and registration agree. The service owns all request/grant deadlines; the [protocol](../../PROTOCOL.md#request-and-one-time-approval) specifies their lifetimes.

IPC version **3** uses one pipe. Removed phone challenge, assertion and reload operations are rejected. Ordinary unlocked target-console clients read non-sensitive status; elevated clients manage passwords/bindings; only verified LogonUI can request unlock verification, receive a one-time offer or claim credentials. Process/pipe tokens, PID, session and expected LogonUI image are pinned and checked.

One MTA worker owns BLE and maintains the bound phone after native sign-in; IPC only validates, queues and reads status. Pending cleanup keeps the worker busy, but an idle retained connection does not. The shared [BLE operations](../Bluetooth/SystemBleSession.cpp) use Windows-cached service structure, verify unique system endpoints and pairing history, then perform new protected subscription/Uncached CCCD read/unsubscribe for every request. Missing/stale RSSI waits within the original deadline; fresh low signal fails. Communication and RSSI must still be within 3 seconds at claim.

States distinguish idle, verifying, approved, failed, consumed and completed binding. Reasons distinguish pairing/association, protected operation, connection, RSSI, timeout, cancellation, storage and context failures. Request deadlines remain 30 seconds; no retry or callback extends them.

`serviceDiagnostics` exposes the latest request's bounded verification trace to the verified unlocked target console user. Diagnostics records request IDs, watcher status/counts, pairing properties, GATT results, operation timings and failures. Cleanup failures preserve an earlier verification failure.

Request completion clears evidence while retaining a valid connection. Disconnect invalidates evidence/structure and leaves Windows reconnection intent active; reconnection never approves a request. Logoff, account/binding change, suspend and service stop close the connection. Preparation errors are explicit; stable failures wait for an explicit request or changed context rather than retrying indefinitely.

The service consumes authorization before decrypting. CP rebuild, packing failure and native password rejection cannot restore it. Connection, system association, console/power/account and registration changes invalidate affected requests. Actual native Windows session recovery remains the acceptance result.
## Password management

After the first native sign-in, choose **Start setup** on the installation result page or launch `--setup`. The elevated WinUI password window verifies the installed target account. Only a saved copy matching the complete verified identity permits skipping the password step. Saving a copy successfully enables binding on the ordinary Status page; cancellation and failure do not. For independent maintenance, open tray **Password…** and choose save, update or removal.

`credentialSummary` returns the verified account and saved-copy state to the unlocked installation target's ordinary console session. It returns no password or snapshot nonce and creates no management snapshot or phone approval. The management pipe accepts local authenticated connections, but status/nonces and credential changes still require an administrator; phone-pipe operations remain unchanged.

Before a console user token exists, `captureProvisioningIdentity` accepts only a real physical-console LogonUI caller and the installer-recorded target SID. It records system-provided identity metadata in memory and returns no password, snapshot nonce or phone grant.

After sign-in, queries use `NetUserGetInfo` level 24 for the online provider/name and local SID, and match unfiltered identity-store entries by PrimarySid for ProviderID. The qualified name uses Windows `provider\principal` format; the store's QualifiedUserName property is not required. Target, console and logon checks remain required. Service restart does not require another lock/unlock cycle.

The snapshot lasts five minutes. A new management query can renew it without another sign-in. Candidates are invalidated by logoff, console disconnection, another console account or service restart. Unavailable or ambiguous Windows identity properties are explicit verification failures. The target is the console user, not an alternate administrator entered at UAC. Identity must not be reconstructed from diagnostics or the saved credential.

The main Password page refreshes on entry, activation and operation-window exit. Refresh is in the page header; Save/Update and removal sit side by side. Unknown state disables password changes. The elevated window contains PasswordBox, Save/Update and Cancel; a failed query replaces the primary action with Retry. Removal uses ContentDialog with Cancel as default. InfoBar reports results/errors. **Remove saved password** clears only the local copy. Closing the window leaves the ordinary tray running.

## Removal and maintenance

Installer `clearForRemoval` must receive service confirmation that the password, grant, snapshot and BLE request were cleared before removal continues. There is no success path that skips a failed credential-clear operation.

Keep identity checks, consume-before-decrypt ordering, caller separation and impersonation boundaries intact during maintenance. Logs must not include passwords, nonce bytes, credential plaintext or device identifiers in public reports. See the [testing guide](../../docs/Testing.md#authentication-and-security-boundaries) for caller, identity, replay and restart scenarios.
