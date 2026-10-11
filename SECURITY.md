<!-- Created by Rui MA on 26 Sep 2026 -->

# Security

## Credential protection

- The saved Microsoft account password remains on the PC, protected by **LocalSystem user-scope DPAPI** and SYSTEM-only vault ACLs. Its format is unchanged.
- Product binding uses separate machine-bound DPAPI storage, with SYSTEM/administrator-only write permissions and atomic commit. Ordinary desktop clients read only non-sensitive service summaries.
- Neither the phone nor the desktop app receives the password. Only verified LogonUI can claim it after current presence validation. The service consumes authorization before decrypting; CP uses native Negotiate.
- SYSTEM, administrator or kernel compromise is outside this protection boundary. Controlled plaintext is cleared where practical; removal does not guarantee erasure from backups or SSD history.

## Presence authorization

The user explicitly clicks **Unlock** on the PC. The phone needs no fresh Face ID, Touch ID, tap or app interaction. Locking the PC alone does not initiate unlock.

The service checks a unique Windows ContainerId relationship, authenticated Secure Connections pairing records, fresh protected ANCS/CCCD operations and current address/type-associated RSSI. Full account identity, request, binding, connection, session, logon and lock generation remain bound to one short-lived, single-use authorization.

Connections and Windows-cached service structure may persist across unlocks. They are not authorization: every request resets its evidence and performs new protected operations. Background connection/reconnection never releases credentials.

**Pairing records are not independent proof of current-link LESC mode or key reuse.** Successful authenticated/encrypted GATT requests prove the requested protected operation succeeded, within the Windows API boundary.

**RSSI is not secure distance.** Advertisements are unauthenticated, can be spoofed or relayed, and may be missing during standby or address rotation. A nearby signal is a presence hint, not proof of the phone user's intent or resistance to a relay attack.

## Windows boundaries

Original password/PIN providers remain available. Initial sign-in after boot or sign-out still requires a native method. Only the existing password-backed MSA, single-user physical-console scope is supported; no local-account, multi-user or remote-session support is added.

IPC version 3 removes all signature/phone transport operations. Ordinary processes cannot begin unlock verification, approve it, obtain auto-submit offers or claim passwords. UAC is required for password and binding changes; the service verifies the installed target's complete identity rather than using the elevated administrator as target.

Ordinary clients cannot report successful unlocks. Only the original pinned LogonUI claim with matching nonce and current identity/session/binding may report its native result. Last-unlock time/RSSI is non-sensitive service-memory history and cannot create or restore authorization.

Cancellation, expiry, disconnect, suspend, unlock, logoff, account/session change, binding mutation and invalid system association invalidate related authorization. Cached communication, old/missing RSSI, late callbacks and repeated claims cannot authorize release. Missing/stale RSSI may wait within the original request deadline; claim still requires fresh communication and signal. Native password failure never restores a consumed grant.

