<!-- Created by Rui MA on 26 Sep 2026 -->

# Security

## Credential protection

- The saved Microsoft account password remains on the PC, protected by **LocalSystem user-scope DPAPI** and SYSTEM-only vault ACLs. The storage format remains unchanged.
- Product binding uses separate machine-bound DPAPI storage, with SYSTEM/administrator-only write permissions and atomic commit. Ordinary desktop clients read only non-sensitive service summaries.
- Neither the phone nor the desktop app receives the password. Only a verified LogonUI process can claim it after a fresh presence check. The service consumes the authorization before decrypting the password; the Credential Provider submits it through native Negotiate.
- SYSTEM, administrator or kernel compromise is outside this protection boundary. Plaintext under the application's control is cleared where practical; removing the saved copy does not guarantee erasure from backups or SSD history.

## Presence authorization

The user explicitly clicks **Unlock** on the PC. The phone needs no fresh Face ID, Touch ID, tap or app interaction. Locking the PC alone does not initiate unlock.

The service checks a unique Windows ContainerId relationship, authenticated Secure Connections pairing records, fresh protected ANCS/CCCD operations and current address/type-associated RSSI. Full account identity, request, binding, connection, session, logon and lock generation remain bound to one short-lived, single-use authorization.

Connections and Windows-cached service structure may persist across unlocks. They are not authorization: every request resets its evidence and performs new protected operations. Background connection/reconnection never releases credentials.

**Pairing records are not independent proof of current-link LESC mode or key reuse.** Successful authenticated/encrypted GATT requests prove the requested protected operation succeeded, within the Windows API boundary.

**RSSI is not a secure measure of distance.** Advertisements are unauthenticated, can be spoofed or relayed, and may be missing during standby or address rotation. A nearby signal is a presence hint, not proof of the phone user's intent or resistance to a relay attack.

## Windows boundaries

Original password/PIN providers remain available. Initial sign-in after boot or sign-out still requires a native method. Support is limited to one password-backed Microsoft account (MSA) with an existing physical-console session. Local accounts, multiple users and remote sessions are not supported.

IPC version 3 removes all signature/phone transport operations. Ordinary processes cannot begin unlock verification, approve it, obtain auto-submit offers or claim passwords. UAC is required for password and binding changes; the service verifies the complete identity of the configured installation target rather than using the administrator account that granted elevation.

Ordinary clients cannot report successful unlocks. Only the original pinned LogonUI claim with matching nonce and current identity/session/binding may report its native result. The last unlock time and RSSI are non-sensitive history held in service memory and cannot create or restore authorization.

Cancellation, expiry, disconnect, suspend, unlock, logoff, account/session change, binding mutation and invalid system association invalidate related authorization. Cached communication, old/missing RSSI, late callbacks and repeated claims cannot authorize release. If RSSI is missing or stale, verification may wait for a fresh reading within the original request deadline; claiming the password still requires fresh communication and signal evidence. Native password failure never restores a consumed grant.

