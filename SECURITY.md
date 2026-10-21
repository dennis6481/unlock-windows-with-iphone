<!-- Created by Rui MA on 26 Sep 2026 -->
<!-- Modified by Liam on 21 Oct 2026 -->

# Security

## Credential protection

- The saved Windows account password remains on the PC, protected by **LocalSystem user-scope DPAPI** and SYSTEM-only vault ACLs. The storage format remains unchanged.
- Product binding uses separate machine-bound DPAPI storage, with SYSTEM/administrator-only write permissions and atomic commit. Ordinary desktop clients read only non-sensitive service summaries.
- Neither the phone nor the desktop app receives the password. Only a verified LogonUI process can claim it after a fresh presence check. The service consumes the authorization before decrypting the password; the Credential Provider submits it through native Negotiate.
- SYSTEM, administrator or kernel compromise is outside this protection boundary. Plaintext under the application's control is cleared where practical; removing the saved copy does not guarantee erasure from backups or SSD history.

## Presence authorization

By default the user explicitly clicks **Unlock** on the PC. An administrator may enable automatic verification when the existing user's locked sign-in UI activates, **without requiring sleep**. A Win+L lock can immediately auto-unlock when the authorized iPhone is nearby; a display-off/on event can re-arm one additional attempt while the same session stays locked. The phone needs no fresh Face ID, Touch ID, tap or app interaction. **An unattended PC can unlock when someone wakes it with the authorized phone nearby.** Keep this mode off on shared or security-sensitive systems.

For unlock, the service checks the selected system-paired BLE endpoint ID, authenticated Secure Connections pairing records, fresh protected ANCS/CCCD operations and current address/type-associated RSSI. Full account identity, request, binding, connection, session, logon and lock generation remain bound to one short-lived, single-use authorization.

Binding verifies secure pairing and fresh protected communication without starting RSSI collection or authorizing password release. RSSI collection has separate request-local evidence; samples from another endpoint, address/type, connection revision or request cannot authorize unlock. After collecting RSSI, the session rechecks the target and communication state together under its lock.

Connections and Windows-cached service structure may persist across unlocks. They are not authorization: every request resets its evidence and performs new protected operations. Background connection/reconnection never releases credentials.

**Pairing records are not independent proof of current-link LESC mode or key reuse.** Successful authenticated/encrypted GATT requests prove the requested protected operation succeeded, within the Windows API boundary.

**RSSI is not a secure measure of distance.** Advertisements are unauthenticated, can be spoofed or relayed, and may be missing during standby or address rotation. A nearby signal is a presence hint, not proof of the phone user's intent or resistance to a relay attack.

## Windows boundaries

Original password/PIN providers remain available. Initial sign-in after boot or sign-out still requires a native method. Support is limited to one password-backed Microsoft or local Windows account with an existing physical-console session. Local-account support is experimental; multiple users and remote sessions are not supported.

IPC version 3 removes all signature/phone transport operations. Ordinary processes cannot begin unlock verification, approve it, obtain auto-submit offers or claim passwords. UAC is required for password and binding changes; the service verifies the complete identity of the configured installation target rather than using the administrator account that granted elevation.

Ordinary clients cannot report successful unlocks. Only the original pinned LogonUI claim with matching nonce and current identity/session/binding may report its native result. The last unlock time and RSSI are non-sensitive history held in service memory and cannot create or restore authorization.

Cancellation, expiry, disconnect, suspend, unlock, logoff, account/session change, binding mutation and invalid selected BLE pairing invalidate related authorization. Cached communication, old/missing RSSI, late callbacks and repeated claims cannot authorize release. If RSSI is missing or stale, verification may wait for a fresh reading within the original request deadline; fresh qualifying RSSI permits renewal of time-expired communication within that same deadline. Claiming the password still requires fresh communication and signal evidence. Native password failure never restores a consumed grant.

