<!-- Created by Rui MA on 01 Oct 2026 -->

# Saved credential service

The LocalSystem service is the Windows authority for requests, phone approval and password release. Saved identity consists of SID, the original system QualifiedUserName and ProviderID; a matching SID alone is insufficient when the online identity has changed.

## Password protection

The vault uses **LocalSystem user-scope DPAPI**, with `CRYPTPROTECT_UI_FORBIDDEN`, not `CRYPTPROTECT_LOCAL_MACHINE`. Password files/directories have SYSTEM-only ACLs. Controlled plaintext is cleared as early as practical. Credentials are packed by CP inside LogonUI, not by the service in Session 0.

This protection does not resist an administrator who obtains SYSTEM or a compromised kernel. Registration is separate public-key/SID storage using machine-scope DPAPI. Read [SECURITY.md](../../SECURITY.md) for limits.

## Authentication and IPC

`unlockEligibility` checks an existing physical-console token, SID, session and explicit locked state. An eligible LogonUI caller can create a request only when its captured identity, saved identity and registration agree. The service owns all request/grant deadlines; the [protocol](../../PROTOCOL.md#request-and-one-time-approval) specifies their lifetimes.

The phone pipe allows only status peek, one-time challenge delivery, phone failure reports and assertion submission. It cannot begin a request or access a password. Peeking neither returns nor consumes the challenge. Late failures cannot overwrite a later request.

The saved-credential pipe authorizes operations according to administrator, current console and eligible LogonUI roles. Real pipe tokens, client PID/session, SYSTEM identity and required process image are checked with retained process handles. Impersonation must end before DPAPI operates as LocalSystem. Internal IPC version 2 rejects incompatible messages; matching builds use the same header/operation definitions.

Authentication states distinguish idle, waitingPhone, awaitingAssertion, approved, failed and consumed. Errors retain phase/reason rather than classifying every failure as a session change. Operations re-query the console; unrelated session notifications do not invalidate its request.

Only a valid phone assertion creates a grant. `takeAutoSubmitOffer` returns a non-secret one-time offer to eligible LogonUI. `claimCredential` rechecks identity/session and **consumes the grant before decrypting**. CP rebuilding, packing failure and native password rejection cannot restore it. Actual unlock, identity/session change, expiry and service restart invalidate outstanding approval.

## Password management

After the first native sign-in, choose **Start setup** on the installation result page or **Continue setup…** from the ordinary tray. The existing elevated password window verifies the installed target account. Only a saved copy matching the complete verified identity permits skipping the password step. Setup also requires the service to reload phone registration before handing control back to the ordinary tray. Saving a copy successfully advances to the existing iPhone pairing window; cancellation and failure do not. **Manage saved password…** remains available for independent maintenance.

Before a console user token exists, `captureProvisioningIdentity` accepts only a real physical-console LogonUI caller and the installer-recorded target SID. It records system-provided identity metadata in memory and returns no password, snapshot nonce or phone grant. After native sign-in, a management status request validates the actual console token/SID and binds the candidate to its logon authentication ID before creating a snapshot.

The snapshot lasts five minutes. **Refresh** can issue a new snapshot for the same verified console without another sign-in. Candidates are invalidated by logoff, console disconnection, another console account or service restart. An unavailable candidate is an explicit verification failure; the UI offers Refresh and retains technical diagnostics. The target is the console user, not an alternate administrator entered at UAC. Identity must not be reconstructed from diagnostics.

**Remove saved password…** clears the local copy after confirmation. It does not change the account's actual Windows/online password. Closing the window leaves the ordinary tray running. Technical details retain SID, QualifiedUserName, ProviderID and original errors for diagnosis.

## Removal and maintenance

Installer `clearForRemoval` must receive service confirmation that the password, grant, snapshot and challenge were cleared before removal continues. There is no success path that skips a failed credential-clear operation.

Keep identity checks, consume-before-decrypt ordering, endpoint separation and impersonation boundaries intact during maintenance. Logs must not include passwords, nonce bytes, keys or assertion bodies. See the [testing guide](../../docs/Testing.md#authentication-and-security-boundaries) for caller, identity, replay and restart scenarios.
