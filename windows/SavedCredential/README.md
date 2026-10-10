<!-- Created by Rui MA on 01 Oct 2026 -->

# Saved credential service

The LocalSystem service is the Windows authority for requests, phone approval and password release. Saved identity consists of SID, the Windows-qualified account name and ProviderID; a matching SID alone is insufficient when the online identity has changed.

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

After the first native sign-in, choose **Start setup** on the installation result page or launch `--setup`. The elevated WinUI password window verifies the installed target account. Only a saved copy matching the complete verified identity permits skipping the password step. Setup also requires the service to reload phone registration before handing control back to the ordinary tray. Saving a copy successfully advances to the existing iPhone pairing window; cancellation and failure do not. For independent maintenance, open tray **Password…** and choose save, update or removal.

`credentialSummary` returns the verified account and saved-copy state to the unlocked installation target's ordinary console session. It returns no password or snapshot nonce and creates no management snapshot or phone approval. The management pipe accepts local authenticated connections, but status/nonces and credential changes still require an administrator; phone-pipe operations remain unchanged.

Before a console user token exists, `captureProvisioningIdentity` accepts only a real physical-console LogonUI caller and the installer-recorded target SID. It records system-provided identity metadata in memory and returns no password, snapshot nonce or phone grant.

After sign-in, queries use `NetUserGetInfo` level 24 for the online provider/name and local SID, and match unfiltered identity-store entries by PrimarySid for ProviderID. The qualified name uses Windows `provider\principal` format; the store's QualifiedUserName property is not required. Target, console and logon checks remain required. Service restart does not require another lock/unlock cycle.

The snapshot lasts five minutes. A new management query can renew it without another sign-in. Candidates are invalidated by logoff, console disconnection, another console account or service restart. Unavailable or ambiguous Windows identity properties are explicit verification failures. The target is the console user, not an alternate administrator entered at UAC. Identity must not be reconstructed from diagnostics or the saved credential.

The main Password page refreshes on entry, activation and operation-window exit. Refresh is in the page header; Save/Update and removal sit side by side. Unknown state disables password changes. The elevated window contains PasswordBox, Save/Update and Cancel; a failed query replaces the primary action with Retry. Removal uses ContentDialog with Cancel as default. InfoBar reports results/errors. **Remove saved password** clears only the local copy. Closing the window leaves the ordinary tray running.

## Removal and maintenance

Installer `clearForRemoval` must receive service confirmation that the password, grant, snapshot and challenge were cleared before removal continues. There is no success path that skips a failed credential-clear operation.

Keep identity checks, consume-before-decrypt ordering, endpoint separation and impersonation boundaries intact during maintenance. Logs must not include passwords, nonce bytes, keys or assertion bodies. See the [testing guide](../../docs/Testing.md#authentication-and-security-boundaries) for caller, identity, replay and restart scenarios.
