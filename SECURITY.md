<!-- Created by Rui MA on 05 Oct 2026 -->

# Security model and limitations

This is an **experimental developer preview**. It has not undergone an independent security audit and does not guarantee absolute security. Use particular caution on machines containing important confidential information. A working unlock demonstration is not evidence that all attack or failure scenarios have been covered.

## Credentials and encryption

- The iPhone holds a non-exportable Secure Enclave P-256 signing key. Its keychain representation uses `AfterFirstUnlockThisDeviceOnly`, is not synchronized and has no software-key fallback.
- Windows keeps an encrypted **copy of the account password** so its native authentication can still validate the account. This is a password-backed unlock design, not passwordless Windows authentication.
- The dedicated LocalSystem service encrypts that copy using **LocalSystem user-scope DPAPI**, rather than machine-scope DPAPI. Password storage is restricted by SYSTEM-only ACLs. Phone public-key registration is separate protected storage using machine-scope DPAPI.
- The tray and BLE link never receive the password. An eligible LogonUI Credential Provider can obtain it only after valid phone approval. The service consumes that approval before decrypting; plaintext is cleared where controlled and CP submits through native Negotiate.

DPAPI, ACLs and caller checks do not protect against an attacker who controls SYSTEM, the kernel or the relevant running processes. Plaintext exists transiently during native credential submission. Deleting files does not guarantee physical erasure from SSDs, backups or snapshots.

## Authentication boundaries

Requests use a random nonce, canonical ECDSA P-256/SHA-256 payload and the locally registered phone key. Approval is short-lived, bound to identity/session/lock generation and consumed once. IPC separates ordinary-user transport, elevated management and eligible LogonUI operations. Pairing requires an unlocked desktop and full-fingerprint confirmation; alternate administrator elevation does not select a different target account.

The application does **not remove, disable or replace the original Windows password/PIN sign-in providers**. Initial sign-in after boot or sign-out still uses a native Windows method. Phone approval permits a native password attempt; Windows remains the authentication authority. Keep a working native sign-in method available during experiments.

## Proximity, device access and trust

RSSI is only a configurable signal-strength heuristic. It does not prove a fixed distance and is not a cryptographic distance bound or a defense against relay attacks. ComputerId identifies the configured target for routing; it does not authenticate the Windows server cryptographically.

Automatic response does not require fresh Face ID/Touch ID or a confirmation tap for each signature. The key can be usable after the first phone unlock following restart, even while the phone is subsequently locked. Physical possession and phone settings therefore matter.

`unlock_approved` reports a service grant, not proof that the desktop unlocked. Expired requests, consumed grants, stale callbacks or native password failure cannot authorize a second attempt without a fresh request/signature. The [protocol](Protocol.md) specifies the exact boundaries.

## Diagnostics and reporting

Do not publish passwords, private keys, provisioning/signing material or raw credential data. Diagnostic code retains account/SID/session and device/request identifiers when needed to establish identity and timing; redact personal identifiers in shared reports while keeping restricted original evidence.

When reporting a suspected issue, include the affected revision, platform versions and a sanitized reproduction. Avoid putting credentials or exploit-sensitive details in public issues. Use GitHub's private vulnerability-reporting entry if it is available for the repository; this document does not promise that a private channel or response SLA is configured.

There is no separate security-maintenance commitment for historical experimental revisions. The [testing guide](docs/Testing.md) lists identity, caller, replay and failure checks; passing those checks does not constitute a security audit.
