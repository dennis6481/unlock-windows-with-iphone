<!-- Created by Rui MA on 26 Sep 2026 -->
<!-- Modified by Codex on 26 Sep 2026 -->

# UnlockService core

`UnlockServiceCore` is the security-state library that is now exercised through the foreground `unlock_service_host` named-pipe prototype and will later be hosted by the Session 0 Windows Service. It currently:

- issues version-1 challenges with a fresh request ID and 32-byte nonce;
- serializes the challenge using the protocol JSON envelope;
- parses assertion JSON through Windows C++/WinRT JSON APIs;
- checks request ID, version, challenge lifetime and single-use state;
- checks the P-256 raw public-key shape and SHA-256 key fingerprint;
- requires the raw public key to match the explicitly installed enrollment key;
- rebuilds the fixed signing payload and verifies the raw 64-byte ECDSA signature through CNG.
- returns `unlock_approved` only when the signature is valid and the enrolled Windows SID is loaded; this is a decision signal for a future Credential Provider/LSA path, not a system unlock operation.

The IPC prototype uses a local named pipe, checks that the connecting process belongs to the same Windows user, and supports issue-challenge, verify-assertion and reload-enrollment requests. `EnrollmentStore` persists one 65-byte P-256 public key together with the enrolling user's validated Windows SID under `%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat`; the record is protected with DPAPI machine scope and an ACL limited to SYSTEM, Administrators and the current Windows user. `unlock_pairing_tool` is the only current enrollment writer and requires explicit notification confirmation. GATT transports a candidate key to that tool but never writes the enrollment file directly. The SID record and `unlock_approved` decision are now ready for later account mapping, while creating a real Windows Service and using the mapping during logon are still pending.
