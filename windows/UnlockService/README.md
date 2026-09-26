<!-- Created by Rui MA on 26 Sep 2026 -->

# UnlockService core

`UnlockServiceCore` is the security-state library that is now exercised through the foreground `unlock_service_host` named-pipe prototype and will later be hosted by the Session 0 Windows Service. It currently:

- issues version-1 challenges with a fresh request ID and 32-byte nonce;
- serializes the challenge using the protocol JSON envelope;
- parses assertion JSON through Windows C++/WinRT JSON APIs;
- checks request ID, version, challenge lifetime and single-use state;
- checks the P-256 raw public-key shape and SHA-256 key fingerprint;
- requires the raw public key to match the explicitly installed enrollment key;
- rebuilds the fixed signing payload and verifies the raw 64-byte ECDSA signature through CNG.

The IPC prototype uses a local named pipe, checks that the connecting process belongs to the same Windows user, and supports issue-challenge and verify-assertion requests. It does not yet persist enrolled keys, map a key to a Windows SID, or create a Windows Service. The prototype intentionally starts without an enrollment key, so a valid iPhone assertion returns `key_not_enrolled` until the pairing flow is implemented.
