<!-- Created by Rui MA on 26 Sep 2026 -->

# UnlockService core

`UnlockServiceCore` is the security-state library that will be hosted by the future Session 0 Windows Service. It currently:

- issues version-1 challenges with a fresh request ID and 32-byte nonce;
- serializes the challenge using the protocol JSON envelope;
- parses assertion JSON through Windows C++/WinRT JSON APIs;
- checks request ID, version, challenge lifetime and single-use state;
- checks the P-256 raw public-key shape and SHA-256 key fingerprint;
- requires the raw public key to match the explicitly installed enrollment key;
- rebuilds the fixed signing payload and verifies the raw 64-byte ECDSA signature through CNG.

It does not yet persist enrolled keys, map a key to a Windows SID, expose IPC, or create a Windows Service. Those boundaries remain deliberately outside the GATT transport process and must be added before any unlock decision is connected to LogonUI or LSA.
