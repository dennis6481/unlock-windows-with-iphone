# Windows protocol verifier

`SigningPayload.cpp` and `UnlockCrypto.cpp` are the first Windows-side implementation of the authentication boundary. The former reconstructs the fixed signing bytes; the latter uses Windows CNG (`bcrypt.dll`) to verify the raw P-256 public key and raw `r || s` signature emitted by the iOS target.

The verifier is deliberately independent of BLE, JSON parsing, the Windows Service, Credential Provider and LSA. Those layers must pass it the exact fixed binary signing payload described in [`../../protocol/README.md`](../../protocol/README.md).

`UnlockLogonBuffer.h` defines the package-specific `ProtocolSubmitBuffer` shared by the Credential Provider and the LSA package. It contains an enrolled key ID, challenge fields, the selected account SID and the iPhone signature, but never a Windows password. The LSA package must resolve the key ID to its protected enrollment record and compare the mapped SID; it must not trust the SID field by itself.

Important rules:

- The iOS public key is SEC1 uncompressed `0x04 || X || Y` (65 bytes).
- The signature is fixed-width `r || s` (64 bytes), not DER.
- The verifier hashes the signing payload with SHA-256 before calling `BCryptVerifySignature`.
- Invalid arguments, invalid signatures and CNG failures are different results.
- There is no software-key fallback and no “nearby device” acceptance path.

This library does not yet register or load an LSA package. It is a reusable primitive for both `UnlockService` and the final `LSAAuthenticationPackage`, where the latter must perform its own verification rather than trust a desktop process.
