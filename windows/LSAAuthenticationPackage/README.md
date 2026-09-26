# LSAAuthenticationPackage

This is the final passwordless authentication boundary. The package will be loaded by LSA and implement the package callbacks required for a custom authentication package, including an `LsaApLogonUserEx2` path for the custom logon buffer.

The custom buffer is `Protocol/UnlockLogonBuffer.h`. It contains the enrolled-key identifier, Windows account mapping, request identifier, nonce, timestamp/audience fields and iPhone signature. The package must resolve the enrolled public key, reconstruct the fixed binary signing payload and call the shared CNG verifier itself. It must not trust a result sent by `UnlockService` or a desktop UI process. The key-to-SID mapping and the outstanding-challenge/nonce state must be protected independently of the Credential Provider.

The implementation is intentionally not a loadable DLL yet. Returning an incomplete token structure or registering an untested package can affect system logon. The first code milestone here is an isolated token/account-mapping test on a disposable Windows VM, followed by explicit install and rollback scripts.
