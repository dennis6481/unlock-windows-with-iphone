# Windows implementation status

Windows is being implemented as separate components because they run under different security and lifecycle boundaries.

## Components

- `GattHost`: packaged C++/WinRT host using Windows GATT Server APIs. It must declare the Bluetooth capability and will be tested in the background/locked-screen lifecycle.
- `UnlockService`: Session 0 Windows Service for challenge state, replay protection, protected public-key enrollment, IPC and audit logging. It must not assume that it can directly host GATT from Session 0.
- `CredentialProvider`: LogonUI tile for `CPUS_UNLOCK_WORKSTATION`. It serializes the custom authentication payload; it is not the component that verifies the iPhone signature.
- `LSAAuthenticationPackage`: LSA-loaded package that validates the custom payload, maps the enrolled public key to a Windows account, and returns the token information required for the logon session.
- `PairingTool`: one-time enrollment and public-key fingerprint confirmation.

## Current code

The CNG P-256 verifier is in [`Protocol/UnlockCrypto.cpp`](Protocol/UnlockCrypto.cpp). It is intentionally a library only. No service, LSA package, registry registration, or system unlock behavior has been installed.

Build on Windows with Visual Studio 2022 and CMake:

```powershell
cmake -S windows -B windows/build -A x64
cmake --build windows/build --config Debug
```

The current macOS workspace cannot compile Windows SDK code. A Windows build is required before any LSA registration is considered.

## Security gate

The LSA DLL will not be registered on a daily-use machine until all of these are true:

1. The public key is enrolled with an explicit user confirmation and mapped to one Windows SID.
2. Challenge freshness, single-use nonces and account mapping are enforced.
3. The LSA package independently verifies the signature.
4. A failure returns an explicit logon failure and leaves Windows Hello/PIN/password available.
5. The package can be removed or disabled from a recovery environment.
