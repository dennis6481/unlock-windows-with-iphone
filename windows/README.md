# Windows implementation status

Windows is being implemented as separate components because they run under different security and lifecycle boundaries.

## Components

- `GattHost`: C++/WinRT foreground transport prototype is now present in `GattHost/main.cpp`. It creates the service, four characteristics, challenge notifications and assertion/result transport. Packaging and locked-screen/background lifecycle are still pending.
- `UnlockService`: `UnlockServiceCore` now owns challenge freshness, single-use state, assertion JSON parsing, key fingerprint matching and CNG verification in an isolated library. The Session 0 service process and IPC endpoint are still pending.
- `CredentialProvider`: LogonUI tile for `CPUS_UNLOCK_WORKSTATION`. It serializes the custom authentication payload; it is not the component that verifies the iPhone signature.
- `LSAAuthenticationPackage`: LSA-loaded package that validates the custom payload, maps the enrolled public key to a Windows account, and returns the token information required for the logon session.
- `PairingTool`: one-time enrollment and public-key fingerprint confirmation.

## Current code

The CNG P-256 verifier is in [`Protocol/UnlockCrypto.cpp`](Protocol/UnlockCrypto.cpp). `ProtocolTests/main.cpp` tests the fixed payload and raw signature path. `UnlockService/UnlockServiceCore.cpp` adds the in-memory challenge, enrollment-key check and assertion verification boundary; `UnlockServiceTests/main.cpp` covers valid authentication, unenrolled-key rejection, malformed input, request mismatch, expiration and replay rejection. No Windows Service, LSA package, registry registration or system unlock behavior has been installed.

Build on Windows with Visual Studio 2022 and CMake:

```powershell
cmake -S windows -B windows/build -A x64
cmake --build windows/build --config Debug
ctest --test-dir windows/build -C Debug --output-on-failure
```

The current Windows build has three targets: `unlock_protocol_tests`, `unlock_service_tests` and the foreground `unlock_gatt_host`. The local NMake/SDK setup can run the same checks with `ctest --test-dir windows/build --output-on-failure`.

The current macOS workspace cannot compile Windows SDK code. A Windows build is required before any LSA registration is considered.

## Security gate

The LSA DLL will not be registered on a daily-use machine until all of these are true:

1. The public key is enrolled with an explicit user confirmation and mapped to one Windows SID.
2. Challenge freshness, single-use nonces and account mapping are enforced.
3. The LSA package independently verifies the signature.
4. A failure returns an explicit logon failure and leaves Windows Hello/PIN/password available.
5. The package can be removed or disabled from a recovery environment.
