<!-- Modified by Rui MA on 26 Sep 2026 -->
<!-- Modified by Codex on 26 Sep 2026 -->

# Windows implementation status

Windows is being implemented as separate components because they run under different security and lifecycle boundaries.

## Components

- `GattHost`: C++/WinRT foreground transport prototype is now present in `GattHost/main.cpp`. It creates the service, four characteristics, challenge notifications and assertion/result transport. Packaging and locked-screen/background lifecycle are still pending.
- `UnlockService`: `UnlockServiceCore` now owns challenge freshness, single-use state, assertion JSON parsing, key fingerprint matching and CNG verification in an isolated library. `unlock_service_host` exercises it through a same-user named-pipe boundary and loads the explicitly enrolled public key from the protected local store; conversion to a real Session 0 service is still pending.
- `CredentialProvider`: LogonUI tile for `CPUS_UNLOCK_WORKSTATION`. It serializes the custom authentication payload; it is not the component that verifies the iPhone signature.
- `LSAAuthenticationPackage`: LSA-loaded package that validates the custom payload, maps the enrolled public key to a Windows account, and returns the token information required for the logon session.
- `PairingTool`: one-time enrollment and public-key fingerprint confirmation through a Windows notification with Confirm/Cancel buttons.

## Current code

The CNG P-256 verifier is in [`Protocol/UnlockCrypto.cpp`](Protocol/UnlockCrypto.cpp). `ProtocolTests/main.cpp` tests the fixed payload and raw signature path. `UnlockService/UnlockServiceCore.cpp` adds the in-memory challenge, enrollment-key check and assertion verification boundary; `EnrollmentStore` protects the enrolled raw public key plus the enrolling user's validated Windows SID with DPAPI and an administrative ACL; `UnlockServiceTests/main.cpp` covers valid authentication, unenrolled-key rejection, malformed input, request mismatch, expiration and replay rejection. No Windows Service, LSA package, registry registration or system unlock behavior has been installed.

Build on Windows with Visual Studio 2026 and CMake from a Developer Command Prompt:

```powershell
cmake -S windows -B windows/build -G "NMake Makefiles"
cmake --build windows/build --config Debug
ctest --test-dir windows/build -C Debug --output-on-failure
```

The current Windows build has seven runnable targets: `unlock_protocol_tests`, `unlock_service_tests`, `unlock_service_ipc_tests`, `unlock_enrollment_store_tests`, `unlock_service_host`, the foreground `unlock_gatt_host` and the enrollment `unlock_pairing_tool`. The IPC test uses a dedicated test pipe, so it can run while the real `UnlockService` host is active. `unlock_enrollment_store_tests` verifies the DPAPI protect/load round trip and the Windows SID round trip. The Visual Studio/CMake setup can run the tests with `ctest --test-dir windows/build --output-on-failure`.

For a shorter command, use the repository Makefile from this directory:

```powershell
cd windows
make                 # configure, build and run tests
make build           # build only
make test            # build and run tests
make run-service     # start UnlockService in the foreground
make run-gatt        # start GattHost in the foreground
```

The Makefile initializes the Visual Studio environment automatically, uses the NMake Makefiles generator, keeps build outputs in `build`, and redirects compiler/linker temporary files to the repository-root `.tmp` directory when the system drive is low on space. The shortcut does not require manually entering a long command:

```cmd
make build
make test
```

The Makefile uses the existing `build` directory and the `Debug` configuration by default. Use `make CONFIG=Release` to select another configuration. Build outputs stay in `windows/build`; only tool temporary files go to the root `.tmp` directory.

The current macOS workspace cannot compile Windows SDK code. A Windows build is required before any LSA registration is considered.

## Security gate

The LSA DLL will not be registered on a daily-use machine until all of these are true:

1. The public key is enrolled with an explicit notification confirmation, stored with DPAPI/ACL protection, and persisted together with one validated Windows SID.
2. Challenge freshness, single-use nonces and account mapping are enforced.
3. The LSA package independently verifies the signature.
4. A failure returns an explicit logon failure and leaves Windows Hello/PIN/password available.
5. The package can be removed or disabled from a recovery environment.
