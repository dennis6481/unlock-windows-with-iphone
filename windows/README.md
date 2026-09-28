<!-- Modified by Rui MA on 26 Sep 2026 -->

# Windows implementation status

Windows is being implemented as separate components because they run under different security and lifecycle boundaries.

## Components

- `GattHost`: C++/WinRT foreground transport prototype is now present in `GattHost/main.cpp`. It creates the service, four characteristics, challenge notifications and assertion/result transport. Packaging and locked-screen/background lifecycle are still pending.
- `UnlockService`: `UnlockServiceCore` now owns challenge freshness, single-use state, assertion JSON parsing, key fingerprint matching, CNG verification, the enrolled Windows SID decision and a one-time short-lived approval handoff in an isolated library. A valid assertion with the enrolled SID returns `unlock_approved`; `unlock_service_host` can consume that approval through a same-user named-pipe boundary as a binary `UnlockLogonBuffer`. Conversion to a real Session 0 service is still pending.
- `CredentialProvider`: a build-only V2 COM shell for a `CPUS_LOGON`/`CPUS_UNLOCK_WORKSTATION` LogonUI tile. Windows 10 and later normally request `CPUS_LOGON` on the lock screen, while policy-restricted systems can request `CPUS_UNLOCK_WORKSTATION`. It associates the credential with the current user SID through `ICredentialProviderSetUserArray` and `ICredentialProviderCredential2`. It is not registered by the normal build; guarded VM-only scripts can register and roll it back for lock-screen smoke testing. `GetSerialization` looks up the named LSA package before consuming one approved `UnlockLogonBuffer`, and returns no credential while that package is absent. The LSA package must still verify the buffer independently.
- `LSAAuthenticationPackage`: build-only LSA package prototype. It independently validates the custom payload, maps the enrolled public key to a Windows SID, and prepares the token information required for a future logon session; it is not registered.
- `PairingTool`: one-time enrollment and public-key fingerprint confirmation through a Windows notification with Confirm/Cancel buttons.

## Current code

The CNG P-256 verifier is in [`Protocol/UnlockCrypto.cpp`](Protocol/UnlockCrypto.cpp). `ProtocolTests/main.cpp` tests the fixed payload, raw signature path and the shared `UnlockLogonBuffer` codec. `UnlockService/UnlockServiceCore.cpp` adds the in-memory challenge, enrollment-key check, assertion verification, `unlock_approved` decision boundary, short approval cooldown and one-time approval consumption; `EnrollmentStore` protects the enrolled raw public key plus the enrolling user's validated Windows SID with DPAPI and an administrative ACL; `UnlockServiceTests/main.cpp` covers valid authentication with SID approval, unenrolled-key rejection, malformed input, request mismatch, expiration, replay rejection, cooldown suppression and approval consumption. `LSAAuthenticationPackage/UnlockLsaLogonVerifier.cpp` independently rechecks the buffer, enrollment mapping and signature for the build-only LSA package. No Windows Service, LSA registry registration or system unlock behavior has been installed.

Build on Windows with Visual Studio 2026, CMake, and Make. The Makefile
automatically reads the native Windows processor architecture and starts the
matching Visual Studio environment (`x64` or `arm64`). It also reconfigures the
existing build directory before every build, so an x64 CMake cache is not
reused for an ARM64 DLL or vice versa:

```powershell
cd windows
make
```

The current Windows build has thirteen relevant targets: the six tests, `unlock_service_host`, the foreground `unlock_gatt_host`, the enrollment `unlock_pairing_tool`, the native `unlock_windows_components_wizard.exe`, the build-only `unlock_credential_provider.dll`, the build-only `unlock_lsa_authentication_package.dll` and the read-only `unlock_lsa_package_lookup.exe`. The IPC test uses a dedicated test pipe, so it can run while the real `UnlockService` host is active. `unlock_enrollment_store_tests` verifies the DPAPI protect/load round trip and the Windows SID round trip. `unlock_credential_provider_tests` loads the DLL without registration, verifies both `CPUS_LOGON` and `CPUS_UNLOCK_WORKSTATION` enumeration, returns no credential, and validates the separate serialization adapter against `UnlockLogonBuffer`. `unlock_lsa_authentication_package_tests` verifies independent buffer verification and package exports without loading the package into LSASS. `unlock_lsa_package_lookup.exe` only checks whether the package is visible through LSA after an explicit VM registration and reboot. The Visual Studio/CMake setup can run the tests with `ctest --test-dir windows/build --output-on-failure`.

For a shorter command, use the repository Makefile from this directory:

```powershell
cd windows
make                 # configure, build and run tests
make build           # build only
make build-release   # build Release binaries (no Debug CRT)
make release         # alias for make build-release
make test            # build and run tests
make run-service     # start UnlockService in the foreground
make run-gatt        # start GattHost in the foreground
```

The Makefile locates the newest installed Visual Studio instance with `vswhere`,
requires the matching native C++ toolset, initializes its environment
automatically, detects the native Windows architecture before selecting the
matching toolchain, uses the NMake Makefiles generator,
keeps build outputs in `build`, and redirects compiler/linker temporary files
to the repository-root `.tmp` directory when the system drive is low on space.
The shortcut does not require manually entering a long command:

```cmd
make build
make build-release
make test
```

The Makefile uses the existing `build` directory and the `Debug` configuration by default. Use `make CONFIG=Release` to select another configuration. `TARGET_ARCH=auto` is the default; it detects the native Windows architecture. `TARGET_ARCH=x64` or `TARGET_ARCH=arm64` is available only for deliberate cross-compilation. `VS_DEV_CMD=auto` locates Visual Studio; set `VS_DEV_CMD` to a full `VsDevCmd.bat` path only for a nonstandard installation. Build outputs stay in `windows/build`; only tool temporary files go to the root `.tmp` directory.

The current macOS workspace cannot compile Windows SDK code. A Windows build is required before any LSA registration is considered.

For the disposable VM smoke test, build Release and copy the complete
`windows/build` directory to the VM. The VM does not need Visual Studio, CMake
or Make. Double-click `unlock_windows_components_wizard.exe` (or start it from
an elevated command prompt) to install and uninstall the Credential Provider
and LSA package together:

```powershell
# On the Windows build machine
cd .\windows
make build-release

# In the VM, after copying the complete build directory
cd .\build
.\unlock_windows_components_wizard.exe
```

The EXE asks Windows for elevation and checks that it, both source DLLs and
Windows have the same native architecture. On Windows 11 ARM they must all be
ARM64. It installs both components, asks for a reboot, and can verify the LSA
package ID afterward. It intentionally refuses an existing installation: the
update/overwrite path is not implemented. Its uninstall first restores both
registry configurations, then records a pending cleanup. The automatic logon
task is still under verification on Windows 11. If it does not open the EXE
after reboot, run `unlock_windows_components_wizard.exe --resume-uninstall`
from the build directory to remove both DLLs and the wizard state. No
PowerShell continuation is used.
Reboot or sign out, keep `UnlockService` running in the VM, and check whether
the “Unlock Windows with iPhone” tile appears on the unlock screen. The prior
VM build rejected `CPUS_LOGON`, so LogonUI showed only PIN despite a successful
LSA lookup, Credential Provider registry/DLL check and direct COM smoke test.
The current build accepts `CPUS_LOGON`; confirm the deployed DLL hash and
observe whether `LogonUI.exe` loads it. This provider test still requires LSA
Protection to be disabled in the disposable VM and does not yet prove automatic
unlock or production compatibility.

`Windows-Unlock-Components-Wizard.ps1` remains only as a compatibility
launcher for the EXE; it does not install, uninstall, or schedule a
continuation itself.

## Security gate

The LSA DLL will not be registered on a daily-use machine until all of these are true:

1. The public key is enrolled with an explicit notification confirmation, stored with DPAPI/ACL protection, and persisted together with one validated Windows SID.
2. Challenge freshness, single-use nonces and the `unlock_approved` account decision are enforced.
3. The LSA package independently verifies the signature.
4. A failure returns an explicit logon failure and leaves Windows Hello/PIN/password available.
5. The package can be removed or disabled from a recovery environment.
