<!-- Modified by Rui MA on 27 Sep 2026 -->
<!-- Modified by Rui MA on 28 Sep 2026 -->

# LSAAuthenticationPackage

This is the final passwordless authentication boundary. The repository now
contains a build-only DLL with the package callbacks required for a custom
authentication package, including an `LsaApLogonUserEx2` path for the custom
logon buffer. It is not registered with LSA by the build.

The custom buffer is `Protocol/UnlockLogonBuffer.h`. The build-only package
resolves the enrolled public key, reconstructs the fixed binary signing
payload and calls the shared CNG verifier itself. It does not trust a result
sent by `UnlockService` or a desktop UI process. It independently checks the
key ID, registered SID, audience and freshness, and prepares
`LSA_TOKEN_INFORMATION_V2` with the enrolled SID. A process-lifetime request
ID cache also rejects a second submission of the same buffer.

The implementation is intentionally not registered yet. The isolated tests
cover the verifier and DLL exports, but real LSA loading, registry
registration, token creation and lock-screen behavior still require a
disposable Windows VM followed by explicit install and rollback scripts.

## VM-only smoke test

`LookupAuthenticationPackage.cpp` builds `unlock_lsa_package_lookup.exe`. It
only calls `LsaLookupAuthenticationPackage`; it does not change the registry.
After the package has been installed and the VM rebooted, run:

```powershell
.\windows\build\unlock_lsa_package_lookup.exe
```

Success prints the LSA-assigned package ID. A nonzero result means that LSA
did not recognize the package; do not proceed to the lock-screen test.

### LSA Protection limitation

On Windows with LSA Protection enabled, this unsigned development DLL is
blocked by Code Integrity and lookup reports `not loaded`, even when the
registry entry and `System32` copy are correct. The current VM smoke test must
therefore run only in a disposable VM with LSA Protection disabled and after a
reboot. A successful package ID lookup in that VM does not prove production
compatibility.

Production LSA loading requires a Microsoft-signed LSA plugin. A normal
Authenticode or self-signed certificate is not sufficient; the production
path requires an EV certificate and Microsoft Partner Center LSA file
signing.

Use the native Components Wizard EXE. It requests elevation itself and must be
built for the native Windows architecture:

```powershell
# On the Windows build machine
cd .\windows
make build-release

# In the VM, after copying the complete build directory
cd .\build
.\unlock_windows_components_wizard.exe
```

The wizard installs this package together with the Credential Provider. It
backs up the `Authentication Packages` `REG_MULTI_SZ` value, detects the native
x64 or ARM64 architecture, verifies that both DLLs and the EXE match it, copies
the native DLLs to `System32`, and adds only the package DLL base name. It
refuses an existing installation; overwrite/update is not implemented. For
uninstall, it restores both registry configurations and requires a reboot. The
automatic logon task is still under verification on Windows 11; if it does not
launch the EXE after reboot, run
`unlock_windows_components_wizard.exe --resume-uninstall` from the build
directory to delete both DLLs and wizard state. No typed VM confirmation,
PowerShell `-Confirm` prompt, or PowerShell continuation is required.

The underlying LSA-only scripts remain available for automation:

```powershell
.\windows\LSAAuthenticationPackage\Uninstall-TestLsaAuthenticationPackage.ps1
# reboot the VM
.\windows\LSAAuthenticationPackage\Uninstall-TestLsaAuthenticationPackage.ps1 `
    -RemoveFile
```

The second rollback step removes the package DLL and then deletes the rollback
JSON. The backup is intentionally retained between the registry-restore step
and the final file-removal step.

The enrolled key must be created inside the VM. DPAPI enrollment data from
the development host must not be copied into the VM. Take a VM snapshot
before any registration and keep Windows Hello/PIN/password available for
recovery. The package is still not registered by the normal build.
