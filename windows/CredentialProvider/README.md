<!-- Created by Rui MA on 27 Sep 2026 -->
<!-- Modified by Rui MA on 28 Sep 2026 -->

# Credential Provider prototype

This directory contains a build-only V2 Credential Provider shell supporting
both `CPUS_LOGON` and `CPUS_UNLOCK_WORKSTATION`. Windows 10 and later normally
use `CPUS_LOGON` while unlocking, while policy-restricted systems can still use
`CPUS_UNLOCK_WORKSTATION`. It obtains the current user SID through
`ICredentialProviderSetUserArray` and exposes one read-only “Unlock Windows with
iPhone” tile associated with that user. The V2 field set includes the
Credential Provider logo field required by the LogonUI sign-in-options surface,
using a generated test bitmap so the COM contract can be tested against the
installed Windows SDK.

The serialization adapter can pack an already-approved challenge, key ID,
raw SID and raw `r || s` signature into the shared `UnlockLogonBuffer` and the
Windows `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION` shape. It does not
verify the signature, fetch a password, or accept data from an environment
variable. A future protected IPC client will supply the approval; the LSA
Authentication Package must verify it independently.

The current prototype deliberately does not:

- register a Credential Provider CLSID;
- submit a password, PIN, software key or Windows logon token;
- trust an `unlock_approved` result as a login token;
- load or register an LSA Authentication Package;
- claim that selecting the tile unlocks Windows.

The service-side protected, short-lived approval handoff now exposes a
one-time binary buffer over the development named pipe. The COM tile first
looks up the named LSA package and only then consumes that buffer; if the LSA
package is absent it returns `CPGSR_NO_CREDENTIAL_FINISHED` without consuming
the approval. `CredentialProviderTests` loads the DLL directly,
instantiates it through `DllGetClassObject`, verifies the V2 user association,
the unlock-workstation tile and that no credential serialization is returned.
The same test also validates the separate serialization adapter against the
shared codec; it is not a bypass around the protected handoff.

## VM-only registration

The repository contains a native Windows installer EXE for a disposable VM. It
installs this Credential Provider together with the LSA package, copies the
native DLLs to `System32`, registers the COM class and adds the Credential
Provider registration. Before making any change, it detects the native Windows
architecture and rejects a DLL or EXE that does not match it. This prevents an
x64 DLL from being registered for ARM64 LogonUI. It does not register either
component on the normal build host.

```powershell
# On the Windows build machine
cd .\windows
make build-release

# In the VM, after copying the complete build directory
cd .\build
.\unlock_windows_components_wizard.exe
```

Double-clicking the EXE requests elevation. Its status screen shows the
Windows, EXE, source-DLL and installed-DLL architectures. It intentionally
refuses an existing installation; overwrite/update is not implemented. Its
uninstall removes the CP registration and restores the original LSA
registration value, then records a pending cleanup. The automatic logon task
is still under verification on Windows 11; if it does not start this EXE after
reboot, run `unlock_windows_components_wizard.exe --resume-uninstall` from the
build directory. No `INSTALL-TEST-VM` text, `-Confirm` prompt, or PowerShell
continuation is required. Reboot or sign out of the VM before checking the unlock tile. The
current provider still requires the LSA package and a pending approval from
`UnlockService`; it is a lock-screen handoff smoke test, not a finished
automatic unlock implementation.

The previous VM run showed only the PIN provider because the old build rejected
the `CPUS_LOGON` scenario commonly used by Windows 10 and later at lock screen.
The current build accepts both supported scenarios. The Windows 11 ARM VM now
shows the tile and reaches the LSA lookup when it is selected. A valid iPhone
approval has not yet been handed to LogonUI, so this is still not a completed
unlock flow.

The legacy CP-only scripts remain available for automation. Their two-phase
uninstall is still useful only when the LSA package is not installed:

```powershell
.\windows\CredentialProvider\Uninstall-TestCredentialProvider.ps1
# reboot the VM
.\windows\CredentialProvider\Uninstall-TestCredentialProvider.ps1 `
    -RemoveFile
```

The second rollback step removes the provider DLL and then deletes the
rollback JSON. The backup remains between the registry-removal step and the
final file-removal step so the operation can be retried safely after a reboot.
