<!-- Created by Rui MA on 27 Sep 2026 -->
<!-- Modified by Codex on 27 Sep 2026 -->

# Credential Provider prototype

This directory contains a build-only V2 `CPUS_UNLOCK_WORKSTATION` Credential
Provider shell. It obtains the current user SID through
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

The repository also contains guarded registration and rollback scripts for a
disposable Windows VM. They copy the x64 DLL to `System32`, register the COM
class and add the Credential Provider registration. They do not register the
provider on the normal build host.

```powershell
.\windows\CredentialProvider\Install-TestCredentialProvider.ps1 `
    -IUnderstandThisIsAThrowawayVm -Confirm
```

Reboot or sign out of the VM before checking the unlock tile. The current
provider still requires the LSA package and a pending approval from
`UnlockService`; it is a lock-screen handoff smoke test, not a finished
automatic unlock implementation.

Current VM status: the LSA package lookup and direct COM smoke test succeed,
and the registration/DLL paths are present, but LogonUI still shows only the
PIN provider. This means the remaining blocker is Credential Provider
activation/display in LogonUI; the actual lock-screen tile-to-LSA handoff has
not yet been observed.

To roll back, run the uninstall script before removing the DLL:

```powershell
.\windows\CredentialProvider\Uninstall-TestCredentialProvider.ps1 `
    -IUnderstandThisIsAThrowawayVm -Confirm
# reboot the VM
.\windows\CredentialProvider\Uninstall-TestCredentialProvider.ps1 `
    -IUnderstandThisIsAThrowawayVm -RemoveFile -Confirm
```

The second rollback step removes the provider DLL and then deletes the
rollback JSON. The backup remains between the registry-removal step and the
final file-removal step so the operation can be retried safely after a reboot.
