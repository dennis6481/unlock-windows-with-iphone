<!-- Created by Rui MA on 29 Sep 2026 -->

# LSA interactive conversion probe

This is a diagnostic-only SSP/AP and trusted SYSTEM client for the next Gate 1
experiment. It asks the LSA-provided `GetAuthDataForUser` helper for the
enrolled SAM account's authorization data, passes that exact result to
`ConvertAuthDataToToken` with `Interactive`, and reports the resulting token.
The preferred VM path is package-internal reporting and does not depend on
`LsaLookupAuthenticationPackage`: `SpInitialize` writes helper availability,
and the installer records the elevated user's SAM name and SID in a
SYSTEM/Administrators-only diagnostic file. The first eligible
`SpAcceptCredentials` notification acts only as a post-logon trigger; the worker
uses the installer-recorded SAM identity without reading password or
supplemental-credential material. The trusted-client path continues to use the
enrolled SID if package lookup becomes available.

The package is deliberately separate from the production authentication
package. It rejects every logon entry point, rejects untrusted package calls,
accepts one fixed request from a caller registered with
`LsaRegisterLogonProcess`, closes the temporary token immediately, and keeps
`productionTokenConstruction=not-authorized` in the report.

Loading any custom package into LSASS can make a test installation unbootable.
Do not register this DLL on a primary machine. Preserve a recovery path and the
exact existing `Security Packages` registry value before installation. The
package has not been added to the product installer and must never be shipped
as a product component.

## Run on a disposable VM

Use a VM snapshot and a test account. This experiment loads an unsigned DLL
into LSASS and changes `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security
Packages`; a failed package can prevent sign-in. Never use the installer on a
daily-use machine or turn off LSA Protection on one. Restore the VM snapshot
to remove the probe after collecting evidence.

On the development machine, build the two diagnostic targets if you need fresh
binaries:

```powershell
cmake --build windows/build --config Release --target `
    unlock_lsa_convert_probe_package unlock_lsa_convert_probe
```

The installer never builds on the VM. Copy the following prebuilt files into
one VM folder, sign in as the test account backed by a local SAM SID, then
double-click `Install-VmProbe.cmd`:

```text
Install-VmProbe.cmd
Install-VmProbe.ps1
unlock_lsa_convert_probe_package.dll
```

The installer also accepts the repository layout where the prebuilt DLL is in
`windows\build` or `windows\build\Release`. Accept UAC, read the warning and
type `INSTALL` once. Leave the VM to perform its two automatic restarts, then
sign in as the same test account. The installer:

1. refuses to proceed unless `RunAsPPL` and `RunAsPPLBoot` are both disabled;
2. requires a prebuilt `unlock_lsa_convert_probe_package.dll` and stages its
   SHA-256 hash, failing immediately if the DLL is missing;
3. stages the script and DLL under
   `%ProgramData%\UnlockWindowsWithIPhone\LsaConvertProbeInstaller` with an ACL
   limited to SYSTEM and Administrators;
4. saves the original `Security Packages` list in `state.json`, and writes the
   installing user's verified `S-1-5-21` SID and SAM name to
   `target-account.ini`;
5. removes an older probe registration and reboots;
6. resumes as SYSTEM, installs and hashes the DLL, registers it and reboots;
7. verifies after boot that the expected DLL is registered and mapped in
   LSASS; and
8. waits for the target user's interactive logon report and opens it in
   Notepad.

If Notepad does not open, inspect the state and report from an elevated
PowerShell window:

```powershell
$probeDir = Join-Path $env:ProgramData 'UnlockWindowsWithIPhone\LsaConvertProbeInstaller'
Get-Content -LiteralPath (Join-Path $probeDir 'state.json')
Get-Content -LiteralPath (Join-Path $probeDir 'report.txt')
```

`report.txt` begins with `stage=SpInitialize`. After an eligible logon it
should show `accountSource=installer-config` and
`GetAuthDataForUser.status`. A nonzero status and `GetAuthDataForUser.bytes=0`
mean conversion was not attempted; only a successful authorization-data call
can lead to `ConvertAuthDataToToken.status` and a token report. Do not treat
helper availability or a loaded DLL as an unlock success. If `state.json`
shows `Failed`, inspect `installer-error.txt` in the same directory. Do not
continue past a failed check by manually editing the registry.

The installer deliberately does not build software, disable LSA protection,
change Credential Guard policy, or continue after a hash/registration/load
check fails. A background-stage failure is saved as
`installer-error.txt` in the staging directory and opened at the next target
user logon. The two restarts are intentional so an already mapped DLL is never
overwritten in place.

After a run reaches `Complete` or `Failed`, the same CMD can be run again with
a newly built DLL. The installer preserves the original pre-probe `Security
Packages` value, unregisters the currently loaded probe, reboots before
replacing the DLL, and then performs the normal register-and-verify reboot. It
rejects a second launch while an earlier run is still in progress.

The automation is diagnostic infrastructure, not a product installer. After
exporting only the evidence needed for analysis, restore the pre-install VM
snapshot. This is the supported cleanup path for this experimental package;
deleting the DLL while LSASS has it mapped is not a safe uninstall procedure.

Building does not install or load the package. The VM-only installer handles
registration and restarts, but snapshot rollback remains a separate step.
Before installing, verify that the DLL and
client were built for x64 and inspect whether LSA protection or Credential
Guard policy will reject an unsigned test package.

## Current physical-machine preflight (29 September 2026)

The current machine reports `RunAsPPL=2` and `RunAsPPLBoot=2`. The generated
x64 DLL is unsigned. Microsoft requires an LSA plug-in loaded into protected
LSASS to carry a Microsoft signature, so this binary cannot be registered for
the live experiment while that protection remains enabled. The machine's Code
Integrity log also already contains event 3033 records showing another
unsigned package (`APPLE-W.dll`) being rejected by `wininit.exe`; this is direct
local confirmation that the signing boundary is active.

No registry value, System32 file, LSASS state or boot setting was changed by
this preflight. Continuing on this same physical installation requires one of
two explicit decisions: obtain Microsoft LSA plug-in signing, or temporarily
disable LSA protection and accept the resulting security reduction and reboot
risk. Merely applying a local/test Authenticode signature is not sufficient.
Do not register this unsigned DLL until that decision and a recovery procedure
have been approved.

The useful report must include the status from both helpers and, on success,
the converted token's type, elevation type, restriction state, integrity
level, authentication ID, owner, primary group, default DACL, complete groups
and complete privileges. A successful conversion is evidence about this
specific Windows build and account only; it does not yet prove that returning
`LSA_TOKEN_INFORMATION_V2` from the production AP receives identical UAC
processing.

The package does not reject LSA initialization merely because an individual
support callback is absent. `SpInitialize` records the table and succeeds, and
the trusted diagnostic request reports availability for every helper it needs.
This distinction is intentional: Microsoft documents that returning an error
from `SpInitialize` unloads the package and removes it from the available
package list, which would hide the exact callback availability this experiment
is intended to measure.

The package advertises `SECPKG_FLAG_LOGON` in `SpGetInfo`. Without that flag,
the DLL can be loaded and remain mapped in LSASS while the package does not
declare support for `LsaLogonUser`, leaving it unavailable through
`LsaLookupAuthenticationPackage`. Only `LsaApLogonUserEx2` is populated because
Microsoft requires an authentication package to implement one of
`LsaApLogonUser`, `LsaApLogonUserEx`, or `LsaApLogonUserEx2`; the two older
variants are not required. The function table is populated by named fields so
that null legacy callbacks cannot be mistaken for a shifted table entry.

## Package-internal report and privacy

On a disposable VM, install the rebuilt DLL and reboot as described above.
`SpInitialize` creates this UTF-16 report inside the installer-created
SYSTEM/Administrators-only directory:

```text
%ProgramData%\UnlockWindowsWithIPhone\LsaConvertProbeInstaller\report.txt
```

Before a credential notification it contains `stage=SpInitialize`, helper
availability and the configured target identity (or a configuration error). The first non-service,
non-machine `SpAcceptCredentials` call for an `Interactive` or `Unlock` logon
queues the full probe on a worker and replaces the file with the normal
conversion and token report. Other logon types are ignored. The callback copies
only the notification's non-secret account names and SID for filtering and
diagnostic output. It never reads `Password`, `OldPassword`, or supplemental
credentials.

The worker does not treat the notification identity as the helper input. This
matters for Microsoft Account sign-in, where the VM exposed only an
`S-1-11-96-...` cloud identity through `SpAcceptCredentials`, although the
desktop token used the backing `<COMPUTER>\\<USER>` / `S-1-5-21-...` SAM account.
Instead, the worker reads the SAM name and expected SID captured by the
installer, passes the SAM-compatible name directly to `GetAuthDataForUser`, and
requires the converted token's user SID to match the configured SID. A mismatch
is an explicit probe failure. This path does not call `LookupAccountNameW` or
open the DPAPI-protected enrollment file. Token reporting inside LSASS emits
raw SIDs and privilege LUIDs instead of resolving their display names, because
those lookup APIs can recursively require LSA RPC. The callback returns success
regardless of probe outcome so that this diagnostic package cannot reject the
real account's logon.

The VM sample has confirmed that these identities can describe the same signed-in
user: `SpAcceptCredentials` first reported the email and an `S-1-11-96-...`
cloud SID, while the resulting desktop token and `Get-LocalUser` identify
`<COMPUTER>\\<USER>` with an `S-1-5-21-...` SID and
`PrincipalSource=MicrosoftAccount`. The configured SAM target therefore does
not select a different person; it selects the local security principal that
`GetAuthDataForUser` documents as its input domain.

After signing in, read it from an elevated PowerShell session:

```powershell
$probeDir = Join-Path $env:ProgramData 'UnlockWindowsWithIPhone\LsaConvertProbeInstaller'
Get-Content -LiteralPath (Join-Path $probeDir 'report.txt')
```

The report can still contain machine/account SIDs, a default DACL and token
group membership if conversion succeeds. `target-account.ini` contains the
test account's SAM name and SID; `state.json` may retain installer metadata.
Treat the entire directory as sensitive. Do not commit or send raw reports,
screenshots, `target-account.ini`, or the VM image. For a shared excerpt,
replace account-specific names and SIDs consistently with placeholders and
retain the status codes, token attributes and comparison structure. Review
the excerpt manually before sending it; never substitute a redacted report
for the local original when judging SID equality.

Older probe builds wrote `%SystemRoot%\Temp\unlock-lsa-convert-probe.txt`.
Moving to this version does not remove that older file. On an upgraded test VM,
review it locally and remove it from an elevated PowerShell session when it is
no longer needed; restoring the pre-install snapshot removes both versions.

Interpretation is deliberately mechanical:

- no file: `SpInitialize` was not reached, or LSASS could not create the file;
- `stage=SpInitialize`: the package initialized, but no eligible interactive or
  unlock trigger has run since initialization; `targetConfigError` indicates an
  invalid or missing installer target and must not be ignored;
- full report: the package-internal worker ran, so package lookup is no longer
  part of the experiment.

References:

- [LSA-mode initialization](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-mode-initialization)
- [`SpLsaModeInitialize`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-splsamodeinitializefn)
- [`SecPkgInfo` capability flags](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkginfoa)
- [`LsaApLogonUser`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_ap_logon_user)
- [`SpAcceptCredentials`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-spacceptcredentialsfn)
- [`SECPKG_PRIMARY_CRED`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/ns-ntsecpkg-secpkg_primary_cred)
- [`GetAuthDataForUser`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_get_auth_data_for_user)
- [`ConvertAuthDataToToken`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_convert_auth_data_to_token)
- [Registering SSP/AP DLLs](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [Security-package installation restrictions](https://learn.microsoft.com/en-us/windows/win32/secauthn/restrictions-around-registering-and-installing-a-security-package)
