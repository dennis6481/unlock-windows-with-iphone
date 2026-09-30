<!-- Created by Rui MA on 29 Sep 2026 -->

# LSA token feasibility probe

`unlock_lsa_token_probe` is a Gate 1 diagnostic. Its default mode is read-only:
it does not create a logon session, build an `LSA_TOKEN_INFORMATION_V2`, install
a package, change the registry or alter the enrolled account.

The probe obtains the primary token for the active physical console session,
requires its user SID to match the protected enrollment record, and records its
elevation type, elevation state, restriction state, token type and integrity
level. When UAC exposes a linked token, the probe also inspects that token and
performs three comparisons:

- the desktop token with its linked token;
- the linked token with groups and privileges inferred by
  `AuthzInitializeContextFromSid`;
- the desktop token with the same Authz-derived candidate for historical
  context.

Both real tokens include their primary group, owner and default DACL in the
report. An Authz context does not provide equivalent token fields, so the probe
does not claim to compare those fields with Authz.

Build the target through the normal Windows build workflow, then run it on the
dedicated physical Windows test machine as LocalSystem with `SeTcbPrivilege`.
`WTSQueryUserToken` will intentionally fail when the caller does not have that
security context. Redirect stdout to a file so the report can be reviewed
before any production token work resumes.

An exit code of zero means only that evidence collection completed. The linked
full token is the best observable reference for the full side of a normal UAC
logon, but it is not proof of the input contract between a third-party
authentication package and LSA. Even a close Authz match does not prove that
returning similar `LSA_TOKEN_INFORMATION_V2` data would make LSA perform native
UAC filtering and linked-token construction. The report also does not classify
groups that LSA adds automatically. Production token construction remains
blocked until those boundaries are proven without hard-coded SID lists or
synthetic security information.

Interpret the elevation fields before comparing the lists:

- `Limited` desktop plus `Full` linked token is the intended UAC administrator
  test configuration.
- `Default` means the token has no linked token. A standard user, disabled UAC,
  the built-in Administrator policy or another policy choice can make that
  result unsuitable for this comparison.
- `Full` means the observed desktop token is elevated. Record why the desktop
  is using it instead of assuming it is the filtered side.

If the desktop elevation type says a linked token should exist but Windows
does not return it, the probe fails explicitly instead of silently falling back
to a two-way comparison.

The explicit `--s4u` mode performs a second feasibility experiment. It asks the
built-in MSV1_0 package to create a temporary interactive S4U token for the
enrolled local account, then compares that token with the active console token.
This mode still does not install or modify system configuration, but it creates
a transient logon session and can produce Windows security audit events. Its
output is evidence only; it does not authorize copying observed token fields
into the custom authentication package.

## Physical-machine test procedure

Use a dedicated or spare Windows machine. This probe is read-only and does not
require installing the Credential Provider or LSA package, but enrollment must
be created on the same Windows installation because the record is protected by
machine-scope DPAPI.

1. Build the probe and the existing foreground enrollment components:

   ```powershell
   cmake --build windows/build --config Release --target `
       unlock_lsa_token_probe unlock_service_host unlock_pairing_tool
   ```

2. Log in as the Windows account that will be enrolled. Start
   `unlock_service_host.exe` in a normal, non-SYSTEM PowerShell window and keep
   it running.

3. Copy the 130-hex-digit raw public key from the iPhone application. In a
   second normal PowerShell window, run the pairing tool and confirm that the
   Windows and iPhone fingerprints match:

   ```powershell
   .\windows\build\unlock_pairing_tool.exe --key-clipboard
   ```

   Do not run the pairing tool as SYSTEM. It records the SID of its caller.

4. Confirm that the local enrollment record exists:

   ```powershell
   Test-Path "$env:ProgramData\UnlockWindowsWithIPhone\enrollment.dat"
   ```

5. Open an elevated PowerShell window. Adjust `$probe` if the executable is in
   a configuration-specific subdirectory, then register and run a temporary
   SYSTEM task:

   ```powershell
   $probe = (Resolve-Path '.\windows\build\unlock_lsa_token_probe.exe').Path
   $reportDir = Join-Path $env:ProgramData 'UnlockWindowsWithIPhone\LsaTokenProbeReports'
   $report = Join-Path $reportDir 'lsa-token-probe.txt'
   $taskName = 'Unlock-LSA-Token-Probe'

   New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction Stop | Out-Null
   $acl = New-Object Security.AccessControl.DirectorySecurity
   $acl.SetAccessRuleProtection($true, $false)
   $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
   $propagation = [Security.AccessControl.PropagationFlags]::None
   $allow = [Security.AccessControl.AccessControlType]::Allow
   foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
       $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
       $rule = New-Object Security.AccessControl.FileSystemAccessRule(
           $sid, [Security.AccessControl.FileSystemRights]::FullControl,
           $inheritance, $propagation, $allow
       )
       $acl.AddAccessRule($rule)
   }
   Set-Acl -LiteralPath $reportDir -AclObject $acl -ErrorAction Stop
   if (Test-Path -LiteralPath $report) {
       Remove-Item -LiteralPath $report -Force -ErrorAction Stop
   }
   $script = "& '$probe'"
   $encodedCommand = [Convert]::ToBase64String(
       [Text.Encoding]::Unicode.GetBytes("$script *> '$report'")
   )
   $action = New-ScheduledTaskAction `
       -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
       -Argument "-NoProfile -NonInteractive -EncodedCommand $encodedCommand"
   $principal = New-ScheduledTaskPrincipal `
       -UserId 'SYSTEM' `
       -LogonType ServiceAccount `
       -RunLevel Highest
   $settings = New-ScheduledTaskSettingsSet `
       -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

   Register-ScheduledTask `
       -TaskName $taskName `
       -Action $action `
       -Principal $principal `
       -Settings $settings `
       -Force
   Start-ScheduledTask -TaskName $taskName
   Start-Sleep -Seconds 2
   while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
       Start-Sleep -Milliseconds 500
   }

   Get-ScheduledTaskInfo -TaskName $taskName
   Get-Content $report
   ```

6. Preserve the report locally for review. The scheduled task principal must
   be SYSTEM; `WTSQueryUserToken` fails explicitly if it lacks the required
   security context. Do not interpret exit code zero as approval for production
   token construction.

7. Preserve this first report before continuing. It establishes whether Authz
   resembles the linked full token more closely than the filtered desktop
   token; it does not prove that a custom authentication package receives the
   same UAC processing as a built-in interactive logon.

## MSV1_0 S4U comparison

Run this only after preserving the default report. Keep the enrolled user
logged in at the physical console. Reuse the same elevated PowerShell window
and replace the temporary task action so the probe receives `--s4u`:

```powershell
$probe = (Resolve-Path '.\windows\build\unlock_lsa_token_probe.exe').Path
$reportDir = Join-Path $env:ProgramData 'UnlockWindowsWithIPhone\LsaTokenProbeReports'
$report = Join-Path $reportDir 'lsa-s4u-token-probe.txt'
$taskName = 'Unlock-LSA-Token-Probe'

if (Test-Path -LiteralPath $report) {
    Remove-Item -LiteralPath $report -Force -ErrorAction Stop
}
$script = "& '$probe' --s4u"
$encodedCommand = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes("$script *> '$report'")
)
$action = New-ScheduledTaskAction `
    -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    -Argument "-NoProfile -NonInteractive -EncodedCommand $encodedCommand"
$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Principal $principal `
    -Settings $settings `
    -Force
Start-ScheduledTask -TaskName $taskName

while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
    Start-Sleep -Milliseconds 500
}

Get-ScheduledTaskInfo -TaskName $taskName
Get-Content $report
```

Preserve the complete S4U report even when `LsaLogonUser` returns an error. A
successful result must still be reviewed for UAC filtering, cloud-account
groups, privileges, owner, primary group and default DACL before any production
architecture decision.

### Observed result on 29 September 2026

The enrolled Microsoft-connected local administrator produced a normal UAC
pair: the desktop token was `Limited`, restricted and medium-integrity, while
its linked token was `Full`, unrestricted and high-integrity. The desktop token
had five privileges and marked Administrators deny-only. The linked full token
and SID-derived Authz context both contained the same 24 privilege names, so
the earlier two-way comparison did not establish that Authz itself would cause
an elevation. Authz is plausibly closer to pre-filter account authorization
than to the filtered desktop token.

Authz still did not reproduce the linked full interactive token. It left
`SeCreateGlobalPrivilege` and `SeImpersonatePrivilege` disabled, reported
Administrators without the owner attribute, included the local RID 513 group
that was absent from the real token, and lacked the interactive, console,
logon-session, integrity, Microsoft Account and cloud-authentication SIDs. It
also provides no equivalent source for the observed primary group, owner or
default DACL. The real full token used Administrators as owner and in its
default DACL; the filtered token used the user SID instead.

This evidence retracts the claim that the 24 Authz privileges alone prove a
privilege escalation. It does not authorize using Authz data for production:
there is still no verified contract that a third-party `LsaApLogonUserEx2`
result receives native UAC filtering, linked-token construction or the missing
Microsoft Account and logon-session semantics.

## Next investigation boundary

`GetAuthDataForUser` and `ConvertAuthDataToToken` are not ordinary Win32
exports that this executable can call. LSA supplies those callbacks through
`LSA_SECPKG_FUNCTION_TABLE` when it initializes an SSP/AP through
`SpLsaModeInitialize` and `SpInitialize`. The current prototype is registered
through the legacy `Authentication Packages` path and receives only the smaller
`LSA_DISPATCH_TABLE` in `LsaApInitializePackage`; it therefore cannot expose
those helpers to this standalone probe without changing its LSA initialization
contract.

The next experiment must consequently use a separate diagnostic-only SSP/AP,
registered under `Security Packages` on a disposable test installation. It
should reject all logon attempts and expose only one bounded diagnostic request
that obtains SAM authorization data, calls
`ConvertAuthDataToToken(Interactive)`, inspects the returned token inside LSA,
and returns a report. The production authentication package and installer must
not be migrated to the SSP/AP contract merely to run this experiment.

MSV1_0 rejected the `Interactive` S4U request with
`STATUS_BAD_VALIDATION_CLASS (0xC00000A7)`. This remains a negative feasibility
result, not a reason to weaken privileges or change the request to a `Network`
logon: a network impersonation token does not establish the required
`Interactive`/`Unlock` semantics.

## Report handling

The probe prints account names, raw user and group SIDs, token owner, primary
group and default DACL because they are needed to diagnose token differences.
These values can identify the test account or machine. The example task writes
only inside a SYSTEM/Administrators-only directory; do not redirect it to
`C:\Temp`, a cloud-synced folder, or a shared drive. Keep the original local
for comparison, but replace account-specific SIDs, paths and names
consistently before sharing an excerpt or screenshot. Review the result
manually; do not commit a raw report. After review, delete the two report
files and unregister the temporary task. This cleanup does not erase copies
already exported or backed up.

After both reports have been copied off the test machine, remove only the
temporary task:

   ```powershell
   Unregister-ScheduledTask -TaskName 'Unlock-LSA-Token-Probe' -Confirm:$false
   ```

Do not continue to the unpackaged GATT probe or production GattAgent work until
the token report has been reviewed and Gate 1 has subsequently produced a real
Windows unlock.
