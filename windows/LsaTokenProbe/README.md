<!-- Created by Rui MA on 29 Sep 2026 -->

# LSA token feasibility probe

`unlock_lsa_token_probe` is a read-only Gate 1 diagnostic. It does not create a
logon session, build an `LSA_TOKEN_INFORMATION_V2`, install a package, change
the registry or alter the enrolled account.

The probe obtains the primary token for the active physical console session,
requires its user SID to match the protected enrollment record, and compares:

- the existing token groups with groups inferred by `AuthzInitializeContextFromSid`;
- the existing token privileges with privileges inferred by Authz;
- the existing token's primary group, owner and default DACL.

Build the target through the normal Windows build workflow, then run it on the
dedicated physical Windows test machine as LocalSystem with `SeTcbPrivilege`.
`WTSQueryUserToken` will intentionally fail when the caller does not have that
security context. Redirect stdout to a file so the report can be reviewed
before any production token work resumes.

An exit code of zero means only that evidence collection completed. It does
not prove that copying the reported data into an LSA token is correct. In
particular, the report does not classify groups that LSA adds automatically;
production token construction remains blocked until that boundary is proven
without hard-coded SID lists or synthetic security information.

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
   $report = 'C:\Temp\lsa-token-probe.txt'
   $taskName = 'Unlock-LSA-Token-Probe'

   New-Item -ItemType Directory -Force C:\Temp | Out-Null
   $script = "whoami; whoami /priv; & '$probe'"
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

6. Preserve the report for review. Its preamble must show
   `nt authority\system` and enabled `SeTcbPrivilege`. Do not interpret exit
   code zero as approval for production token construction.

7. After the report has been copied off the test machine, remove only the
   temporary task:

   ```powershell
   Unregister-ScheduledTask -TaskName 'Unlock-LSA-Token-Probe' -Confirm:$false
   ```

Do not continue to the unpackaged GATT probe or production GattAgent work until
the token report has been reviewed and Gate 1 has subsequently produced a real
Windows unlock.
