# Created by Rui MA on 29 Sep 2026
#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Resume', 'ShowReport')]
    [string]$Mode = 'Install',

    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$packageName = 'unlock_lsa_convert_probe_package'
$installedDll = Join-Path $env:SystemRoot 'System32\unlock_lsa_convert_probe_package.dll'
$stateRoot = Join-Path $env:ProgramData 'UnlockWindowsWithIPhone\LsaConvertProbeInstaller'
$reportPath = Join-Path $stateRoot 'report.txt'
$statePath = Join-Path $stateRoot 'state.json'
$errorPath = Join-Path $stateRoot 'installer-error.txt'
$targetAccountPath = Join-Path $stateRoot 'target-account.ini'
$stagedDll = Join-Path $stateRoot 'unlock_lsa_convert_probe_package.dll'
$stagedScript = Join-Path $stateRoot 'Install-VmProbe.ps1'
$resumeTaskName = 'Unlock-LSA-Convert-Probe-Installer'
$reportTaskName = 'Unlock-LSA-Convert-Probe-Report'
$lsaSubKey = 'SYSTEM\CurrentControlSet\Control\Lsa'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Start-ElevatedInstall {
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode Install -Elevated' -f `
        $PSCommandPath.Replace('"', '""')
    Start-Process `
        -FilePath 'powershell.exe' `
        -ArgumentList $arguments `
        -Verb RunAs
}

function Initialize-StateDirectory {
    New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null

    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        )
        $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $stateRoot -AclObject $security
}

function Get-LsaKey([bool]$Writable) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $lsaSubKey,
        $Writable
    )
    if ($null -eq $key) {
        throw 'Cannot open HKLM\SYSTEM\CurrentControlSet\Control\Lsa.'
    }
    return $key
}

function Get-SecurityPackages {
    $key = Get-LsaKey $false
    try {
        return [string[]]@(
            $key.GetValue(
                'Security Packages',
                [string[]]@(),
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            ) | Where-Object { $_ -and $_ -ne '""' }
        )
    }
    finally {
        $key.Dispose()
    }
}

function Set-SecurityPackages([string[]]$Packages) {
    $key = Get-LsaKey $true
    try {
        $key.SetValue(
            'Security Packages',
            [string[]]$Packages,
            [Microsoft.Win32.RegistryValueKind]::MultiString
        )
    }
    finally {
        $key.Dispose()
    }
}

function Remove-ProbePackage {
    [string[]]$remaining = @(
        Get-SecurityPackages | Where-Object { $_ -ne $packageName }
    )
    Set-SecurityPackages $remaining
}

function Add-ProbePackage {
    [string[]]$updated = @(
        Get-SecurityPackages | Where-Object { $_ -ne $packageName }
    ) + $packageName
    Set-SecurityPackages $updated
}

function Assert-LsaProtectionDisabled {
    $key = Get-LsaKey $false
    try {
        $runAsPpl = [int]$key.GetValue('RunAsPPL', 0)
        $runAsPplBoot = [int]$key.GetValue('RunAsPPLBoot', 0)
    }
    finally {
        $key.Dispose()
    }

    if ($runAsPpl -ne 0 -or $runAsPplBoot -ne 0) {
        throw "Unsigned VM probe refused: RunAsPPL=$runAsPpl, RunAsPPLBoot=$runAsPplBoot."
    }
}

function Write-State($State) {
    $temporaryPath = "$statePath.tmp"
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $statePath -Force
}

function Read-State {
    if (-not (Test-Path -LiteralPath $statePath)) {
        throw "Installer state is missing: $statePath"
    }
    return Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
}

function Set-FailedState([string]$Message) {
    $Message | Set-Content -LiteralPath $errorPath -Encoding UTF8
    if (-not (Test-Path -LiteralPath $statePath)) {
        return
    }

    $state = Read-State
    $state.stage = 'Failed'
    if ($state.PSObject.Properties.Name -contains 'error') {
        $state.error = $Message
    }
    else {
        $state | Add-Member -MemberType NoteProperty -Name error -Value $Message
    }
    Write-State $state
}

function Register-ResumeTask {
    $action = New-ScheduledTaskAction `
        -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$stagedScript`" -Mode Resume"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask `
        -TaskName $resumeTaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
}

function Register-ReportTask([string]$UserName) {
    $action = New-ScheduledTaskAction `
        -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$stagedScript`" -Mode ShowReport"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserName
    $principal = New-ScheduledTaskPrincipal `
        -UserId $UserName `
        -LogonType Interactive `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask `
        -TaskName $reportTaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
}

function Remove-TaskWithWarning([string]$TaskName) {
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    }
    catch {
        Write-Warning "Could not remove scheduled task '$TaskName': $($_.Exception.Message)"
    }
}

function Restart-ForNextStage([string]$Message) {
    Write-Host ''
    Write-Host $Message -ForegroundColor Yellow
    Write-Host 'The VM will restart now. The installer will continue automatically.' -ForegroundColor Yellow
    Restart-Computer -Force
}

function Invoke-Install {
    if (-not (Test-Administrator)) {
        if ($Elevated) {
            throw 'Administrator elevation failed.'
        }
        Start-ElevatedInstall
        return
    }

    $previousState = $null
    if (Test-Path -LiteralPath $statePath) {
        $previousState = Read-State
        if ($previousState.stage -notin @('Complete', 'Failed')) {
            throw "An installation is already in progress at stage '$($previousState.stage)'."
        }
        if (-not ($previousState.PSObject.Properties.Name -contains 'originalPackages')) {
            throw 'The previous installer state does not contain the original Security Packages value.'
        }
    }

    Write-Host 'WARNING: this installs an unsigned diagnostic DLL into LSASS.' -ForegroundColor Yellow
    Write-Host 'Use it only inside the disposable VM with a working snapshot.' -ForegroundColor Yellow
    $confirmation = Read-Host 'Type INSTALL to install the prebuilt DLL and automatically restart the VM twice'
    if ($confirmation -cne 'INSTALL') {
        throw 'Installation was cancelled.'
    }

    Assert-LsaProtectionDisabled

    $candidateDlls = @(
        (Join-Path $PSScriptRoot 'unlock_lsa_convert_probe_package.dll'),
        (Join-Path $PSScriptRoot '..\build\unlock_lsa_convert_probe_package.dll'),
        (Join-Path $PSScriptRoot '..\build\Release\unlock_lsa_convert_probe_package.dll')
    )
    $packageDll = $candidateDlls |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if (-not $packageDll) {
        throw @"
The prebuilt diagnostic DLL was not found. Copy these three files into one VM folder:
  Install-VmProbe.cmd
  Install-VmProbe.ps1
  unlock_lsa_convert_probe_package.dll
The installer never builds binaries on the VM.
"@
    }

    Initialize-StateDirectory
    Remove-Item -LiteralPath $errorPath -Force -ErrorAction SilentlyContinue
    Remove-Item `
        -LiteralPath (Join-Path $stateRoot 'report-timeout.txt') `
        -Force `
        -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $PSCommandPath -Destination $stagedScript -Force
    Copy-Item -LiteralPath $packageDll -Destination $stagedDll -Force
    $stagedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $stagedDll).Hash
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -notmatch '^S-1-5-21-(?:\d+-){3}\d+$') {
        throw "The installer user is not backed by a SAM account: $($identity.User.Value)"
    }

    @(
        '[Target]'
        "SamName=$($identity.Name)"
        "Sid=$($identity.User.Value)"
    ) | Set-Content -LiteralPath $targetAccountPath -Encoding Unicode

    $state = [ordered]@{
        stage = 'ReplaceAndRegister'
        createdAt = (Get-Date).ToString('o')
        userName = $identity.Name
        userSid = $identity.User.Value
        targetAccountPath = $targetAccountPath
        originalPackages = if ($null -ne $previousState) {
            [string[]]@($previousState.originalPackages)
        }
        else {
            [string[]]@(Get-SecurityPackages)
        }
        stagedHash = $stagedHash
    }
    Write-State $state

    Register-ResumeTask
    Register-ReportTask $identity.Name
    Remove-ProbePackage
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue

    Restart-ForNextStage 'Stage 1 complete: the old package registration has been removed.'
}

function Invoke-Resume {
    if (-not (Test-Administrator)) {
        throw 'The resume stage must run as LocalSystem or an administrator.'
    }
    Assert-LsaProtectionDisabled
    $state = Read-State

    if ($state.stage -eq 'ReplaceAndRegister') {
        $loaded = @(
            Get-Process -Name lsass -Module -ErrorAction Stop |
                Where-Object { $_.ModuleName -ieq "$packageName.dll" }
        )
        if ($loaded.Count -ne 0) {
            throw 'The old diagnostic DLL is still loaded in LSASS after restart.'
        }

        Copy-Item -LiteralPath $stagedDll -Destination $installedDll -Force
        $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedDll).Hash
        if ($installedHash -ne $state.stagedHash) {
            throw 'The installed DLL hash does not match the staged DLL.'
        }

        Add-ProbePackage
        Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
        $state.stage = 'VerifyAfterLoad'
        Write-State $state
        Restart-ForNextStage 'Stage 2 complete: the new diagnostic DLL has been installed and registered.'
        return
    }

    if ($state.stage -eq 'VerifyAfterLoad') {
        $registered = @(Get-SecurityPackages) -contains $packageName
        if (-not $registered) {
            throw 'The diagnostic package is missing from Security Packages after restart.'
        }

        $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedDll).Hash
        if ($installedHash -ne $state.stagedHash) {
            throw 'The installed DLL changed after restart.'
        }

        $loaded = @(
            Get-Process -Name lsass -Module -ErrorAction Stop |
                Where-Object { $_.ModuleName -ieq "$packageName.dll" }
        )
        if ($loaded.Count -eq 0) {
            throw 'The diagnostic DLL is registered but is not loaded in LSASS.'
        }

        $state.stage = 'WaitingForReport'
        Write-State $state
        Remove-TaskWithWarning $resumeTaskName
        return
    }

    if ($state.stage -in @('WaitingForReport', 'Complete')) {
        Remove-TaskWithWarning $resumeTaskName
        return
    }

    throw "Unknown installer stage: $($state.stage)"
}

function Invoke-ShowReport {
    $state = Read-State
    $installerDeadline = (Get-Date).AddSeconds(60)
    while ($state.stage -in @('ReplaceAndRegister', 'VerifyAfterLoad') -and
           (Get-Date) -lt $installerDeadline) {
        Start-Sleep -Seconds 1
        $state = Read-State
    }

    if ($state.stage -eq 'Failed') {
        Remove-TaskWithWarning $reportTaskName
        if (Test-Path -LiteralPath $errorPath) {
            Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$errorPath`""
        }
        return
    }
    if ($state.stage -ne 'WaitingForReport') {
        return
    }

    $deadline = (Get-Date).AddSeconds(60)
    $reportReady = $false
    do {
        if (Test-Path -LiteralPath $reportPath) {
            $content = Get-Content -LiteralPath $reportPath -Raw
            if ($content -match 'accountSource=installer-config' -or
                $content -match 'accountSource=SpAcceptCredentials' -or
                $content -match 'probeStatus=') {
                $reportReady = $true
                break
            }
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    $state.stage = 'Complete'
    $state.completedAt = (Get-Date).ToString('o')
    $state.reportReady = $reportReady
    Write-State $state
    Remove-TaskWithWarning $reportTaskName

    if ($reportReady) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$reportPath`""
        return
    }

    $statusPath = Join-Path $stateRoot 'report-timeout.txt'
    @(
        'The diagnostic DLL was installed, but a full report was not produced within 60 seconds.'
        "Inspect: $reportPath"
        "Installer state: $statePath"
    ) | Set-Content -LiteralPath $statusPath -Encoding UTF8
    Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$statusPath`""
}

try {
    switch ($Mode) {
        'Install' { Invoke-Install }
        'Resume' { Invoke-Resume }
        'ShowReport' { Invoke-ShowReport }
    }
}
catch {
    $failure = $_
    if ($Mode -eq 'Resume') {
        try {
            Set-FailedState ($failure | Out-String)
            Remove-TaskWithWarning $resumeTaskName
        }
        catch {
            Write-Warning "Could not persist the resume failure: $($_.Exception.Message)"
        }
    }
    Write-Error $failure
    if ($Mode -eq 'Install') {
        Read-Host 'Installation stopped. Press Enter to close this window'
    }
    exit 1
}
