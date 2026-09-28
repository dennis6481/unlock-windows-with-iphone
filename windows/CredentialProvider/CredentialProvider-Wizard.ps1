# Created by Rui MA on 28 Sep 2026

[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Install', 'Unregister', 'RemoveFile', 'Status')]
    [string]$Action = 'Menu',
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build'),
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\..\.tmp\credential-provider-backup')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\WindowsArchitecture.ps1')

$clsid = '{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}'
$providerName = 'Unlock Windows with iPhone'
$dllName = 'unlock_credential_provider.dll'
$installScript = Join-Path $PSScriptRoot 'Install-TestCredentialProvider.ps1'
$uninstallScript = Join-Path $PSScriptRoot 'Uninstall-TestCredentialProvider.ps1'
$targetPath = Join-Path $env:windir "System32\$dllName"
$providerRegistrationPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
$inprocPath = "$clsidPath\InprocServer32"
$backupFile = Join-Path ([IO.Path]::GetFullPath($BackupDirectory)) 'credential-provider.json'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Status {
    $sourcePath = Join-Path $BuildDirectory $dllName
    $nativeArchitecture = Get-NativeWindowsArchitecture
    $powerShellArchitecture = Get-CurrentPowerShellArchitecture
    $sourceArchitecture = if (Test-Path -LiteralPath $sourcePath) {
        Get-PortableExecutableArchitecture -Path $sourcePath
    } else {
        'NotPresent'
    }
    $installedArchitecture = if (Test-Path -LiteralPath $targetPath) {
        Get-PortableExecutableArchitecture -Path $targetPath
    } else {
        'NotPresent'
    }
    $inprocServer = if (Test-Path -LiteralPath $inprocPath) {
        (Get-Item -LiteralPath $inprocPath).GetValue('')
    } else {
        $null
    }

    Write-Host "$providerName Credential Provider status" -ForegroundColor Cyan
    [PSCustomObject]@{
        Elevated = (Test-IsAdministrator)
        NativeWindowsArchitecture = $nativeArchitecture
        PowerShellArchitecture = $powerShellArchitecture
        SourceDllPresent = (Test-Path -LiteralPath $sourcePath)
        SourceDllArchitecture = $sourceArchitecture
        InstalledDllPresent = (Test-Path -LiteralPath $targetPath)
        InstalledDllArchitecture = $installedArchitecture
        NativeArchitectureCompatible = (
            $powerShellArchitecture -eq $nativeArchitecture -and
            ($sourceArchitecture -eq 'NotPresent' -or $sourceArchitecture -eq $nativeArchitecture) -and
            ($installedArchitecture -eq 'NotPresent' -or $installedArchitecture -eq $nativeArchitecture)
        )
        CredentialProviderRegistered = (Test-Path -LiteralPath $providerRegistrationPath)
        ClsidRegistered = (Test-Path -LiteralPath $clsidPath)
        InprocServer32 = $inprocServer
        RollbackBackupPresent = (Test-Path -LiteralPath $backupFile)
        RollbackBackup = $backupFile
    } | Format-List

    if (Test-Path -LiteralPath $sourcePath) {
        $hash = Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256
        Write-Host "Source DLL SHA256: $($hash.Hash)"
    }

    if (Test-Path -LiteralPath $targetPath) {
        $hash = Get-FileHash -LiteralPath $targetPath -Algorithm SHA256
        Write-Host "Installed DLL SHA256: $($hash.Hash)"
    }
}

function Select-Action {
    if ($Action -ne 'Menu') {
        return $Action
    }

    Write-Host ''
    Write-Host "$providerName Credential Provider wizard" -ForegroundColor Cyan
    Write-Host '1. Install the new build'
    Write-Host '2. Uninstall registration, then reboot'
    Write-Host '3. Remove the DLL and rollback backup after reboot'
    Write-Host '4. Show status'
    Write-Host 'Q. Quit'

    switch (Read-Host -Prompt 'Select an action') {
        '1' { return 'Install' }
        '2' { return 'Unregister' }
        '3' { return 'RemoveFile' }
        '4' { return 'Status' }
        { $_ -in 'Q', 'q' } { return $null }
        default { throw 'Unknown action.' }
    }
}

$selectedAction = Select-Action
if ($null -eq $selectedAction) {
    Write-Host 'Cancelled.'
    return
}

if ($selectedAction -eq 'Status') {
    Show-Status
    return
}

if (-not (Test-IsAdministrator)) {
    throw 'Run the wizard from an elevated PowerShell window inside the test VM.'
}

switch ($selectedAction) {
    'Install' {
        & $installScript `
            -BuildDirectory $BuildDirectory `
            -BackupDirectory $BackupDirectory
        Write-Host 'Restart or sign out before checking the Credential Provider tile.' -ForegroundColor Green
    }
    'Unregister' {
        & $uninstallScript `
            -BackupDirectory $BackupDirectory
        Write-Host 'Restart the VM, then rerun this wizard and select Remove the DLL.' -ForegroundColor Green
    }
    'RemoveFile' {
        & $uninstallScript `
            -BackupDirectory $BackupDirectory `
            -RemoveFile
        Write-Host 'The test Credential Provider DLL and rollback backup were removed.' -ForegroundColor Green
    }
    default {
        throw "Unsupported action '$selectedAction'."
    }
}
