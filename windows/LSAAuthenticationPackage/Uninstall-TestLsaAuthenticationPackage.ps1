# Created by Rui MA on 27 Sep 2026
# Modified by Codex on 27 Sep 2026

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\..\.tmp\lsa-package-backup'),
    [switch]$RemoveFile,
    [switch]$IUnderstandThisIsAThrowawayVm
)

$ErrorActionPreference = 'Stop'

if (-not $IUnderstandThisIsAThrowawayVm) {
    throw 'This script is only for a disposable VM. Re-run with -IUnderstandThisIsAThrowawayVm.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window inside the test VM.'
}

$backupFile = Join-Path ([IO.Path]::GetFullPath($BackupDirectory)) 'authentication-packages.json'
$backupDirectoryPath = [IO.Path]::GetFullPath($BackupDirectory)
if (-not (Test-Path -LiteralPath $backupFile)) {
    throw "Rollback backup was not found at '$backupFile'."
}

$backup = Get-Content -LiteralPath $backupFile -Raw | ConvertFrom-Json
$expectedModuleName = 'unlock_lsa_authentication_package'
if ($backup.ModuleName -ne $expectedModuleName) {
    throw "The backup is for '$($backup.ModuleName)', not '$expectedModuleName'."
}

$expectedTargetPath = Join-Path $env:windir 'System32\unlock_lsa_authentication_package.dll'
if ([IO.Path]::GetFullPath($backup.TargetPath) -ne [IO.Path]::GetFullPath($expectedTargetPath)) {
    throw 'The rollback backup target is outside the expected System32 package path.'
}

$lsaRegistryPath = [string]$backup.RegistryPath
$lsaRegistryName = [string]$backup.RegistryValueName
$originalValues = [string[]]$backup.ExistingValues

if (-not $PSCmdlet.ShouldProcess(
        "$($backup.TargetPath) and $lsaRegistryPath\$lsaRegistryName",
        "Restore the pre-install LSA package state"
    )) {
    return
}

Set-ItemProperty -LiteralPath $lsaRegistryPath -Name $lsaRegistryName -Value $originalValues

if ($RemoveFile) {
    try {
        if (Test-Path -LiteralPath $backup.TargetPath) {
            Remove-Item -LiteralPath $backup.TargetPath -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $backupFile) {
            Remove-Item -LiteralPath $backupFile -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $backupDirectoryPath) {
            $remainingBackupItems = @(Get-ChildItem -LiteralPath $backupDirectoryPath -Force -ErrorAction SilentlyContinue)
            if ($remainingBackupItems.Count -eq 0) {
                Remove-Item -LiteralPath $backupDirectoryPath -Force -ErrorAction Stop
            }
        }
    } catch {
        throw "The registry was restored, but the package DLL or rollback backup could not be removed. Reboot the VM, then rerun with -RemoveFile. Details: $($_.Exception.Message)"
    }
} else {
    Write-Host 'The registry was restored. Reboot the VM before removing the package DLL.'
}

Write-Host 'The test LSA package registration was rolled back.'
