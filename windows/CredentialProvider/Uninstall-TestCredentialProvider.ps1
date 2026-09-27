# Created by Rui MA on 27 Sep 2026
# Modified by Codex on 27 Sep 2026

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\..\.tmp\credential-provider-backup'),
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

$backupFile = Join-Path ([IO.Path]::GetFullPath($BackupDirectory)) 'credential-provider.json'
$backupDirectoryPath = [IO.Path]::GetFullPath($BackupDirectory)
if (-not (Test-Path -LiteralPath $backupFile)) {
    throw "Rollback backup was not found at '$backupFile'."
}

$backup = Get-Content -LiteralPath $backupFile -Raw | ConvertFrom-Json
$expectedClsid = '{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}'
if ($backup.Clsid -ne $expectedClsid) {
    throw "The backup is for '$($backup.Clsid)', not '$expectedClsid'."
}

$targetPath = Join-Path $env:windir 'System32\unlock_credential_provider.dll'
if ([IO.Path]::GetFullPath($backup.TargetPath) -ne [IO.Path]::GetFullPath($targetPath)) {
    throw 'The rollback backup target is outside the expected System32 provider path.'
}

$providerRegistrationPath = [string]$backup.ProviderRegistrationPath
$clsidPath = [string]$backup.ClsidPath

if (-not $PSCmdlet.ShouldProcess(
        "$targetPath and $providerRegistrationPath",
        'Remove the test Credential Provider registration'
    )) {
    return
}

Remove-Item -LiteralPath $providerRegistrationPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $clsidPath -Recurse -Force -ErrorAction SilentlyContinue

if ($RemoveFile) {
    try {
        if (Test-Path -LiteralPath $targetPath) {
            Remove-Item -LiteralPath $targetPath -Force -ErrorAction Stop
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
        throw "The registry was restored, but the provider DLL or rollback backup could not be removed. Reboot the VM, then rerun with -RemoveFile. Details: $($_.Exception.Message)"
    }
} else {
    Write-Host 'The registry was restored. Reboot the VM before removing the provider DLL.'
}

Write-Host 'The test Credential Provider registration was rolled back.'
