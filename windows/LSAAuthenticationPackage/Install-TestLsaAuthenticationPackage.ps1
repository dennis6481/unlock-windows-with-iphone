# Created by Rui MA on 27 Sep 2026
# Modified by Codex on 27 Sep 2026

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build'),
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\..\.tmp\lsa-package-backup'),
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

if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw 'The current LSA package build requires a 64-bit Windows OS and 64-bit PowerShell.'
}

$dllName = 'unlock_lsa_authentication_package.dll'
$moduleName = [IO.Path]::GetFileNameWithoutExtension($dllName)
$sourcePath = (Resolve-Path (Join-Path $BuildDirectory $dllName)).Path
$targetPath = Join-Path $env:windir "System32\$dllName"
$lsaRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsaRegistryName = 'Authentication Packages'
$backupDirectoryPath = [IO.Path]::GetFullPath($BackupDirectory)
$backupFile = Join-Path $backupDirectoryPath 'authentication-packages.json'

$lsaValues = @(
    (Get-ItemProperty -LiteralPath $lsaRegistryPath -Name $lsaRegistryName -ErrorAction Stop).$lsaRegistryName
)
if ($lsaValues.Count -eq 0) {
    throw "The registry value '$lsaRegistryName' is empty; refusing to replace the system authentication package list."
}

if ($lsaValues -contains $moduleName) {
    throw "The package '$moduleName' is already registered. Use the rollback script instead of installing twice."
}

if (Test-Path -LiteralPath $targetPath) {
    throw "The target DLL already exists at '$targetPath'; refusing to overwrite an existing system package. Restore the VM snapshot or choose a clean test VM."
}

if (Test-Path -LiteralPath $backupFile) {
    throw "A rollback backup already exists at '$backupFile'. Use a fresh BackupDirectory or remove it only after restoring the VM snapshot."
}

if (-not $PSCmdlet.ShouldProcess(
        "$targetPath and $lsaRegistryPath\$lsaRegistryName",
        "Install $moduleName for the next VM boot"
    )) {
    return
}

New-Item -ItemType Directory -Path $backupDirectoryPath -Force | Out-Null

[ordered]@{
    RegistryPath = $lsaRegistryPath
    RegistryValueName = $lsaRegistryName
    ExistingValues = [string[]]$lsaValues
    ModuleName = $moduleName
    TargetPath = $targetPath
    CreatedAtUtc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $backupFile -Encoding UTF8

Copy-Item -LiteralPath $sourcePath -Destination $targetPath -Force
$registeredValues = @($lsaValues | Where-Object { $_ -ne $moduleName }) + $moduleName
Set-ItemProperty -LiteralPath $lsaRegistryPath -Name $lsaRegistryName -Value ([string[]]$registeredValues)

Write-Host "Installed $moduleName for the next LSA initialization."
Write-Host "Rollback data: $backupFile"
Write-Host 'Reboot the VM, then run LookupAuthenticationPackage.exe to verify that LSA loaded it.'
