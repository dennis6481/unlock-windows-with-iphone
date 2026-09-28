# Created by Rui MA on 27 Sep 2026

[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build'),
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\..\.tmp\credential-provider-backup')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\WindowsArchitecture.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window inside the test VM.'
}

$clsid = '{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}'
$providerName = 'Unlock Windows with iPhone'
$dllName = 'unlock_credential_provider.dll'
$sourcePath = (Resolve-Path (Join-Path $BuildDirectory $dllName)).Path
$targetPath = Join-Path $env:windir "System32\$dllName"
$providerRegistrationPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
$inprocPath = "$clsidPath\InprocServer32"
$backupDirectoryPath = [IO.Path]::GetFullPath($BackupDirectory)
$backupFile = Join-Path $backupDirectoryPath 'credential-provider.json'
$nativeArchitecture = Get-NativeWindowsArchitecture
$powerShellArchitecture = Get-CurrentPowerShellArchitecture
$sourceArchitecture = Get-PortableExecutableArchitecture -Path $sourcePath

if ($powerShellArchitecture -ne $nativeArchitecture) {
    throw "This $powerShellArchitecture PowerShell process is emulated on $nativeArchitecture Windows. Run native $nativeArchitecture PowerShell so the Credential Provider registry view matches LogonUI."
}

if ($sourceArchitecture -ne $nativeArchitecture) {
    throw "The source DLL is $sourceArchitecture, but this Windows installation is $nativeArchitecture. Rebuild with make build-release so the Makefile selects the native architecture."
}

if (Test-Path -LiteralPath $backupFile) {
    throw "A rollback backup already exists at '$backupFile'. Use a fresh VM snapshot or restore it before installing again."
}

foreach ($path in @($providerRegistrationPath, $clsidPath, $targetPath)) {
    if (Test-Path -LiteralPath $path) {
        throw "The target already exists at '$path'; refusing to overwrite an existing provider."
    }
}

New-Item -ItemType Directory -Path $backupDirectoryPath -Force | Out-Null
[ordered]@{
    Clsid = $clsid
    ProviderName = $providerName
    SourcePath = $sourcePath
    TargetPath = $targetPath
    NativeWindowsArchitecture = $nativeArchitecture
    PowerShellArchitecture = $powerShellArchitecture
    SourceArchitecture = $sourceArchitecture
    ProviderRegistrationPath = $providerRegistrationPath
    ClsidPath = $clsidPath
    InprocPath = $inprocPath
    CreatedAtUtc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $backupFile -Encoding UTF8

try {
    Copy-Item -LiteralPath $sourcePath -Destination $targetPath

    $installedArchitecture = Get-PortableExecutableArchitecture -Path $targetPath
    if ($installedArchitecture -ne $nativeArchitecture) {
        throw "The copied DLL is $installedArchitecture, but LogonUI requires $nativeArchitecture."
    }

    New-Item -Path $providerRegistrationPath -Force | Out-Null
    Set-Item -LiteralPath $providerRegistrationPath -Value $providerName

    New-Item -Path $inprocPath -Force | Out-Null
    Set-Item -LiteralPath $clsidPath -Value $providerName
    Set-Item -LiteralPath $inprocPath -Value $targetPath
    New-ItemProperty -LiteralPath $inprocPath -Name 'ThreadingModel' -PropertyType String -Value 'Apartment' -Force | Out-Null
} catch {
    Remove-Item -LiteralPath $providerRegistrationPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $clsidPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
    throw
}

Write-Host "Installed $providerName ($sourceArchitecture) for the next VM logon."
Write-Host "Rollback data: $backupFile"
Write-Host 'Reboot or sign out of the VM before checking the Credential Provider tile.'
