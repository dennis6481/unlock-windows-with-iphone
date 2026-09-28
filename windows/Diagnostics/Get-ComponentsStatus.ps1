# Created by Rui MA on 28 Sep 2026

# Read-only Components Wizard diagnostics for Windows 10 and later.

[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\WindowsArchitecture.ps1')

$componentStatePath = 'HKLM:\SOFTWARE\UnlockWindowsWithIPhone\ComponentsWizard'
$credentialProviderClsid = '{2F7A2DF4-75B4-4D8E-8A3B-0DA46C6E9112}'
$credentialProviderPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$credentialProviderClsid"
$clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$credentialProviderClsid"
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$taskName = 'UnlockWindowsWithIPhone-FinalizeUninstall'
$files = @(
    (Join-Path $BuildDirectory 'unlock_windows_components_wizard.exe'),
    (Join-Path $BuildDirectory 'unlock_credential_provider.dll'),
    (Join-Path $BuildDirectory 'unlock_lsa_authentication_package.dll'),
    (Join-Path $env:windir 'System32\unlock_credential_provider.dll'),
    (Join-Path $env:windir 'System32\unlock_lsa_authentication_package.dll')
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$state = Get-ItemProperty -LiteralPath $componentStatePath -ErrorAction SilentlyContinue
$lsaValue = (Get-ItemProperty -LiteralPath $lsaPath -Name 'Authentication Packages' -ErrorAction SilentlyContinue).'Authentication Packages'

Write-Host 'Unlock Windows with iPhone Components diagnostics' -ForegroundColor Cyan
[PSCustomObject]@{
    Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    NativeWindowsArchitecture = Get-NativeWindowsArchitecture
    BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
    CredentialProviderRegistered = Test-Path -LiteralPath $credentialProviderPath
    CredentialProviderClsidRegistered = Test-Path -LiteralPath $clsidPath
    CredentialProviderInprocServer = if (Test-Path -LiteralPath "$clsidPath\InprocServer32") {
        (Get-Item -LiteralPath "$clsidPath\InprocServer32").GetValue('')
    } else {
        $null
    }
    LsaPackageRegistered = ($lsaValue -contains 'unlock_lsa_authentication_package')
    LsaAuthenticationPackages = $lsaValue
    WizardStatePresent = $null -ne $state
    WizardSchemaVersion = if ($state) { $state.SchemaVersion } else { $null }
    WizardPhase = if ($state) { $state.Phase } else { $null }
    WizardTransactionId = if ($state) { $state.TransactionId } else { $null }
    WizardLastError = if ($state) { $state.LastError } else { $null }
    CleanupTaskPresent = $null -ne $task
    CleanupTaskState = if ($task) { $task.State } else { $null }
    CleanupTaskLastRun = if ($task) { $task.LastRunTime } else { $null }
    CleanupTaskLastResult = if ($task) { $task.LastTaskResult } else { $null }
} | Format-List

foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        [PSCustomObject]@{
            Path = [IO.Path]::GetFullPath($file)
            Present = $false
            Architecture = 'NotPresent'
            SHA256 = $null
        } | Format-List
        continue
    }

    $resolved = (Resolve-Path -LiteralPath $file).Path
    [PSCustomObject]@{
        Path = $resolved
        Present = $true
        Architecture = Get-PortableExecutableArchitecture -Path $resolved
        SHA256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
        Attributes = (Get-Item -LiteralPath $resolved).Attributes
    } | Format-List
}
