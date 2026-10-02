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
$taskName = 'UnlockWindowsWithIPhone-FinalizeUninstall'
$savedCredentialServiceName = 'UnlockWindowsSavedCredentialService'
$files = @(
    (Join-Path $BuildDirectory 'unlock_windows_components_wizard.exe'),
    (Join-Path $BuildDirectory 'unlock_credential_provider.dll'),
    (Join-Path $BuildDirectory 'unlock_saved_credential_service.exe'),
    (Join-Path $BuildDirectory 'unlock_saved_credential_manager.exe'),
    (Join-Path $env:windir 'System32\unlock_credential_provider.dll'),
    (Join-Path $env:windir 'System32\unlock_saved_credential_service.exe')
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$savedCredentialService = Get-CimInstance Win32_Service -Filter "Name='$savedCredentialServiceName'" -ErrorAction Stop
$state = Get-ItemProperty -LiteralPath $componentStatePath -ErrorAction SilentlyContinue

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
    WizardStatePresent = $null -ne $state
    WizardSchemaVersion = if ($state) { $state.SchemaVersion } else { $null }
    WizardPhase = if ($state) { $state.Phase } else { $null }
    WizardTransactionId = if ($state) { $state.TransactionId } else { $null }
    WizardLastError = if ($state) { $state.LastError } else { $null }
    CredentialCleanupConfirmed = if ($state) { $state.CredentialCleanupConfirmed } else { $null }
    SavedCredentialServicePresent = $null -ne $savedCredentialService
    SavedCredentialServiceState = if ($savedCredentialService) { $savedCredentialService.State } else { $null }
    SavedCredentialServiceStartName = if ($savedCredentialService) { $savedCredentialService.StartName } else { $null }
    SavedCredentialServicePath = if ($savedCredentialService) { $savedCredentialService.PathName } else { $null }
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
