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
$taskName = 'UnlockWindowsWithIPhone-CompleteOperation'
$savedCredentialServiceName = 'UnlockWindowsSavedCredentialService'
$files = @(
    (Join-Path $BuildDirectory 'setup.exe'),
    (Join-Path $BuildDirectory 'unlock_credential_provider.dll'),
    (Join-Path $BuildDirectory 'unlock_saved_credential_service.exe'),
    (Join-Path $BuildDirectory 'unlock_saved_credential_manager.exe'),
    (Join-Path $BuildDirectory 'unlock_gatt_host.exe'),
    (Join-Path $BuildDirectory 'unlock_pairing_tool.exe'),
    (Join-Path $env:windir 'System32\unlock_credential_provider.dll'),
    (Join-Path $env:windir 'System32\unlock_saved_credential_service.exe'),
    (Join-Path $env:windir 'System32\unlock_gatt_host.exe'),
    (Join-Path $env:windir 'System32\unlock_pairing_tool.exe'),
    (Join-Path $env:windir 'System32\unlock_saved_credential_manager.exe'),
    (Join-Path $env:windir 'System32\unlock_windows_components_wizard.exe')
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
    $_.TaskName -in @($taskName, 'UnlockWindowsWithIPhone-GattHost', 'UnlockWindowsWithIPhone-ComponentResult')
})
$task = $tasks | Where-Object TaskName -eq $taskName
$taskInfo = if ($task) { Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop } else { $null }
$savedCredentialService = Get-CimInstance Win32_Service -Filter "Name='$savedCredentialServiceName'" -ErrorAction Stop
$state = Get-ItemProperty -LiteralPath $componentStatePath -ErrorAction SilentlyContinue
$startupCommand = $null
$startupObservation = 'No recorded target SID'
if ($state -and $state.TargetSid) {
    $hive = "Registry::HKEY_USERS\$($state.TargetSid)"
    if (Test-Path -LiteralPath $hive) {
        $run = Join-Path $hive 'Software\Microsoft\Windows\CurrentVersion\Run'
        if (Test-Path -LiteralPath $run) {
            $startupCommand = (Get-Item -LiteralPath $run -ErrorAction Stop).GetValue('Unlock Windows with iPhone')
        }
        $startupObservation = 'Target hive loaded; Run entry inspected (Windows user enable/disable choice not inspected)'
    } else {
        $startupObservation = 'Target user hive not loaded; read-only diagnostics did not mount it'
    }
}

Write-Host ('Unlock Windows with iPhone' + [char]0x00AE + ' Components diagnostics') -ForegroundColor Cyan
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
    StartupTargetSid = if ($state) { $state.TargetSid } else { $null }
    StartupRunCommand = $startupCommand
    StartupObservation = $startupObservation
    PreviousGattLoginTaskPresent = $null -ne ($tasks | Where-Object TaskName -eq 'UnlockWindowsWithIPhone-GattHost')
    CredentialCleanupConfirmed = if ($state) { $state.CredentialCleanupConfirmed } else { $null }
    SavedCredentialServicePresent = $null -ne $savedCredentialService
    SavedCredentialServiceState = if ($savedCredentialService) { $savedCredentialService.State } else { $null }
    SavedCredentialServiceStartName = if ($savedCredentialService) { $savedCredentialService.StartName } else { $null }
    SavedCredentialServicePath = if ($savedCredentialService) { $savedCredentialService.PathName } else { $null }
    ContinuationTaskPresent = $null -ne $task
    ContinuationTaskState = if ($task) { $task.State } else { $null }
    ContinuationTaskLastRun = if ($taskInfo) { $taskInfo.LastRunTime } else { $null }
    ContinuationTaskLastResult = if ($taskInfo) { $taskInfo.LastTaskResult } else { $null }
} | Format-List

$tasks | Select-Object TaskName, State, @{Name='UserId'; Expression={$_.Principal.UserId}},
    @{Name='RunLevel'; Expression={$_.Principal.RunLevel}},
    @{Name='ExecutionTimeLimit'; Expression={$_.Settings.ExecutionTimeLimit}} | Format-List

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
