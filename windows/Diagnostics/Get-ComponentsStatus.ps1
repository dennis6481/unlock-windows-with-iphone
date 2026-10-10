# Created by Rui MA on 28 Sep 2026

[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\WindowsArchitecture.ps1')

$definitions = @{}
function Read-HeaderDefinitions([string]$Path) {
    $source = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    foreach ($match in [regex]::Matches($source, 'inline constexpr wchar_t (k\w+)\[\] = L"((?:\\.|[^"\\])*)";')) {
        $name = $match.Groups[1].Value
        if ($definitions.ContainsKey($name)) { throw "Duplicate shared definition: $name" }
        $definitions[$name] = $match.Groups[2].Value.Replace('\\', '\').Replace('\"', '"')
    }
    foreach ($match in [regex]::Matches($source, 'inline constexpr std::uint32_t (k\w+) = (\d+);')) {
        $name = $match.Groups[1].Value
        if ($definitions.ContainsKey($name)) { throw "Duplicate shared definition: $name" }
        $definitions[$name] = [uint32]$match.Groups[2].Value
    }
    return $source
}
function Get-Definition([string]$Name) {
    if (!$definitions.ContainsKey($Name)) { throw "Missing shared definition: $Name" }
    return $definitions[$Name]
}
function Read-RegistryRecord([Microsoft.Win32.RegistryKey]$Root, [string]$Path) {
    $key = $Root.OpenSubKey($Path, $false)
    if (!$key) { return $null }
    try {
        $record = [ordered]@{ RegistryPath = $Path }
        foreach ($name in $key.GetValueNames()) { $record[$name] = $key.GetValue($name) }
        return $record
    } finally { $key.Dispose() }
}

$manifest = Read-HeaderDefinitions (Join-Path $PSScriptRoot '..\ComponentFiles.h')
$contract = Read-HeaderDefinitions (Join-Path $PSScriptRoot '..\Setup\SetupContract.h')
Read-HeaderDefinitions (Join-Path $PSScriptRoot '..\SavedCredential\SavedCredentialIpc.h') | Out-Null
Read-HeaderDefinitions (Join-Path $PSScriptRoot '..\PhoneApproval\EnrollmentStore.h') | Out-Null
$versionSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\ProductVersion.h') -Raw -ErrorAction Stop
$version = [regex]::Matches($versionSource, 'kProductVersion\{(\d+), (\d+), (\d+)\}')
if ($version.Count -ne 1) { throw 'Could not parse the authoritative product version.' }
$packageVersion = $version[0].Groups[1..3].Value -join '.'
$buildMetadata = Get-ProductBuildMetadata -Architecture (Get-NativeWindowsArchitecture)
if ($buildMetadata.Version -cne $packageVersion) { throw 'Build metadata version does not match the authoritative product version.' }
$setupBuildName = $buildMetadata.SetupFile
$distDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\dist'))

$entries = [regex]::Matches($manifest, '\{(k\w+), (true|false)\}')
$count = [regex]::Match($manifest, 'std::array<ComponentFile, (\d+)>')
if (!$count.Success -or $entries.Count -ne [int]$count.Groups[1].Value -or !$entries.Count) {
    throw 'Could not parse the complete shared component manifest.'
}
$components = @()
$seen = @{}
foreach ($entry in $entries) {
    $name = Get-Definition $entry.Groups[1].Value
    if ($seen.ContainsKey($name)) { throw "Duplicate component filename: $name" }
    if ([IO.Path]::GetFileName($name) -ne $name -or [IO.Path]::IsPathRooted($name)) {
        throw "Component manifest contains a non-filename value: $name"
    }
    $seen[$name] = $true
    $components += [PSCustomObject]@{ Name = $name; DesktopTool = $entry.Groups[2].Value -eq 'true' }
}

$guidSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\CredentialProvider\UnlockCredentialProvider.h') -Raw -ErrorAction Stop
$guidDefinition = [regex]::Matches($guidSource, 'kUnlockCredentialProviderClsid\s*\{([^;]+)\};')
if ($guidDefinition.Count -ne 1) { throw 'Missing authoritative Credential Provider GUID.' }
$guidParts = @([regex]::Matches($guidDefinition[0].Groups[1].Value, '0x([0-9a-fA-F]+)') |
    ForEach-Object { [Convert]::ToUInt32($_.Groups[1].Value, 16) })
if ($guidParts.Count -ne 11) { throw 'Could not parse the Credential Provider GUID.' }
$credentialProviderClsid = ('{{{0:x8}-{1:x4}-{2:x4}-{3:x2}{4:x2}-{5:x2}{6:x2}{7:x2}{8:x2}{9:x2}{10:x2}}}' -f $guidParts)
$credentialProviderPath = (Get-Definition 'kCredentialProviderRegistryRoot') + '\' + $credentialProviderClsid
$clsidPath = (Get-Definition 'kClsidRegistryRoot') + '\' + $credentialProviderClsid
$rootPath = Get-Definition 'kProductRegistryPath'
$statePath = $rootPath + '\' + (Get-Definition 'kWizardStateKeyName')
$installedPath = $rootPath + '\' + (Get-Definition 'kInstalledProductKeyName')
$resultPath = $rootPath + '\' + (Get-Definition 'kResultKeyName')
$targetSidName = Get-Definition 'kTargetSidValueName'
$installedVersionName = Get-Definition 'kInstalledVersionValueName'
$taskNames = @((Get-Definition 'kBootTask'), (Get-Definition 'kResultTask'), (Get-Definition 'kFinalizeTask'))

$fieldEntries = [regex]::Matches($contract, '\{(k\w+), &CompletionRecord::(\w+)\}')
$fieldCount = [regex]::Match($contract, 'std::array<CompletionTextField, (\d+)>')
if (!$fieldCount.Success -or $fieldEntries.Count -ne [int]$fieldCount.Groups[1].Value -or !$fieldEntries.Count) {
    throw 'Could not parse the authoritative completion field order.'
}
$resultFields = @($fieldEntries | ForEach-Object { Get-Definition $_.Groups[1].Value })
foreach ($layout in [regex]::Matches($contract, 'inline constexpr std::(?:size_t|uint32_t) (kCompletion\w+) = ([^;]+);')) {
    $name = $layout.Groups[1].Value
    if ($definitions.ContainsKey($name)) { continue }
    $parts = [regex]::Split($layout.Groups[2].Value, '\s*([+|])\s*')
    $value = [long]0
    for ($part = 0; $part -lt $parts.Count; $part += 2) {
        $operand = $parts[$part].Trim()
        $number = switch ($operand) {
            'sizeof(std::uint32_t)' { [Runtime.InteropServices.Marshal]::SizeOf([uint32]0) }
            'sizeof(wchar_t)' { [Text.Encoding]::Unicode.GetByteCount('a') }
            'kCompletionTextFields.size()' { $resultFields.Count }
            default {
                if ($operand -match '^\d+$') { [long]$operand }
                elseif ($operand -match '^kCompletion\w+$') { Get-Definition $operand }
                else { throw "Unsupported completion layout expression: $operand" }
            }
        }
        if (!$part) { $value = $number }
        elseif ($parts[$part - 1] -eq '+') { $value += $number }
        else { $value = $value -bor $number }
    }
    $definitions[$name] = $value
}
$wordBytes = Get-Definition 'kCompletionWordBytes'
$characterBytes = Get-Definition 'kCompletionCharacterBytes'
$versionWord = Get-Definition 'kCompletionVersionWord'
$flagsWord = Get-Definition 'kCompletionFlagsWord'
$lengthsWord = Get-Definition 'kCompletionLengthsWord'
$headerBytes = (Get-Definition 'kCompletionHeaderWords') * $wordBytes
$finishedFlag = Get-Definition 'kCompletionFinishedFlag'
$successFlag = Get-Definition 'kCompletionSuccessFlag'

$nativeArchitecture = Get-NativeWindowsArchitecture
if (![Environment]::Is64BitProcess) { throw 'Run diagnostics in 64-bit PowerShell to inspect the native deployment paths.' }
$systemDirectory = [Environment]::SystemDirectory
$desktopDirectory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) (Get-Definition 'kDesktopDirectoryName')
$productDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) (Get-Definition 'kEnrollmentDataDirectoryName')
$transactionRoot = Join-Path (Join-Path $productDirectory (Get-Definition 'kSetupDirectoryName')) (Get-Definition 'kTransactionsDirectoryName')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
try {
    $state = Read-RegistryRecord $machine $statePath
    $installed = Read-RegistryRecord $machine $installedPath
    $rawResult = Read-RegistryRecord $machine $resultPath
    $result = $null
    if ($rawResult) {
        $snapshot = $rawResult[(Get-Definition 'kSnapshotValueName')]
        if ($snapshot -isnot [byte[]] -or $snapshot.Length -lt $headerBytes -or
            $snapshot.Length -gt (Get-Definition 'kCompletionMaximumBytes') -or
            [BitConverter]::ToUInt32($snapshot, $versionWord * $wordBytes) -ne (Get-Definition 'kCompletionVersion')) {
            throw 'Invalid completion snapshot.'
        }
        $flags = [BitConverter]::ToUInt32($snapshot, $flagsWord * $wordBytes)
        if ($flags -band (-bnot (Get-Definition 'kCompletionFlags'))) { throw 'Invalid completion flags.' }
        $result = [ordered]@{ RegistryPath = $resultPath; Finished = ($flags -band $finishedFlag) -ne 0; Success = ($flags -band $successFlag) -ne 0 }
        $offset = $headerBytes
        for ($index = 0; $index -lt $resultFields.Count; $index++) {
            $bytes = [long][BitConverter]::ToUInt32($snapshot, ($lengthsWord + $index) * $wordBytes) * $characterBytes
            if ($bytes -gt $snapshot.Length - $offset) { throw 'Truncated completion field.' }
            $result[$resultFields[$index]] = [Text.Encoding]::Unicode.GetString($snapshot, $offset, [int]$bytes)
            $offset += $bytes
        }
        if ($offset -ne $snapshot.Length) { throw 'Trailing completion snapshot data.' }
    }
    $startupRecord = if ($state) { $state } else { $installed }
    $startupSid = if ($startupRecord) { $startupRecord[$targetSidName] } else { $null }
    $startupCommand = $null
    $startupObservation = 'No recorded target SID'
    if ($startupSid) {
        $hive = $users.OpenSubKey($startupSid, $false)
        if ($hive) {
            try {
                $run = $hive.OpenSubKey((Get-Definition 'kStartupRegistryPath'), $false)
                if ($run) {
                    try { $startupCommand = $run.GetValue((Get-Definition 'kDesktopDirectoryName')) }
                    finally { $run.Dispose() }
                }
                $startupObservation = 'Target hive loaded; Run entry inspected (Windows user enable/disable choice not inspected)'
            } finally { $hive.Dispose() }
        } else { $startupObservation = 'Target user hive not loaded; read-only diagnostics did not mount it' }
    }
    $provider = Read-RegistryRecord $machine $credentialProviderPath
    $clsid = Read-RegistryRecord $machine $clsidPath
    $inproc = Read-RegistryRecord $machine ($clsidPath + '\InprocServer32')
    $uninstall = Read-RegistryRecord $machine (Get-Definition 'kApplicationUninstallRegistryPath')

    Write-Host ('Unlock Windows with iPhone' + [char]0x00AE + ' Components diagnostics') -ForegroundColor Cyan
    [PSCustomObject]@{
        Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        NativeWindowsArchitecture = $nativeArchitecture
        SourcePackageVersion = $packageVersion
        BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
        TransactionRoot = $transactionRoot
        CredentialProviderRegistered = $null -ne $provider
        CredentialProviderClsidRegistered = $null -ne $clsid
        CredentialProviderInprocServer = if ($inproc) { $inproc[''] } else { $null }
        WizardStatePresent = $null -ne $state
        InstalledProductPresent = $null -ne $installed
        CompletionResultPresent = $null -ne $result
        StartupTargetSid = $startupSid
        StartupRunCommand = $startupCommand
        StartupObservation = $startupObservation
    } | Format-List
    foreach ($record in @($state, $installed, $result, $uninstall)) {
        if ($null -ne $record) { [PSCustomObject]$record | Format-List }
    }
} finally { $users.Dispose(); $machine.Dispose() }

$tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.TaskName -in $taskNames })
foreach ($taskName in $taskNames) {
    $task = $tasks | Where-Object TaskName -eq $taskName
    $info = if ($task) { Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop } else { $null }
    [PSCustomObject]@{
        TaskName = $taskName
        Present = $null -ne $task
        State = if ($task) { $task.State } else { $null }
        UserId = if ($task) { $task.Principal.UserId } else { $null }
        RunLevel = if ($task) { $task.Principal.RunLevel } else { $null }
        ExecutionTimeLimit = if ($task) { $task.Settings.ExecutionTimeLimit } else { $null }
        LastRun = if ($info) { $info.LastRunTime } else { $null }
        LastResult = if ($info) { $info.LastTaskResult } else { $null }
    } | Format-List
}
$serviceName = Get-Definition 'kServiceName'
$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
[PSCustomObject]@{
    ServiceName = $serviceName
    Present = $null -ne $service
    State = if ($service) { $service.State } else { $null }
    StartName = if ($service) { $service.StartName } else { $null }
    Path = if ($service) { $service.PathName } else { $null }
} | Format-List

$recordVersion = if ($startupRecord) { $startupRecord[$installedVersionName] } else { $null }
foreach ($component in $components) {
    $installedDirectory = if ($component.DesktopTool) { $desktopDirectory } else { $systemDirectory }
    $buildName = if ($component.Name -eq (Get-Definition 'kInstallerFile')) { $setupBuildName } else { $component.Name }
    $outputDirectory = if ($component.Name -eq (Get-Definition 'kInstallerFile')) { $distDirectory } else { $BuildDirectory }
    foreach ($location in @(
        [PSCustomObject]@{ Role = 'Build'; Path = Join-Path $outputDirectory $buildName; ExpectedVersion = $packageVersion },
        [PSCustomObject]@{ Role = 'Installed'; Path = Join-Path $installedDirectory $component.Name; ExpectedVersion = $recordVersion }
    )) {
        try { $file = Get-Item -LiteralPath $location.Path -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { $file = $null }
        if (!$file) {
            [PSCustomObject]@{ Role = $location.Role; Path = [IO.Path]::GetFullPath($location.Path); Present = $false; ExpectedVersion = $location.ExpectedVersion } | Format-List
            continue
        }
        if ($file.PSIsContainer) { throw "Component path is a directory: $($location.Path)" }
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
        $productVersion = if ($info.ProductVersion) { '{0}.{1}.{2}' -f $info.ProductMajorPart, $info.ProductMinorPart, $info.ProductBuildPart } else { $null }
        [PSCustomObject]@{
            Role = $location.Role
            Path = $file.FullName
            Present = $true
            Architecture = Get-PortableExecutableArchitecture -Path $file.FullName
            ProductVersion = $productVersion
            ProductRevision = $info.ProductPrivatePart
            FileVersion = $info.FileVersion
            ExpectedVersion = $location.ExpectedVersion
            VersionMatchesRecord = if ($location.ExpectedVersion) { $productVersion -eq $location.ExpectedVersion -and $info.ProductPrivatePart -eq 0 } else { $null }
            SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            Attributes = $file.Attributes
        } | Format-List
    }
}
