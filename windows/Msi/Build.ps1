[CmdletBinding()]
param(
    [switch]$Generate,
    [switch]$Validate,
    [string]$BuildDirectory,
    [string]$PackagePath,
    [ValidateSet('x64','arm64')][string]$Architecture
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\WindowsBuild.ps1')

function Get-HeaderStrings([string]$Path) {
    $values = @{}
    foreach ($match in [regex]::Matches([IO.File]::ReadAllText($Path), 'wchar_t\s+(\w+)\[\]\s*=\s*L"([^"]+)";')) {
        $values[$match.Groups[1].Value] = $match.Groups[2].Value.Replace('\\','\')
    }
    return $values
}
function ConvertTo-Xml([string]$Value) { return [Security.SecurityElement]::Escape($Value) }
function Get-PayloadId([string]$Value) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return 'P' + ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())))).Replace('-','').Substring(0,32) }
    finally { $hash.Dispose() }
}
function Assert-PayloadArchitecture([string]$Path, [string]$Architecture, [bool]$Product) {
    $actual = Get-PortableExecutableArchitecture -Path $Path -ClassifyPayload
    if ($actual -ceq $Architecture) { return }
    if (!$Product -and $actual -in @('neutral','arm64x')) { return }
    throw "Wrong payload PE architecture ($actual, expected $Architecture): $Path"
}
function Get-MsiPayload([string]$Directory, [string]$Architecture) {
    $metadata = Get-ProductBuildMetadata -Architecture $Architecture
    $header = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\ComponentFiles.h'))
    $names = Get-HeaderStrings (Join-Path $PSScriptRoot '..\ComponentFiles.h')
    $entries = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $manifest = [regex]::Match($header, '(?s)kComponentFiles\{\{(.*?)\}\};')
    if (!$manifest.Success) { throw 'Missing component filename contract.' }
    foreach ($match in [regex]::Matches($manifest.Groups[1].Value, '\b(k\w+File)\b')) {
        $name = $names[$match.Groups[1].Value]
        if (!$name -or !$seen.Add($name)) { throw 'Invalid component filename contract.' }
        $entries.Add([pscustomobject]@{Name=$name; Product=$true; Path=(Join-Path $Directory $name)})
    }
    if (!$entries.Count) { throw 'Empty component filename contract.' }
    $pathPolicy = [regex]::Match([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'PayloadPaths.h')), '(?s)kPayloadPathComponentPattern\[\]\s*=\s*LR"regex\((.*?)\)regex";').Groups[1].Value
    if (!$pathPolicy) { throw 'Missing package path policy.' }
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $Directory 'DesktopApp.files'))) {
        $name = $line.Replace('/','\')
        if ([IO.Path]::IsPathRooted($name) -or @($name -split '\\' | Where-Object { $_ -notmatch ('\A(?:' + $pathPolicy + ')\z') }).Count) { throw "Unsafe payload path: $name" }
        if ($name -ceq $metadata.MainAppFile) { continue }
        if (!$seen.Add($name)) { throw "Duplicate payload path: $name" }
        $entries.Add([pscustomobject]@{Name=$name; Product=$false; Path=(Join-Path $Directory $name)})
    }
    foreach ($entry in $entries) {
        $item = Get-Item -LiteralPath $entry.Path -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unsafe payload file: $($entry.Path)" }
        $parent = $item.Directory
        while ($parent.FullName.Length -ge $Directory.Length) {
            if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unsafe payload directory: $($parent.FullName)" }
            $parent = $parent.Parent
        }
        $stream = [IO.File]::OpenRead($entry.Path)
        try { $isPe = $stream.ReadByte() -eq 0x4d -and $stream.ReadByte() -eq 0x5a } finally { $stream.Dispose() }
        if ($isPe) { Assert-PayloadArchitecture $entry.Path $Architecture $entry.Product }
        if ($entry.Product) {
            if (!$isPe) { throw "Product component is not PE: $($entry.Path)" }
            $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($entry.Path)
            if ($info.FileVersion -cne $metadata.Version -or $info.ProductVersion -cne $metadata.Version -or
                [version]::new($info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart) -ne [version]$metadata.Version -or
                [version]::new($info.ProductMajorPart,$info.ProductMinorPart,$info.ProductBuildPart,$info.ProductPrivatePart) -ne [version]$metadata.Version) { throw "Mixed product version: $($entry.Path)" }
        }
    }
    return $entries
}
function Write-MsiSources([string]$Directory, [string]$Architecture) {
    $Directory = (Resolve-Path -LiteralPath $Directory).Path
    $metadata = Get-ProductBuildMetadata -Architecture $Architecture
    $entries = @(Get-MsiPayload $Directory $Architecture)
    $identity = Get-HeaderStrings (Join-Path $PSScriptRoot '..\ProductIdentity.h')
    $contract = Get-HeaderStrings (Join-Path $PSScriptRoot 'MsiContract.h')
    $ipc = Get-HeaderStrings (Join-Path $PSScriptRoot '..\SavedCredential\SavedCredentialIpc.h')
    $provider = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\CredentialProvider\UnlockCredentialProvider.h'))
    $guidParts = @([regex]::Matches(([regex]::Match($provider, '(?s)kUnlockCredentialProviderClsid\{(.*?)\};').Groups[1].Value), '0x([0-9a-fA-F]+)') | ForEach-Object { [Convert]::ToUInt32($_.Groups[1].Value,16) })
    if ($guidParts.Count -ne 11) { throw 'Invalid Credential Provider GUID contract.' }
    $clsid = '{' + ('{0:x8}-{1:x4}-{2:x4}-{3:x2}{4:x2}-{5:x2}{6:x2}{7:x2}{8:x2}{9:x2}{10:x2}' -f $guidParts) + '}'
    [guid]::Parse($clsid) | Out-Null
    $resources = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\Resources\resource.h'))
    $name = [regex]::Match($resources,'#define UNLOCK_PRODUCT_NAME "([^"]+)"').Groups[1].Value.Replace('\x00ae',[string][char]0xae)
    if (!$name) { throw 'Missing product display name.' }
    $definitions = @{
        ProductName=$name; MsiVersion=$metadata.ReleaseVersion; FullVersion=$metadata.Version
        MinimumWindowsBuild=$metadata.MinimumWindowsBuild; DesktopDirectoryName=$identity.kDesktopDirectoryName
        InstalledProductRegistryPath=$identity.kInstalledProductRegistryPath; TargetSidValueName=$identity.kTargetSidValueName
        InstalledVersionValueName=$identity.kInstalledVersionValueName; DeploymentKindValueName=$identity.kDeploymentKindValueName
        MsiProductCodeValueName=$identity.kMsiProductCodeValueName
        MainAppFile=$metadata.MainAppFile; MainAppSource=(Join-Path $Directory $metadata.MainAppFile)
        UpgradeCode=$(if ($Architecture -eq 'x64') { $contract.kX64UpgradeCode } else { $contract.kArm64UpgradeCode })
    }
    $generated = Join-Path $Directory 'generated'
    [IO.Directory]::CreateDirectory($generated) | Out-Null
    $include = @('<Include xmlns="http://wixtoolset.org/schemas/v4/wxs">')
    foreach ($key in ($definitions.Keys | Sort-Object)) {
        if (!$definitions[$key]) { throw "Missing MSI definition: $key" }
        $include += '<?define {0}="{1}" ?>' -f $key,(ConvertTo-Xml $definitions[$key])
    }
    $include += '</Include>'
    [IO.File]::WriteAllLines((Join-Path $generated 'Product.wxi'), $include, [Text.UTF8Encoding]::new($false))
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment>')
    $components = [Collections.Generic.List[string]]::new()
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $id = Get-PayloadId $entry.Name
        $components.Add($id)
        $directoryId = 'DesktopDirectory'
        $parts = @($entry.Name -split '\\')
        $relative = ''
        for ($i=0; $i -lt $parts.Count-1; $i++) {
            $relative += '\' + $parts[$i]
            $childId = Get-PayloadId $relative
            if ($directories.Add($relative)) {
                $lines.Add(('<DirectoryRef Id="{0}"><Directory Id="{1}" Name="{2}" /></DirectoryRef>' -f $directoryId,$childId,(ConvertTo-Xml $parts[$i])))
            }
            $directoryId = $childId
        }
        $lines.Add(('<DirectoryRef Id="{0}">' -f $directoryId))
        $lines.Add(('<Component Id="{0}" Guid="*" Bitness="always64">' -f $id))
        if ($entry.Name -ceq $metadata.MainAppFile) {
            $lines.Add(('<File Id="F{0}" Source="{1}" KeyPath="yes">' -f $id,(ConvertTo-Xml $entry.Path)))
            $lines.Add(('<Shortcut Id="MainShortcut" Directory="ProgramMenuFolder" Name="{0}" Advertise="yes" WorkingDirectory="DesktopDirectory" Icon="AppIcon.exe" />' -f (ConvertTo-Xml $name)))
            $lines.Add('</File>')
        } else {
            $lines.Add(('<File Id="F{0}" Source="{1}" KeyPath="yes" />' -f $id,(ConvertTo-Xml $entry.Path)))
        }
        if ($entry.Name -ceq $metadata.CredentialProviderFile) {
            $providerKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\' + $clsid
            $comKey = 'SOFTWARE\Classes\CLSID\' + $clsid
            $lines.Add(('<RegistryKey Root="HKLM" Key="{0}" ForceDeleteOnUninstall="yes"><RegistryValue Type="string" Value="{1}" /></RegistryKey>' -f $providerKey,(ConvertTo-Xml $name)))
            $lines.Add(('<RegistryKey Root="HKLM" Key="{0}" ForceDeleteOnUninstall="yes"><RegistryValue Type="string" Value="{1}" />' -f $comKey,(ConvertTo-Xml $name)))
            $lines.Add(('<RegistryKey Key="InprocServer32"><RegistryValue Type="string" Value="[#F{0}]" />' -f $id))
            $lines.Add('<RegistryValue Name="ThreadingModel" Type="string" Value="Apartment" /></RegistryKey></RegistryKey>')
        }
        if ($entry.Name -ceq $metadata.SavedCredentialServiceFile) {
            $lines.Add(('<ServiceInstall Id="CredentialService" Name="{0}" DisplayName="{1}" Type="ownProcess" Start="auto" ErrorControl="normal" Account="LocalSystem" Vital="yes" />' -f $ipc.kServiceName,(ConvertTo-Xml $ipc.kServiceDisplayName)))
            $lines.Add(('<ServiceControl Id="CredentialServiceControl" Name="{0}" Stop="both" Remove="uninstall" Wait="yes" />' -f $ipc.kServiceName))
        }
        $lines.Add('</Component>')
        $lines.Add('</DirectoryRef>')
    }
    $lines.Add('<ComponentGroup Id="ProductPayload">')
    foreach ($id in $components) { $lines.Add(('<ComponentRef Id="{0}" />' -f $id)) }
    $lines.Add('</ComponentGroup></Fragment></Wix>')
    [IO.File]::WriteAllLines((Join-Path $generated 'Payload.wxs'),$lines,[Text.UTF8Encoding]::new($false))
    $license = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\..\LICENSE.md'))
    $rtf = '{\rtf1\ansi ' + $license.Replace('\','\\').Replace('{','\{').Replace('}','\}').Replace("`r",'').Replace("`n",'\par ') + '}'
    [IO.File]::WriteAllText((Join-Path $generated 'License.rtf'),$rtf,[Text.Encoding]::ASCII)
}

function Read-MsiRows($Database, [string]$Query, [int]$Columns) {
    $view = $Database.OpenView($Query)
    try {
        [void]$view.Execute()
        while ($record = $view.Fetch()) {
            $row = @(); for ($i=1; $i -le $Columns; $i++) { $row += $record.StringData($i) }
            ,$row
        }
    } finally { [void]$view.Close() }
}
function Export-MsiStream($Database, [ValidateSet('_Streams','Binary')][string]$Table, [string]$Name, [string]$Path) {
    $escapedName = $Name.Replace("'","''")
    $view = $Database.OpenView("SELECT ``Data`` FROM ``$Table`` WHERE ``Name``='$escapedName'")
    try {
        $view.Execute(); $record=$view.Fetch()
        if (!$record) { throw "Missing MSI $Table stream $Name" }
        $stream = [IO.File]::Create($Path)
        try {
            do {
                $chunk=$record.ReadStream(1,1048576,1)
                if ($null -eq $chunk) { break }
                # msiReadStreamBytes returns a BSTR with one byte per character.
                $data=[Text.Encoding]::GetEncoding(28591).GetBytes($chunk)
                $stream.Write($data,0,$data.Length)
            } while ($data.Length -eq 1048576)
        } finally { $stream.Dispose() }
    } finally { $view.Close() }
}
function Test-MsiPackage([string]$Path, [string]$Architecture, [string]$Directory) {
    $metadata = Get-ProductBuildMetadata -Architecture $Architecture
    $Path = (Resolve-Path -LiteralPath $Path).Path
    if ([IO.Path]::GetFileName($Path) -cne $metadata.SetupFile) { throw 'MSI filename does not match product metadata.' }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Path,0)
    $properties = @{}
    foreach ($row in (Read-MsiRows $database 'SELECT `Property`,`Value` FROM `Property`' 2)) { $properties[$row[0]]=$row[1] }
    if ($properties.ProductVersion -cne $metadata.ReleaseVersion -or $properties.FullProductVersion -cne $metadata.Version -or $properties.ALLUSERS -ne '1') { throw 'MSI version or machine scope mismatch.' }
    $template = $database.SummaryInformation(0).Property(7)
    $expectedPlatform = if ($Architecture -eq 'x64') { 'x64' } else { 'Arm64' }
    if (($template -split ';')[0] -cne $expectedPlatform) { throw "Wrong MSI architecture: $template" }
    $codes = Get-HeaderStrings (Join-Path $PSScriptRoot 'MsiContract.h')
    $upgrade = if ($Architecture -eq 'x64') { $codes.kX64UpgradeCode } else { $codes.kArm64UpgradeCode }
    if ($properties.UpgradeCode -ine $upgrade) { throw 'Wrong MSI product family.' }
    [guid]::Parse($properties.ProductCode) | Out-Null
    [guid]::Parse($database.SummaryInformation(0).Property(9)) | Out-Null
    if ($properties.ContainsKey('REINSTALLMODE')) { throw 'Do not override REINSTALLMODE in the package Property table.' }
    $repairModes = @(Read-MsiRows $database 'SELECT `Argument` FROM `ControlEvent` WHERE `Event`=''ReinstallMode''' 1)
    if (!@($repairModes | Where-Object { $_[0] -match 'e' -and $_[0] -notmatch 'a' }).Count) { throw 'Repair must replace equal-version files without forcing replacement of every file.' }
    $upgrades = @(Read-MsiRows $database 'SELECT `VersionMax`,`Attributes`,`ActionProperty` FROM `Upgrade`' 3)
    if (!@($upgrades | Where-Object { $_[2] -ceq 'WIX_UPGRADE_DETECTED' -and $_[0] -ceq $metadata.ReleaseVersion -and ([int]$_[1] -band 512) }).Count) { throw 'Same MSI version upgrade recognition is missing.' }
    $media = @(Read-MsiRows $database 'SELECT `Cabinet` FROM `Media`' 1)
    if (!$media.Count -or @($media | Where-Object { !$_[0].StartsWith('#') }).Count) { throw 'MSI payload must use embedded cabinets.' }
    $actions = @{}
    foreach ($row in (Read-MsiRows $database 'SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`' 4)) { $actions[$row[0]]=$row }
    $authoring = [xml][IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Package.wxs'))
    $authoredRemovalCondition = $authoring.SelectSingleNode('//*[local-name()="InstallExecuteSequence"]/*[@Action="RemoveProductData"]').Condition
    if ($authoredRemovalCondition -cne 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE') { throw 'Data removal must be limited to active full uninstall.' }
    $ipc = Get-HeaderStrings (Join-Path $PSScriptRoot '..\SavedCredential\SavedCredentialIpc.h')
    $serviceControls = @(Read-MsiRows $database 'SELECT `Name`,`Event`,`Wait` FROM `ServiceControl`' 3)
    $serviceControl = @($serviceControls | Where-Object { $_[0] -ceq $ipc.kServiceName })
    if ($serviceControl.Count -ne 1 -or ([int]$serviceControl[0][1] -band 0xa0) -ne 0xa0 -or
        $serviceControl[0][2] -ne '1') { throw 'Uninstall must stop and wait for the credential service before removing it.' }
    $sequence = @{}
    foreach ($row in (Read-MsiRows $database 'SELECT `Action`,`Condition`,`Sequence` FROM `InstallExecuteSequence`' 3)) { $sequence[$row[0]]=$row }
    $uiSequence = @{}
    foreach ($row in (Read-MsiRows $database 'SELECT `Action`,`Condition`,`Sequence` FROM `InstallUISequence`' 3)) { $uiSequence[$row[0]]=$row }
    foreach ($table in @('InstallUISequence','InstallExecuteSequence')) {
        $tableSequence = if ($table -ceq 'InstallUISequence') { $uiSequence } else { $sequence }
        foreach ($node in $authoring.SelectNodes("//*[local-name()='$table']/*[@Action]")) {
            if ($tableSequence[$node.Action][1] -cne [string]$node.Condition) { throw "MSI action condition differs from authoring: $table/$($node.Action)" }
        }
        if (!$tableSequence.ContainsKey('CheckExeInstallation') -or
            [int]$tableSequence.CheckExeInstallation[2] -le [int]$tableSequence.LaunchConditions[2] -or
            [int]$tableSequence.CheckExeInstallation[2] -ge [int]$tableSequence.CostInitialize[2]) {
            throw "EXE installation check must follow launch conditions before costing: $table"
        }
    }
    if (!$sequence.ContainsKey('CloseApplication') -or
        [int]$sequence.ValidateDeployment[2] -ge [int]$sequence.CloseApplication[2] -or
        [int]$sequence.CloseApplication[2] -ge [int]$sequence.InstallValidate[2] -or
        [int]$sequence.RemoveExistingProducts[2] -le [int]$sequence.InstallExecute[2] -or
        [int]$sequence.RemoveExistingProducts[2] -ge [int]$sequence.InstallFinalize[2] -or
        [int]$sequence.RollbackDeployment[2] -le [int]$sequence.InstallInitialize[2] -or
        [int]$sequence.PrepareDeployment[2] -le [int]$sequence.RollbackDeployment[2] -or
        [int]$sequence.PrepareDeployment[2] -ge [int]$sequence.StopServices[2] -or
        [int]$sequence.CompleteDeployment[2] -le [int]$sequence.RemoveExistingProducts[2] -or
        [int]$sequence.CompleteDeployment[2] -ge [int]$sequence.CommitDeployment[2] -or
        [int]$sequence.CommitDeployment[2] -ge [int]$sequence.InstallFinalize[2] -or
        $sequence.RemoveProductData[1] -cne $authoredRemovalCondition -or
        [int]$sequence.RemoveProductData[2] -le [int]$sequence.StopServices[2] -or
        [int]$sequence.RemoveProductData[2] -ge [int]$sequence.DeleteServices[2] -or
        [int]$sequence.RemoveProductData[2] -ge [int]$sequence.RemoveFiles[2]) { throw 'Unsafe MSI lifecycle action ordering or conditions.' }
    foreach ($name in @('PrepareDeployment','CompleteDeployment','RemoveProductData')) {
        if (([int]$actions[$name][1] -band 0xc00) -ne 0xc00) { throw "Native deferred action must run as installer server: $name" }
    }
    $files = @(Read-MsiRows $database 'SELECT `File`,`FileName`,`Version`,`Component_`,`Language` FROM `File`' 5)
    $components = @{}
    foreach ($row in (Read-MsiRows $database 'SELECT `Component`,`Directory_`,`Attributes` FROM `Component`' 3)) { $components[$row[0]]=$row }
    $directories = @{}
    foreach ($row in (Read-MsiRows $database 'SELECT `Directory`,`Directory_Parent`,`DefaultDir` FROM `Directory`' 3)) { $directories[$row[0]]=$row }
    $identity = Get-HeaderStrings (Join-Path $PSScriptRoot '..\ProductIdentity.h')
    $root = $directories['DesktopDirectory']
    if (!$root -or $root[1] -cne 'ProgramFiles64Folder' -or
        (($root[2] -split ':')[0] -split '\|')[-1] -cne $identity.kDesktopDirectoryName) { throw 'Wrong MSI product installation directory.' }
    $expected = @(Get-MsiPayload ((Resolve-Path -LiteralPath $Directory).Path) $Architecture)
    if ($files.Count -ne $expected.Count) { throw 'Unexpected MSI file count.' }
    # Extract embedded cabinets as data with expand.exe; never execute msiexec or an administrative install.
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('UnlockMsiCheck-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($scratch) | Out-Null
    try {
        $cabIndex = 0
        foreach ($row in $media) {
            $name = $row[0].Substring(1)
            $cab = Join-Path $scratch ("payload$($cabIndex++).cab")
            Export-MsiStream $database '_Streams' $name $cab
            & "$env:SystemRoot\System32\expand.exe" '-F:*' $cab $scratch | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'MSI cabinet extraction failed.' }
        }
        foreach ($entry in $expected) {
            $id = 'F' + (Get-PayloadId $entry.Name)
            $extracted = Join-Path $scratch $id
            if (!(Test-Path -LiteralPath $extracted -PathType Leaf) -or
                (Get-FileHash -LiteralPath $extracted -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $entry.Path -Algorithm SHA256).Hash) { throw "MSI cabinet payload mismatch: $($entry.Name)" }
            $match = @($files | Where-Object { $_[0] -ceq $id })
            if ($match.Count -ne 1 -or ($entry.Product -and $match[0][2] -cne $metadata.Version)) { throw "MSI file metadata mismatch: $($entry.Name)" }
            # Read language in the original MUI layout; CAB file IDs lose satellite associations.
            if ($match[0][4] -cne [string]$installer.FileVersion($entry.Path,$true)) { throw "MSI file language differs from payload: $($entry.Name)" }
            if ($match[0][4]) {
                foreach ($language in ($match[0][4] -split ',')) {
                    if ($language -notmatch '\A[0-9]+\z') { throw "Invalid MSI file language: $($entry.Name)" }
                    if ([int]$language -ne 0) { [Globalization.CultureInfo]::GetCultureInfo([int]$language) | Out-Null }
                }
            }
            $component = $components[$match[0][3]]
            if (!([int]$component[2] -band 256)) { throw 'Product files require native 64-bit components.' }
            $directoryId = $component[1]
            $relative = ($match[0][1] -split '\|')[-1]
            $visited = [Collections.Generic.HashSet[string]]::new()
            while ($directoryId -cne 'DesktopDirectory') {
                if (!$visited.Add($directoryId) -or !$directories.ContainsKey($directoryId)) { throw 'Invalid MSI target directory chain.' }
                $directoryRow = $directories[$directoryId]
                $relative = (($directoryRow[2] -split ':')[0] -split '\|')[-1] + '\' + $relative
                $directoryId = $directoryRow[1]
            }
            if ($relative -cne $entry.Name) { throw "Unexpected MSI install path: $($entry.Name)" }
            $stream=[IO.File]::OpenRead($extracted)
            try { $pe=$stream.ReadByte() -eq 0x4d -and $stream.ReadByte() -eq 0x5a } finally { $stream.Dispose() }
            if ($pe) { Assert-PayloadArchitecture $extracted $Architecture $entry.Product }
            if ($entry.Product -and [Diagnostics.FileVersionInfo]::GetVersionInfo($extracted).FileVersion -cne $metadata.Version) { throw 'MSI extracted four-part file version mismatch.' }
        }
        $nativeActions = Join-Path $scratch $metadata.InstallerFile
        Export-MsiStream $database 'Binary' 'NativeActions' $nativeActions
        Assert-PayloadArchitecture $nativeActions $Architecture $true
        if ([Diagnostics.FileVersionInfo]::GetVersionInfo($nativeActions).FileVersion -cne $metadata.Version -or
            [Diagnostics.FileVersionInfo]::GetVersionInfo($nativeActions).ProductVersion -cne $metadata.Version -or
            (Get-FileHash -LiteralPath $nativeActions -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath (Join-Path $Directory $metadata.InstallerFile) -Algorithm SHA256).Hash) { throw 'Embedded native MSI action architecture/version/content mismatch.' }
    } finally {
        $resolvedScratch = [IO.Path]::GetFullPath($scratch)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (!$resolvedScratch.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe MSI validation scratch path.' }
        Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
    }
    Write-Host "Verified self-contained $Architecture MSI $($metadata.Version)."
}
if ($MyInvocation.InvocationName -ne '.') {
    if (!$Architecture -or !$BuildDirectory) { throw 'Architecture and BuildDirectory are required.' }
    if ($Generate) { Write-MsiSources $BuildDirectory $Architecture }
    elseif ($Validate) { Test-MsiPackage $PackagePath $Architecture $BuildDirectory }
    else { throw 'Select Generate or Validate.' }
}
