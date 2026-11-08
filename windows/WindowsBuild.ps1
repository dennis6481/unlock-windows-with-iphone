# Created by Rui MA on 28 Sep 2026

[CmdletBinding(DefaultParameterSetName = 'Resources')]
param(
    [Parameter(ParameterSetName = 'Resources')][switch]$WriteBuildResources,
    [Parameter(ParameterSetName = 'Prepare', Mandatory)][switch]$Prepare,
    [Parameter(ParameterSetName = 'MSBuild', Mandatory)][switch]$InvokeMSBuild,
    [Parameter(ParameterSetName = 'MSBuild', Position = 0, Mandatory)][string]$ProjectPath,
    [Parameter(ParameterSetName = 'MSBuild', Position = 1, ValueFromRemainingArguments)][string[]]$MSBuildArguments,
    [Parameter(ParameterSetName = 'MSBuild')][switch]$RunTests,
    [string]$OutputDirectory,
    [ValidateSet('auto', 'x64', 'arm64')][string]$TargetArchitecture
)

function Get-NativeWindowsArchitecture {
    [CmdletBinding()]
    param()

    # PROCESSOR_ARCHITEW6432 reports the native OS architecture when a
    # 32-bit PowerShell process is running under WOW64. Prefer it over
    # PROCESSOR_ARCHITECTURE for that case.
    $reportedArchitectures = @(
        $env:PROCESSOR_ARCHITEW6432
        $env:PROCESSOR_ARCHITECTURE
    ) | Where-Object { $_ }

    foreach ($architecture in $reportedArchitectures) {
        switch ($architecture.ToUpperInvariant()) {
            { $_ -in @('ARM64', 'ARM64EC') } { return 'arm64' }
            { $_ -in @('AMD64', 'X64') } { return 'x64' }
        }
    }

    $reportedArchitectureText = $reportedArchitectures -join ', '
    throw "Unsupported native Windows processor architecture value(s): $reportedArchitectureText. Only x64 and ARM64 are supported."
}

function Get-PortableExecutableArchitecture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$ClassifyPayload
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $stream = [System.IO.File]::Open(
        $resolvedPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )

    try {
        if ($stream.Length -lt 0x40) {
            throw "'$resolvedPath' is too small to be a PE file."
        }

        $dosHeader = New-Object byte[] 0x40
        if ($stream.Read($dosHeader, 0, $dosHeader.Length) -ne $dosHeader.Length) {
            throw "Could not read the DOS header from '$resolvedPath'."
        }

        if ([BitConverter]::ToUInt16($dosHeader, 0) -ne 0x5A4D) {
            throw "'$resolvedPath' does not have an MZ header."
        }

        $peHeaderOffset = [BitConverter]::ToInt32($dosHeader, 0x3C)
        if ($peHeaderOffset -lt 0x40 -or $peHeaderOffset -gt ($stream.Length - 6)) {
            throw "'$resolvedPath' has an invalid PE header offset."
        }

        $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $coffHeader = New-Object byte[] 6
        if ($stream.Read($coffHeader, 0, $coffHeader.Length) -ne $coffHeader.Length) {
            throw "Could not read the PE header from '$resolvedPath'."
        }

        if ([BitConverter]::ToUInt32($coffHeader, 0) -ne 0x00004550) {
            throw "'$resolvedPath' does not have a PE signature."
        }

        $machine = [BitConverter]::ToUInt16($coffHeader, 4)
        if ($ClassifyPayload) {
            $data = [IO.File]::ReadAllBytes($resolvedPath)
            if ($peHeaderOffset -gt $data.Length - 24) { throw "Truncated PE file header: $resolvedPath" }
            $sectionCount = [BitConverter]::ToUInt16($data,$peHeaderOffset+6)
            $optionalSize = [BitConverter]::ToUInt16($data,$peHeaderOffset+20)
            $optional = $peHeaderOffset+24
            $sectionTable = $optional+$optionalSize
            if ($optionalSize -lt 20 -or $sectionTable -gt $data.Length - 40*$sectionCount) { throw "Truncated PE optional header or sections: $resolvedPath" }
            $magic = [BitConverter]::ToUInt16($data,$optional)
            if ($magic -notin @(0x10b,0x20b)) { throw "Unsupported PE optional header: $resolvedPath" }
            $nativeCode = [BitConverter]::ToUInt32($data,$optional+16) -ne 0
            for ($i=0; $i -lt $sectionCount; $i++) {
                if ([BitConverter]::ToUInt32($data,$sectionTable+40*$i+36) -band 0x20000000) { $nativeCode=$true }
            }
            # MUI resources and WinMD metadata are PE containers without native executable sections.
            if (!$nativeCode) { return 'neutral' }
            # ARM64X identifies its hybrid fixups with IMAGE_DYNAMIC_RELOCATION_ARM64X (6).
            # Read the PE32+ load configuration and version-1 dynamic relocation table;
            # do not infer hybrid code from a filename or an arbitrary section name.
            if ($machine -eq 0xaa64 -and $optionalSize -ge 200 -and $magic -eq 0x20b) {
                $configRva = [BitConverter]::ToUInt32($data,$optional+192)
                for ($i=0; $configRva -and $i -lt $sectionCount; $i++) {
                    $section=$sectionTable+40*$i
                    $va=[BitConverter]::ToUInt32($data,$section+12)
                    $rawSize=[BitConverter]::ToUInt32($data,$section+16)
                    $raw=[BitConverter]::ToUInt32($data,$section+20)
                    if ($configRva -lt $va -or $configRva-$va -gt [long]$rawSize-232) { continue }
                    $config=[long]$raw+$configRva-$va
                    if ($config -gt $data.Length-232 -or [BitConverter]::ToUInt32($data,$config) -lt 232) { break }
                    $relocOffset=[BitConverter]::ToUInt32($data,$config+224)
                    $relocSection=[BitConverter]::ToUInt16($data,$config+228)
                    if (!$relocSection -or $relocSection -gt $sectionCount) { break }
                    $relocHeader=$sectionTable+40*($relocSection-1)
                    $table=[long][BitConverter]::ToUInt32($data,$relocHeader+20)+$relocOffset
                    $available=[long][BitConverter]::ToUInt32($data,$relocHeader+16)-$relocOffset
                    if ($available -lt 8 -or $table -gt $data.Length-8) { break }
                    $tableSize=[BitConverter]::ToUInt32($data,$table+4)
                    if ([BitConverter]::ToUInt32($data,$table) -ne 1 -or $tableSize -gt $available-8 -or $tableSize -gt $data.Length-$table-8) { break }
                    $cursor=$table+8; $end=$cursor+$tableSize
                    while ($cursor -le $end-12) {
                        $symbol=[BitConverter]::ToUInt64($data,$cursor)
                        $fixups=[BitConverter]::ToUInt32($data,$cursor+8)
                        if ($fixups -gt $end-$cursor-12) { throw "Truncated hybrid PE fixups: $resolvedPath" }
                        if ($symbol -eq 6) { return 'arm64x' }
                        $cursor+=12+$fixups
                    }
                    break
                }
            }
        }
        switch ($machine) {
            0x8664 { return 'x64' }
            0xAA64 { return 'arm64' }
            default {
                $machine = [BitConverter]::ToUInt16($coffHeader, 4).ToString('X4')
                throw "'$resolvedPath' has unsupported PE machine type 0x$machine."
            }
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-CurrentPowerShellArchitecture {
    [CmdletBinding()]
    param()

    $processPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    return Get-PortableExecutableArchitecture -Path $processPath
}

function Get-ProductBuildMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64', 'X64', 'ARM64')][string]$Architecture
    )

    $componentHeader = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ComponentFiles.h'))
    $productHeader = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ProductVersion.h'))
    $versionMatch = [regex]::Match($productHeader, 'kProductVersion\{(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\}')
    if (!$versionMatch.Success) { throw 'Missing Windows product version.' }
    $parts = @(1..4 | ForEach-Object { [uint16]::Parse($versionMatch.Groups[$_].Value) })
    if ($parts[0] -gt 255 -or $parts[1] -gt 255) { throw 'MSI ProductVersion fields require major/minor <= 255 and patch <= 65535; versions are never truncated.' }
    $version = $parts -join '.'
    $releaseVersion = $parts[0..2] -join '.'
    $names = @{}
    foreach ($match in [regex]::Matches($componentHeader, 'wchar_t\s+(\w+)\[\]\s*=\s*L"([^"]+)";')) {
        $names[$match.Groups[1].Value] = $match.Groups[2].Value
    }
    foreach ($required in @('kCredentialProviderFile', 'kSavedCredentialServiceFile', 'kMainAppFile')) {
        if (!$names.ContainsKey($required)) { throw "Missing shared component filename: $required" }
    }
    $minimumBuildMatch = [regex]::Match($componentHeader, 'kMinimumWindowsBuild\s*=\s*(\d+)')
    if (!$minimumBuildMatch.Success) { throw 'Missing minimum Windows build.' }
    $normalizedArchitecture = $Architecture.ToLowerInvariant()
    $msiContract = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Msi/MsiContract.h'))
    $installerMatch = [regex]::Match($msiContract, 'kCustomActionFile\[\]\s*=\s*L"([^"]+)";')
    if (!$installerMatch.Success) { throw 'Missing MSI custom-action filename.' }
    $installerFile = $installerMatch.Groups[1].Value
    $versionFiles = @{
        CredentialProvider = "unlock_credential_provider-version.rc"
        SavedCredentialService = "unlock_saved_credential_service-version.rc"
        MainApp = "UnlockWithIPhone-version.rc"
        Installer = "$([IO.Path]::GetFileNameWithoutExtension($installerFile))-version.rc"
    }
    [pscustomobject]@{
        Architecture = $normalizedArchitecture
        Version = $version
        ReleaseVersion = $releaseVersion
        VersionDefinition = $versionMatch.Value
        Major = $parts[0]
        Minor = $parts[1]
        Patch = $parts[2]
        Build = $parts[3]
        MinimumWindowsBuild = $minimumBuildMatch.Groups[1].Value
        CredentialProviderFile = $names.kCredentialProviderFile
        SavedCredentialServiceFile = $names.kSavedCredentialServiceFile
        MainAppFile = $names.kMainAppFile
        InstallerFile = $installerFile
        SetupFile = "UnlockWithIPhone_${releaseVersion}_${normalizedArchitecture}_setup.msi"
        VersionFiles = $versionFiles
    }
}

function Write-BuildResources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64', 'X64', 'ARM64')][string]$Architecture,
        [object]$Metadata
    )

    if (!$Metadata) { $Metadata = Get-ProductBuildMetadata -Architecture $Architecture }
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $props = @(
        '<!-- Created by Rui MA on 10 Oct 2026 -->',
        '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">',
        '  <PropertyGroup>',
        "    <UnlockProductVersion>$($metadata.Version)</UnlockProductVersion>",
        "    <UnlockProductVersionParts>$($metadata.Major),$($metadata.Minor),$($metadata.Patch),$($metadata.Build)</UnlockProductVersionParts>",
        "    <UnlockArchitecture>$($metadata.Architecture)</UnlockArchitecture>",
        "    <UnlockPlatform>$($metadata.Architecture.ToUpperInvariant())</UnlockPlatform>",
        "    <UnlockMinimumWindowsBuild>$($metadata.MinimumWindowsBuild)</UnlockMinimumWindowsBuild>",
        "    <UnlockCredentialProviderFile>$($metadata.CredentialProviderFile)</UnlockCredentialProviderFile>",
        "    <UnlockSavedCredentialServiceFile>$($metadata.SavedCredentialServiceFile)</UnlockSavedCredentialServiceFile>",
        "    <UnlockMainAppFile>$($metadata.MainAppFile)</UnlockMainAppFile>",
        "    <UnlockMainAppBaseName>$([IO.Path]::GetFileNameWithoutExtension($metadata.MainAppFile))</UnlockMainAppBaseName>",
        "    <UnlockInstallerFile>$($metadata.InstallerFile)</UnlockInstallerFile>",
        "    <UnlockInstallerBaseName>$([IO.Path]::GetFileNameWithoutExtension($metadata.InstallerFile))</UnlockInstallerBaseName>",
        "    <UnlockSetupFile>$($metadata.SetupFile)</UnlockSetupFile>",
        "    <UnlockSetupBaseName>$([IO.Path]::GetFileNameWithoutExtension($metadata.SetupFile))</UnlockSetupBaseName>",
        '  </PropertyGroup>',
        '</Project>'
    )
    [IO.File]::WriteAllLines((Join-Path $Directory 'UnlockBuild.props'), $props, [Text.UTF8Encoding]::new($false))

    $resourceHeader = (Join-Path $PSScriptRoot 'Resources/resource.h').Replace('\', '/')
    $resourceDefinitions = @{
        CredentialProvider = @{ Type = 'VFT_DLL'; Filename = $metadata.CredentialProviderFile }
        SavedCredentialService = @{ Type = 'VFT_APP'; Filename = $metadata.SavedCredentialServiceFile }
        MainApp = @{ Type = 'VFT_APP'; Filename = $metadata.MainAppFile }
        Installer = @{ Type = 'VFT_DLL'; Filename = $metadata.InstallerFile }
    }
    foreach ($name in $resourceDefinitions.Keys) {
        $definition = $resourceDefinitions[$name]
        $content = @(
            '// Created by Rui MA on 10 Oct 2026',
            '',
            '#include <windows.h>',
            "#include ""$resourceHeader""",
            '',
            '1 VERSIONINFO',
            "FILEVERSION $($metadata.Major),$($metadata.Minor),$($metadata.Patch),$($metadata.Build)",
            "PRODUCTVERSION $($metadata.Major),$($metadata.Minor),$($metadata.Patch),$($metadata.Build)",
            'FILEFLAGSMASK VS_FFI_FILEFLAGSMASK',
            'FILEFLAGS 0',
            'FILEOS VOS_NT_WINDOWS32',
            "FILETYPE $($definition.Type)",
            'FILESUBTYPE 0',
            'BEGIN',
            '    BLOCK "StringFileInfo"',
            '    BEGIN',
            '        BLOCK "040904b0"',
            '        BEGIN',
            '            VALUE "CompanyName", "Rui MA\0"',
            '            VALUE "FileDescription", UNLOCK_PRODUCT_NAME',
            "            VALUE ""FileVersion"", ""$($metadata.Version)\0""",
            "            VALUE ""ProductVersion"", ""$($metadata.Version)\0""",
            '            VALUE "ProductName", UNLOCK_PRODUCT_NAME',
            "            VALUE ""OriginalFilename"", ""$($definition.Filename)\0""",
            '        END',
            '    END',
            '    BLOCK "VarFileInfo"',
            '    BEGIN',
            '        VALUE "Translation", 0x0409, 1200',
            '    END',
            'END'
        )
        [IO.File]::WriteAllLines((Join-Path $Directory $metadata.VersionFiles[$name]), $content, [Text.UTF8Encoding]::new($false))
    }
}

function Invoke-WindowsBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectPath,
        [string[]]$Arguments,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [switch]$RunTests
    )

    $project = (Resolve-Path -LiteralPath $ProjectPath -ErrorAction Stop).Path
    $targets = @($Arguments | Where-Object { $_ -match '^[-/](t|target):' })
    $query = @($Arguments | Where-Object { $_ -match '^[-/](getProperty|getItem|pp|preprocess|targets|version|help)(:|$)' })
    $productBuild = $project -ieq (Join-Path $PSScriptRoot 'UnlockWindows.sln') -and !$query.Count -and
        (!$targets.Count -or ($targets.Count -eq 1 -and $targets[0] -match '^[-/](t|target):(Build|Rebuild)$'))
    if ($RunTests -and !$productBuild) { throw 'RunTests requires a complete solution Build or Rebuild.' }

    $directory = Join-Path $PSScriptRoot 'build'
    $configuration = 'Debug'
    foreach ($argument in $Arguments) {
        if ($argument -match '^[-/](p|property):(.+)$') {
            foreach ($property in ($Matches[2] -split ';')) {
                if ($property -match '^UnlockBuildDirectory=(.+)$') { $directory = $Matches[1] }
                elseif ($property -match '^Configuration=(.+)$') { $configuration = $Matches[1] }
            }
        }
    }
    if (![IO.Path]::IsPathRooted($directory)) { $directory = Join-Path (Get-Location).ProviderPath $directory }
    $directory = [IO.Path]::GetFullPath($directory)
    $increment = $productBuild -and $env:CI -ine 'true' -and $env:GITHUB_ACTIONS -ine 'true'
    $metadata = Get-ProductBuildMetadata -Architecture $Architecture
    if ($increment -and $metadata.Build -eq [uint16]::MaxValue) {
        throw 'Product build number is 65535. Set the next release version/build in ProductVersion.h before building.'
    }
    # Refresh before MSBuild evaluates project imports; every project uses this snapshot.
    if (!$query.Count -and (!$targets.Count -or $targets[0] -notmatch '^[-/](t|target):Clean$')) {
        Write-BuildResources -Directory (Join-Path $directory 'generated') -Architecture $Architecture -Metadata $metadata
    }
    $platform = $Architecture.ToUpperInvariant()
    if ($Architecture -eq 'x64') { $platform = 'x64' }
    & MSBuild.exe $project @Arguments "/p:Platform=$platform" "/p:UnlockBuildDirectory=$directory"
    if ($LASTEXITCODE -ne 0) { return }
    if ($RunTests) {
        & MSBuild.exe (Join-Path $PSScriptRoot 'UnlockWindowsTests.proj') /t:Test /m:1 /nologo `
            "/p:Configuration=$configuration" "/p:Platform=$platform" "/p:UnlockBuildDirectory=$directory" /p:BuildTesting=ON
        if ($LASTEXITCODE -ne 0) { return }
    }
    if ($increment) {
        $headerPath = Join-Path $PSScriptRoot 'ProductVersion.h'
        $header = [IO.File]::ReadAllText($headerPath)
        if (!$header.Contains($metadata.VersionDefinition)) { throw 'ProductVersion.h changed during the build; build number was not advanced.' }
        $next = 'kProductVersion{{{0}, {1}, {2}, {3}}}' -f $metadata.Major, $metadata.Minor, $metadata.Patch, ($metadata.Build + 1)
        [IO.File]::WriteAllText($headerPath, $header.Replace($metadata.VersionDefinition, $next), [Text.UTF8Encoding]::new($false))
        Write-Host "Built $($metadata.Version). Next local build: $($metadata.ReleaseVersion).$($metadata.Build + 1)."
    }
}


function Initialize-VisualStudioEnvironment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture)

    if (!$env:UNLOCK_VS_DEV_CMD) { throw 'UNLOCK_VS_DEV_CMD is required.' }
    $devCommand = $env:UNLOCK_VS_DEV_CMD
    if ($devCommand -ieq 'auto') {
        $component = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
        if ($Architecture -eq 'arm64') { $component = 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' }
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $installation = $null
        if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
            $installation = & $vswhere -all -latest -prerelease -products '*' -requires $component -property installationPath
            if ($LASTEXITCODE -ne 0) { throw "vswhere failed with exit code $LASTEXITCODE." }
        }
        if ($installation) {
            $devCommand = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
        } elseif ($env:VSINSTALLDIR -and (Test-Path -LiteralPath (Join-Path $env:VSINSTALLDIR 'Common7\Tools\VsDevCmd.bat') -PathType Leaf)) {
            $devCommand = Join-Path $env:VSINSTALLDIR 'Common7\Tools\VsDevCmd.bat'
            Write-Warning "Visual Studio C++ component $component was not found by vswhere; using the active Developer Command Prompt."
        } else {
            throw "Could not find Visual Studio with $component. Install Desktop development with C++ and the $Architecture MSVC tools."
        }
    }
    if (!(Test-Path -LiteralPath $devCommand -PathType Leaf)) { throw "VsDevCmd.bat was not found at '$devCommand'." }

    $environmentLines = & $env:ComSpec /d /c "call `"$devCommand`" -arch=$Architecture -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0) { throw "VsDevCmd.bat failed with exit code $LASTEXITCODE." }
    foreach ($line in $environmentLines) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            [Environment]::SetEnvironmentVariable($line.Substring(0, $separator), $line.Substring($separator + 1), 'Process')
        }
    }
    foreach ($tool in @('MSBuild.exe', 'rc.exe', 'mt.exe')) {
        if (!(Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue)) {
            throw "Visual Studio environment is missing $tool."
        }
    }
    if (!$env:WindowsSDKVersion) { throw 'Visual Studio environment did not select a Windows SDK.' }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    if ($Prepare -or $InvokeMSBuild) {
        if (!$TargetArchitecture) { $TargetArchitecture = $env:UNLOCK_TARGET_ARCH }
        if (!$TargetArchitecture -or $TargetArchitecture -ieq 'auto') { $TargetArchitecture = Get-NativeWindowsArchitecture }
        if ($TargetArchitecture -notin @('x64', 'arm64')) { throw "Unsupported target architecture '$TargetArchitecture'. Use auto, x64, or arm64." }
        Initialize-VisualStudioEnvironment -Architecture $TargetArchitecture
        if ($Prepare) {
            if (!$OutputDirectory) { throw 'OutputDirectory is required with Prepare.' }
            Write-BuildResources -Directory (Join-Path $OutputDirectory 'generated') -Architecture $TargetArchitecture
        } else {
            Invoke-WindowsBuild -ProjectPath $ProjectPath -Arguments $MSBuildArguments -Architecture $TargetArchitecture -RunTests:$RunTests
            exit $LASTEXITCODE
        }
    } elseif ($WriteBuildResources) {
        if (!$OutputDirectory -or !$TargetArchitecture -or $TargetArchitecture -ieq 'auto') { throw 'OutputDirectory and an explicit TargetArchitecture are required with WriteBuildResources.' }
        Write-BuildResources -Directory $OutputDirectory -Architecture $TargetArchitecture
    } else {
        Get-NativeWindowsArchitecture
    }
}
