<#
.SYNOPSIS
Runs hermetic smoke and failure tests for install.ps1.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "installer test: $Message"
    }
}

function Assert-Equal {
    param(
        [AllowNull()]$Actual,
        [AllowNull()]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if ($Actual -ne $Expected) {
        throw "installer test: $Message (expected '$Expected', got '$Actual')"
    }
}

function Invoke-ExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Operation,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    try {
        & $Operation
    } catch {
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") {
            throw "installer test: unexpected error '$($_.Exception.Message)'; expected '*$ExpectedMessage*'"
        }
        return
    }
    throw "installer test: $FailureMessage"
}

function New-TestZip {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Entries
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $fileStream = $null
    $zipArchive = $null
    try {
        $fileStream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $zipArchive = [IO.Compression.ZipArchive]::new(
            $fileStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $false
        )
        foreach ($name in $Entries.Keys) {
            $entry = $zipArchive.CreateEntry($name)
            $entryStream = $entry.Open()
            try {
                $bytes = [byte[]]$Entries[$name]
                $entryStream.Write($bytes, 0, $bytes.Length)
            } finally {
                $entryStream.Dispose()
            }
        }
    } finally {
        if ($null -ne $zipArchive) { $zipArchive.Dispose() }
        if ($null -ne $fileStream) { $fileStream.Dispose() }
    }
}

function Write-ChecksumManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][object[]]$Lines
    )

    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $content = ($Lines -join "`n") + "`n"
    [IO.File]::WriteAllText(
        (Join-Path $Directory "SHA256SUMS"),
        $content,
        [Text.UTF8Encoding]::new($false)
    )
}

function New-ReleaseFixture {
    param(
        [Parameter(Mandatory = $true)][string]$ReleaseRoot,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][byte[]]$BinaryBytes,
        [hashtable]$AdditionalEntries = @{}
    )

    $target = "x86_64-pc-windows-msvc"
    $archiveName = "sweepx-v$Version-$target.zip"
    $releaseDirectory = Join-Path $ReleaseRoot "download\v$Version"
    $archivePath = Join-Path $releaseDirectory $archiveName
    $entries = @{ "sweepx.exe" = $BinaryBytes }
    foreach ($name in $AdditionalEntries.Keys) {
        $entries[$name] = $AdditionalEntries[$name]
    }
    New-TestZip -Path $archivePath -Entries $entries
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-ChecksumManifest `
        -Directory $releaseDirectory `
        -Lines @("$hash  $archiveName")
    return [pscustomobject]@{
        ArchiveName = $archiveName
        ArchivePath = $archivePath
        Directory = $releaseDirectory
        Hash = $hash
    }
}

function Assert-InstalledBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][byte[]]$ExpectedBytes
    )

    $items = @(Get-ChildItem -Force -LiteralPath $Directory)
    Assert-Equal $items.Count 1 "install directory contains unexpected files"
    Assert-Equal $items[0].Name "sweepx.exe" "installed executable has the wrong name"
    $actualBytes = [IO.File]::ReadAllBytes((Join-Path $Directory "sweepx.exe"))
    Assert-Equal `
        ([Convert]::ToBase64String($actualBytes)) `
        ([Convert]::ToBase64String($ExpectedBytes)) `
        "installed executable bytes differ from the release fixture"
}

function Get-TreeFingerprint {
    param([Parameter(Mandatory = $true)][string]$Root)

    $records = @()
    foreach ($item in Get-ChildItem -Force -Recurse -LiteralPath $Root | Sort-Object FullName) {
        $relative = $item.FullName.Substring($Root.Length).TrimStart('\', '/')
        if ($item.PSIsContainer) {
            $records += "directory|$relative"
        } else {
            $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
            $records += "file|$relative|$($item.Length)|$hash"
        }
    }
    return $records -join "`n"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot "install.ps1"
$originalTemp = [IO.Path]::GetTempPath()
$testRoot = Join-Path $originalTemp ("sweepx-installer-test-" + [guid]::NewGuid().ToString('N'))
$outsideRoot = Join-Path $originalTemp ("sweepx-installer-outside-" + [guid]::NewGuid().ToString('N'))
$environmentNames = @(
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "SWEEPX_BIN_DIR",
    "SWEEPX_VERSION",
    "SWEEPX_BASE_URL",
    "SWEEPX_DOWNLOAD_BASE_URL",
    "SWEEPX_NO_MODIFY_PATH"
)
$savedEnvironment = @{}
$processTarget = [EnvironmentVariableTarget]::Process
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, $processTarget)
}
$processPathBefore = $env:Path
$canReadUserPath = $true
try {
    $userPathBefore = [Environment]::GetEnvironmentVariable(
        "Path",
        [EnvironmentVariableTarget]::User
    )
} catch {
    $canReadUserPath = $false
    $userPathBefore = $null
}

try {
    New-Item -ItemType Directory -Path $testRoot, $outsideRoot | Out-Null
    $isolatedTemp = Join-Path $testRoot "temp"
    $isolatedHome = Join-Path $testRoot "home"
    $isolatedLocalAppData = Join-Path $testRoot "local-app-data"
    New-Item `
        -ItemType Directory `
        -Path $isolatedTemp, $isolatedHome, $isolatedLocalAppData `
        | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $outsideRoot "sentinel"),
        "outside-sentinel",
        [Text.UTF8Encoding]::new($false)
    )
    $outsideBefore = Get-TreeFingerprint $outsideRoot

    [Environment]::SetEnvironmentVariable("TEMP", $isolatedTemp, $processTarget)
    [Environment]::SetEnvironmentVariable("TMP", $isolatedTemp, $processTarget)
    [Environment]::SetEnvironmentVariable("TMPDIR", $isolatedTemp, $processTarget)
    [Environment]::SetEnvironmentVariable("HOME", $isolatedHome, $processTarget)
    [Environment]::SetEnvironmentVariable("USERPROFILE", $isolatedHome, $processTarget)
    [Environment]::SetEnvironmentVariable("LOCALAPPDATA", $isolatedLocalAppData, $processTarget)
    [Environment]::SetEnvironmentVariable("SWEEPX_BIN_DIR", $null, $processTarget)
    [Environment]::SetEnvironmentVariable("SWEEPX_VERSION", $null, $processTarget)
    [Environment]::SetEnvironmentVariable("SWEEPX_BASE_URL", $null, $processTarget)
    [Environment]::SetEnvironmentVariable("SWEEPX_DOWNLOAD_BASE_URL", $null, $processTarget)
    [Environment]::SetEnvironmentVariable("SWEEPX_NO_MODIFY_PATH", $null, $processTarget)

    $releaseRoot = Join-Path $testRoot "releases"
    $fixtureBytes = [Text.Encoding]::UTF8.GetBytes("synthetic sweepx.exe fixture`n")
    $fixture = New-ReleaseFixture `
        -ReleaseRoot $releaseRoot `
        -Version "9.8.7" `
        -BinaryBytes $fixtureBytes

    $latestDirectory = Join-Path $releaseRoot "latest\download"
    New-Item -ItemType Directory -Force -Path $latestDirectory | Out-Null
    Copy-Item -LiteralPath $fixture.ArchivePath -Destination $latestDirectory
    Copy-Item `
        -LiteralPath (Join-Path $fixture.Directory "SHA256SUMS") `
        -Destination $latestDirectory

    $explicitInstall = Join-Path $testRoot "explicit bin"
    New-Item -ItemType Directory -Path $explicitInstall | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $explicitInstall "sweepx.exe"),
        "old executable",
        [Text.UTF8Encoding]::new($false)
    )
    & $installer `
        -Version "9.8.7" `
        -InstallDir $explicitInstall `
        -BaseUrl $releaseRoot `
        -NoModifyPath
    Assert-InstalledBytes -Directory $explicitInstall -ExpectedBytes $fixtureBytes

    # Exercise a file URI, leading-v normalization, and replacement once more.
    $releaseUri = [Uri]::new(
        [IO.Path]::GetFullPath($releaseRoot),
        [UriKind]::Absolute
    ).AbsoluteUri
    & $installer `
        -Version "v9.8.7" `
        -InstallDir $explicitInstall `
        -BaseUrl $releaseUri `
        -NoModifyPath
    Assert-InstalledBytes -Directory $explicitInstall -ExpectedBytes $fixtureBytes

    # Version defaults to latest and InstallDir defaults from SWEEPX_BIN_DIR.
    $latestInstall = Join-Path $testRoot "latest bin"
    [Environment]::SetEnvironmentVariable("SWEEPX_BIN_DIR", $latestInstall, $processTarget)
    [Environment]::SetEnvironmentVariable("SWEEPX_BASE_URL", $releaseRoot, $processTarget)
    [Environment]::SetEnvironmentVariable("SWEEPX_NO_MODIFY_PATH", "1", $processTarget)
    & $installer
    Assert-InstalledBytes -Directory $latestInstall -ExpectedBytes $fixtureBytes

    # With SWEEPX_BIN_DIR absent, LocalAppData is the default root.
    [Environment]::SetEnvironmentVariable("SWEEPX_BIN_DIR", $null, $processTarget)
    $localAppDataInstall = Join-Path $isolatedLocalAppData "Programs\sweepx\bin"
    & $installer -BaseUrl $releaseRoot -NoModifyPath
    Assert-InstalledBytes -Directory $localAppDataInstall -ExpectedBytes $fixtureBytes

    $badHash = New-ReleaseFixture `
        -ReleaseRoot $releaseRoot `
        -Version "9.8.6" `
        -BinaryBytes $fixtureBytes
    Write-ChecksumManifest `
        -Directory $badHash.Directory `
        -Lines @(("0" * 64) + "  " + $badHash.ArchiveName)
    $hashFailureInstall = Join-Path $testRoot "hash failure bin"
    New-Item -ItemType Directory -Path $hashFailureInstall | Out-Null
    $oldHashFailureBytes = [Text.Encoding]::UTF8.GetBytes("old executable")
    [IO.File]::WriteAllBytes(
        (Join-Path $hashFailureInstall "sweepx.exe"),
        $oldHashFailureBytes
    )
    Invoke-ExpectedFailure `
        -ExpectedMessage "Checksum verification failed" `
        -FailureMessage "installer accepted an invalid checksum" `
        -Operation {
            & $installer `
                -Version "9.8.6" `
                -InstallDir $hashFailureInstall `
                -BaseUrl $releaseRoot `
                -NoModifyPath
        }
    Assert-InstalledBytes `
        -Directory $hashFailureInstall `
        -ExpectedBytes $oldHashFailureBytes

    $missingVersion = "9.8.5"
    $missingArchive = "sweepx-v$missingVersion-x86_64-pc-windows-msvc.zip"
    $missingRelease = Join-Path $releaseRoot "download\v$missingVersion"
    Write-ChecksumManifest `
        -Directory $missingRelease `
        -Lines @(("0" * 64) + "  " + $missingArchive)
    $missingInstall = Join-Path $testRoot "missing artifact bin"
    New-Item -ItemType Directory -Path $missingInstall | Out-Null
    $oldMissingBytes = [Text.Encoding]::UTF8.GetBytes("old executable")
    [IO.File]::WriteAllBytes(
        (Join-Path $missingInstall "sweepx.exe"),
        $oldMissingBytes
    )
    Invoke-ExpectedFailure `
        -ExpectedMessage "Could not download $missingArchive" `
        -FailureMessage "installer accepted a missing release artifact" `
        -Operation {
            & $installer `
                -Version $missingVersion `
                -InstallDir $missingInstall `
                -BaseUrl $releaseRoot `
                -NoModifyPath
        }
    Assert-InstalledBytes `
        -Directory $missingInstall `
        -ExpectedBytes $oldMissingBytes

    $badLayout = New-ReleaseFixture `
        -ReleaseRoot $releaseRoot `
        -Version "9.8.4" `
        -BinaryBytes $fixtureBytes `
        -AdditionalEntries @{ "unexpected.txt" = [Text.Encoding]::UTF8.GetBytes("unexpected") }
    $layoutFailureInstall = Join-Path $testRoot "layout failure bin"
    Invoke-ExpectedFailure `
        -ExpectedMessage "must contain only one" `
        -FailureMessage "installer accepted an archive with an extra member" `
        -Operation {
            & $installer `
                -Version "9.8.4" `
                -InstallDir $layoutFailureInstall `
                -BaseUrl $releaseRoot `
                -NoModifyPath
        }
    Assert-True `
        (-not (Test-Path -LiteralPath $layoutFailureInstall)) `
        "invalid archive layout wrote the install directory"

    $duplicateVersion = "9.8.3"
    $duplicateFixture = New-ReleaseFixture `
        -ReleaseRoot $releaseRoot `
        -Version $duplicateVersion `
        -BinaryBytes $fixtureBytes
    Write-ChecksumManifest `
        -Directory $duplicateFixture.Directory `
        -Lines @(
            "$($duplicateFixture.Hash)  $($duplicateFixture.ArchiveName)",
            "$($duplicateFixture.Hash) *$($duplicateFixture.ArchiveName)"
        )
    $duplicateInstall = Join-Path $testRoot "duplicate checksum bin"
    Invoke-ExpectedFailure `
        -ExpectedMessage "exactly one valid checksum" `
        -FailureMessage "installer accepted duplicate checksum entries" `
        -Operation {
            & $installer `
                -Version $duplicateVersion `
                -InstallDir $duplicateInstall `
                -BaseUrl $releaseRoot `
                -NoModifyPath
        }
    Assert-True `
        (-not (Test-Path -LiteralPath $duplicateInstall)) `
        "duplicate checksum failure wrote the install directory"

    $tempLeaks = @(
        Get-ChildItem `
            -Force `
            -LiteralPath $isolatedTemp `
            -Filter "sweepx-install-*" `
            -ErrorAction SilentlyContinue
    )
    Assert-Equal $tempLeaks.Count 0 "installer left temporary directories behind"
    Assert-Equal $env:Path $processPathBefore "-NoModifyPath changed the process PATH"
    if ($canReadUserPath) {
        $userPathAfter = [Environment]::GetEnvironmentVariable(
            "Path",
            [EnvironmentVariableTarget]::User
        )
        Assert-Equal $userPathAfter $userPathBefore "-NoModifyPath changed the user PATH"
    }
    Assert-Equal `
        (Get-TreeFingerprint $outsideRoot) `
        $outsideBefore `
        "installer wrote outside the isolated test roots"

    Write-Host "PowerShell installer tests passed."
} finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $savedEnvironment[$name],
            $processTarget
        )
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -Recurse -Force -LiteralPath $testRoot -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $outsideRoot) {
        Remove-Item -Recurse -Force -LiteralPath $outsideRoot -ErrorAction SilentlyContinue
    }
}
