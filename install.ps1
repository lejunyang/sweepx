<#
.SYNOPSIS
Installs SweepX from a GitHub release archive.

.DESCRIPTION
Downloads the requested x86-64 Windows release, verifies the SHA-256 checksum,
requires the ZIP archive to contain only a root-level sweepx.exe, and installs
the executable with a same-directory staged move.

.PARAMETER Version
Release version, with or without a leading v. Defaults to latest.

.PARAMETER InstallDir
Destination directory. Defaults to SWEEPX_BIN_DIR when set, otherwise
LocalAppData\Programs\sweepx\bin.

.PARAMETER BaseUrl
Release URL root. Defaults to https://github.com/lejunyang/sweepx/releases.
Local filesystem paths and file:// URIs are also supported.

.PARAMETER NoModifyPath
Do not add the install directory to the current user's PATH or this process's
PATH.

.NOTES
Environment equivalents: SWEEPX_VERSION, SWEEPX_BIN_DIR, SWEEPX_BASE_URL
(or SWEEPX_DOWNLOAD_BASE_URL), and SWEEPX_NO_MODIFY_PATH=1. PATH changes are
limited to the current user; the machine PATH is never changed.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Version = $(if ($env:SWEEPX_VERSION) {
        $env:SWEEPX_VERSION
    } else {
        "latest"
    }),

    [ValidateNotNullOrEmpty()]
    [string]$InstallDir = $(if ($env:SWEEPX_BIN_DIR) {
        $env:SWEEPX_BIN_DIR
    } elseif ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA "Programs\sweepx\bin"
    } else {
        Join-Path `
            ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) `
            "Programs\sweepx\bin"
    }),

    [ValidateNotNullOrEmpty()]
    [string]$BaseUrl = $(if ($env:SWEEPX_BASE_URL) {
        $env:SWEEPX_BASE_URL
    } elseif ($env:SWEEPX_DOWNLOAD_BASE_URL) {
        $env:SWEEPX_DOWNLOAD_BASE_URL
    } else {
        "https://github.com/lejunyang/sweepx/releases"
    }),

    [switch]$NoModifyPath = ($env:SWEEPX_NO_MODIFY_PATH -eq "1")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$target = "x86_64-pc-windows-msvc"
$tempDir = $null
$stagedPath = $null
$backupPath = $null

if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -and
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw "Unsupported Windows architecture: $([Runtime.InteropServices.RuntimeInformation]::OSArchitecture). This release publishes Windows x64 only."
}

function Join-ReleaseLocation {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    if ($Root -match '^(?i:https?|file)://') {
        $trimmedRoot = $Root.TrimEnd([char[]]@('/', '\'))
        return "$trimmedRoot/$($RelativePath.Replace('\', '/'))"
    }

    return Join-Path `
        -Path $Root `
        -ChildPath $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
}

function Copy-ReleaseFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Description
    )

    try {
        if ($Source -match '^(?i:file)://') {
            $sourceUri = [Uri]$Source
            if (-not $sourceUri.IsFile) {
                throw "Unsupported file URI: $Source"
            }
            Copy-Item -LiteralPath $sourceUri.LocalPath -Destination $Destination
            return
        }

        if ($Source -match '^(?i:https?)://') {
            Invoke-WebRequest `
                -UseBasicParsing `
                -Uri $Source `
                -OutFile $Destination
            return
        }

        if ($Source -match '^[A-Za-z][A-Za-z0-9+.-]*://') {
            throw "Unsupported URL scheme in $Source"
        }

        Copy-Item -LiteralPath $Source -Destination $Destination
    } catch {
        throw "Could not download $Description from $Source. $($_.Exception.Message)"
    }
}

function Read-ChecksumEntries {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $entries = @()
    foreach ($rawLine in [IO.File]::ReadAllLines($ManifestPath)) {
        $line = $rawLine.TrimEnd([char]13)
        $match = [regex]::Match(
            $line,
            '^(?<hash>[0-9A-Fa-f]{64})[ \t]+\*?(?<name>.+)$',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if ($match.Success) {
            $entries += [pscustomobject]@{
                Hash = $match.Groups['hash'].Value.ToLowerInvariant()
                Name = $match.Groups['name'].Value
            }
        }
    }
    return $entries
}

function Expand-ValidatedSweepxArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$ArchiveName
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveStream = $null
    $zipArchive = $null
    $entryStream = $null
    $outputStream = $null
    try {
        $archiveStream = [IO.File]::Open(
            $ArchivePath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $zipArchive = [IO.Compression.ZipArchive]::new(
            $archiveStream,
            [IO.Compression.ZipArchiveMode]::Read,
            $false
        )

        if ($zipArchive.Entries.Count -ne 1) {
            throw "$ArchiveName must contain only one root-level sweepx.exe."
        }

        $entry = $zipArchive.Entries[0]
        if ($entry.FullName -cne "sweepx.exe" -or
            $entry.Name -cne "sweepx.exe" -or
            $entry.Length -le 0) {
            throw "$ArchiveName must contain only one non-empty root-level sweepx.exe."
        }

        $entryStream = $entry.Open()
        $outputStream = [IO.File]::Open(
            $OutputPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $entryStream.CopyTo($outputStream)
    } finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $entryStream) { $entryStream.Dispose() }
        if ($null -ne $zipArchive) { $zipArchive.Dispose() }
        if ($null -ne $archiveStream) { $archiveStream.Dispose() }
    }
}

function Get-NormalizedPathEntry {
    param([Parameter(Mandatory = $true)][string]$Entry)

    $normalized = $Entry.Trim()
    if ($normalized.Length -ge 2 -and
        $normalized[0] -eq [char]34 -and
        $normalized[$normalized.Length - 1] -eq [char]34) {
        $normalized = $normalized.Substring(1, $normalized.Length - 2)
    }
    $normalized = [Environment]::ExpandEnvironmentVariables($normalized)
    try {
        $normalized = [IO.Path]::GetFullPath($normalized)
    } catch {
        # Keep unusual but valid PATH entries comparable without rewriting them.
    }

    $root = [IO.Path]::GetPathRoot($normalized)
    while ($normalized.Length -gt $root.Length -and
        ($normalized.EndsWith('\') -or $normalized.EndsWith('/'))) {
        $normalized = $normalized.Substring(0, $normalized.Length - 1)
    }
    return $normalized
}

function Test-PathContains {
    param(
        [AllowNull()][string]$PathValue,
        [Parameter(Mandatory = $true)][string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $false
    }

    $normalizedCandidate = Get-NormalizedPathEntry $Candidate
    $separator = [string][IO.Path]::PathSeparator
    foreach ($entry in $PathValue.Split([char][IO.Path]::PathSeparator)) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }
        if ([string]::Equals(
            (Get-NormalizedPathEntry $entry),
            $normalizedCandidate,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }
    }
    return $false
}

function Add-CurrentUserPath {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $separator = [string][IO.Path]::PathSeparator
    $userPath = [Environment]::GetEnvironmentVariable(
        "Path",
        [EnvironmentVariableTarget]::User
    )
    if (-not (Test-PathContains -PathValue $userPath -Candidate $Directory)) {
        $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
            $Directory
        } else {
            $userPath.TrimEnd([char][IO.Path]::PathSeparator) + $separator + $Directory
        }
        [Environment]::SetEnvironmentVariable(
            "Path",
            $newUserPath,
            [EnvironmentVariableTarget]::User
        )
        Write-Host "Added $Directory to the current user's PATH."
    }

    if (-not (Test-PathContains -PathValue $env:Path -Candidate $Directory)) {
        $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) {
            $Directory
        } else {
            $Directory + $separator + $env:Path
        }
    }
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    throw "InstallDir must not be empty. Set SWEEPX_BIN_DIR or pass -InstallDir."
}
if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    throw "BaseUrl must not be empty."
}
if ($InstallDir.IndexOfAny([char[]]@([char]10, [char]13)) -ge 0 -or
    $BaseUrl.IndexOfAny([char[]]@([char]10, [char]13)) -ge 0) {
    throw "InstallDir and BaseUrl must not contain newlines."
}

$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$isLatest = [string]::Equals($Version, "latest", [StringComparison]::OrdinalIgnoreCase)
if ($isLatest) {
    $releasePath = "latest/download"
    $normalizedVersion = $null
} else {
    $normalizedVersion = if ($Version.StartsWith("v", [StringComparison]::OrdinalIgnoreCase)) {
        $Version.Substring(1)
    } else {
        $Version
    }
    if ($normalizedVersion -cnotmatch '^[0-9][0-9A-Za-z._+\-]*$') {
        throw "Invalid release version: $Version"
    }
    $releasePath = "download/v$normalizedVersion"
}

$releaseLocation = Join-ReleaseLocation -Root $BaseUrl -RelativePath $releasePath

try {
    $tempDir = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("sweepx-install-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    $checksumsPath = Join-Path $tempDir "SHA256SUMS"
    $checksumsSource = Join-ReleaseLocation `
        -Root $releaseLocation `
        -RelativePath "SHA256SUMS"
    Write-Host "Downloading checksums from $checksumsSource"
    Copy-ReleaseFile `
        -Source $checksumsSource `
        -Destination $checksumsPath `
        -Description "SHA256SUMS"

    $checksumEntries = @(Read-ChecksumEntries $checksumsPath)
    if ($isLatest) {
        $archivePattern = '^sweepx-v[0-9][0-9A-Za-z._+\-]*-x86_64-pc-windows-msvc\.zip$'
        $matchingEntries = @(
            $checksumEntries | Where-Object { $_.Name -cmatch $archivePattern }
        )
        if ($matchingEntries.Count -ne 1) {
            throw "SHA256SUMS must contain exactly one SweepX archive for $target."
        }
        $archiveName = $matchingEntries[0].Name
        $expectedHash = $matchingEntries[0].Hash
    } else {
        $archiveName = "sweepx-v$normalizedVersion-$target.zip"
        $matchingEntries = @(
            $checksumEntries | Where-Object { $_.Name -ceq $archiveName }
        )
        if ($matchingEntries.Count -ne 1) {
            throw "SHA256SUMS must contain exactly one valid checksum for $archiveName."
        }
        $expectedHash = $matchingEntries[0].Hash
    }

    $archivePath = Join-Path $tempDir $archiveName
    $archiveSource = Join-ReleaseLocation `
        -Root $releaseLocation `
        -RelativePath $archiveName
    Write-Host "Downloading $archiveSource"
    Copy-ReleaseFile `
        -Source $archiveSource `
        -Destination $archivePath `
        -Description $archiveName

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if (-not [string]::Equals(
        $actualHash,
        $expectedHash,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Checksum verification failed for $archiveName."
    }
    Write-Host "Verified SHA-256 checksum for $archiveName."

    $extractedPath = Join-Path $tempDir "sweepx.exe"
    Expand-ValidatedSweepxArchive `
        -ArchivePath $archivePath `
        -OutputPath $extractedPath `
        -ArchiveName $archiveName

    if (Test-Path -LiteralPath $InstallDir) {
        $installItem = Get-Item -Force -LiteralPath $InstallDir
        if (-not $installItem.PSIsContainer -or
            (($installItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Install path is not a regular directory: $InstallDir"
        }
    } else {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }

    $destination = Join-Path $InstallDir "sweepx.exe"
    if (Test-Path -LiteralPath $destination) {
        $destinationItem = Get-Item -Force -LiteralPath $destination
        if ($destinationItem.PSIsContainer -or
            (($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Install destination is not a regular file: $destination"
        }
    }

    $stagedPath = Join-Path `
        $InstallDir `
        (".sweepx-install-" + [guid]::NewGuid().ToString('N') + ".tmp")
    Copy-Item -LiteralPath $extractedPath -Destination $stagedPath
    if (Test-Path -LiteralPath $destination) {
        $backupPath = Join-Path `
            $InstallDir `
            (".sweepx-install-" + [guid]::NewGuid().ToString('N') + ".bak")
        [IO.File]::Replace($stagedPath, $destination, $backupPath, $true)
        Remove-Item -Force -LiteralPath $backupPath -ErrorAction SilentlyContinue
        $backupPath = $null
    } else {
        [IO.File]::Move($stagedPath, $destination)
    }
    $stagedPath = $null

    Write-Host "Installed sweepx to $destination"
    if (-not $NoModifyPath) {
        Add-CurrentUserPath -Directory $InstallDir
    } elseif (-not (Test-PathContains -PathValue $env:Path -Candidate $InstallDir)) {
        Write-Host "PATH was not modified. Add $InstallDir to PATH to use sweepx."
    }
} finally {
    if ($null -ne $stagedPath -and (Test-Path -LiteralPath $stagedPath)) {
        Remove-Item -Force -LiteralPath $stagedPath -ErrorAction SilentlyContinue
    }
    if ($null -ne $backupPath -and (Test-Path -LiteralPath $backupPath)) {
        Remove-Item -Force -LiteralPath $backupPath -ErrorAction SilentlyContinue
    }
    if ($null -ne $tempDir -and (Test-Path -LiteralPath $tempDir)) {
        Remove-Item -Recurse -Force -LiteralPath $tempDir -ErrorAction SilentlyContinue
    }
}
