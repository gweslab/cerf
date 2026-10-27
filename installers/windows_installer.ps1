$ErrorActionPreference = 'Stop'

function Read-YesNo([string] $question, [bool] $default) {
    $hint = '[y/N]'
    if ($default) { $hint = '[Y/n]' }
    while ($true) {
        $answer = (Read-Host "$question $hint").Trim().ToLowerInvariant()
        if ($answer -eq '') { return $default }
        if ($answer -eq 'y' -or $answer -eq 'yes') { return $true }
        if ($answer -eq 'n' -or $answer -eq 'no') { return $false }
    }
}

function Get-StableRelease($client) {
    $release = $client.DownloadString('https://api.github.com/repos/gweslab/cerf/releases/latest') | ConvertFrom-Json
    $asset = $release.assets | Where-Object { $_.name.EndsWith('-Release-Win32.zip') } | Select-Object -First 1
    if (-not $asset) { throw "The release $($release.tag_name) has no *-Release-Win32.zip asset." }
    $sha256 = $null
    if ($asset.digest -and $asset.digest.StartsWith('sha256:')) { $sha256 = $asset.digest.Substring(7) }
    return @{ Kind = 'release'; Version = $release.tag_name; Name = $asset.name; Url = $asset.browser_download_url
              Size = [int64] $asset.size; Sha256 = $sha256 }
}

function Get-UnstableBuild($client) {
    $ciBase = 'https://cerf-bundles.dz3n.net/cerf_ci'
    $latest = $client.DownloadString("$ciBase/latest.json") | ConvertFrom-Json
    $entry = $latest
    if ($latest.host_branches -and $latest.host_branches.'win32-x86') { $entry = $latest.host_branches.'win32-x86' }
    $name = [string] $entry.object_name
    if (-not $name -or $name.Contains('/') -or $name.Contains('\') -or $name.StartsWith('.')) {
        throw 'latest.json names no win32-x86 build.'
    }
    return @{ Kind = 'unstable build'; Version = "$($entry.ver_major).$($entry.ver_minor).$($entry.ver_patch).$($entry.ver_build)"
              Name = $name; Url = "$ciBase/$name"; Size = [int64] $entry.object_size; Sha256 = [string] $entry.object_sha256 }
}

function Install-CeRuntimeFoundation {
    $productName = 'CE Runtime Foundation'

    if ($PSVersionTable.PSVersion.Major -lt 3) {
        throw "This installer needs PowerShell 3.0 or newer. On Windows 7, install Windows Management Framework 5.1 first."
    }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    } catch {
        throw "TLS 1.2 is not available. Install .NET Framework 4.5 or newer first."
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $defaultDir = Join-Path $HOME $productName
    if ($env:APPDATA) { $defaultDir = Join-Path $env:APPDATA $productName }
    while ($true) {
        $installDir = (Read-Host "Install folder (press Enter for $defaultDir)").Trim()
        if ($installDir -eq '' -or $installDir -eq $defaultDir) {
            $installDir = $defaultDir
            break
        }
        Write-Host ("If you have another installation on this computer, the target directory is from now on " +
                    "treated as the only one. When you uninstall, only this directory is removed.")
        Write-Host ("Prefer a directory under your user profile. A system-wide path asks for Administrator rights " +
                    "and can break later upgrades.")
        if (Read-YesNo 'Are you sure you want to change the directory?' $false) { break }
    }
    $desktopIcon = Read-YesNo 'Create desktop icon?' $true
    $startMenu   = Read-YesNo 'Create Start menu entry?' $true
    $launchAfter = Read-YesNo 'Launch after installation?' $true
    $unstable    = Read-YesNo 'Install unstable version?' $false
    if ($unstable) {
        Write-Host ("You picked an unstable build to install. This build might break on new updates or clobber " +
                    "your installation directory. If you want to continue receiving unstable channel updates, " +
                    "pick that channel in Settings later.")
        if (-not (Read-YesNo 'Would you like to continue?' $false)) { return }
    }

    $client = New-Object Net.WebClient
    $client.Headers.Add('User-Agent', 'cerf-windows-installer')
    if ($unstable) { $build = Get-UnstableBuild $client } else { $build = Get-StableRelease $client }
    Write-Host "Latest $($build.Kind): $productName $($build.Version)"

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    $upgradeDir = Join-Path $installDir 'upgrade'
    $zip        = Join-Path $installDir 'upgrade.zip'
    Write-Host "Preparing $upgradeDir"
    if (Test-Path -LiteralPath $upgradeDir) { Remove-Item -LiteralPath $upgradeDir -Recurse -Force }
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }

    Write-Host "Downloading $($build.Name) ($([math]::Round($build.Size / 1MB, 1)) MB)"
    $client.DownloadFile($build.Url, $zip)
    $actual = (Get-Item -LiteralPath $zip).Length
    if ($build.Size -gt 0 -and $actual -ne $build.Size) {
        Remove-Item -LiteralPath $zip -Force
        throw "The download is $actual bytes; the server announced $($build.Size) bytes. $productName was not installed."
    }
    if ($build.Sha256) {
        $hasher = [Security.Cryptography.SHA256]::Create()
        $stream = [IO.File]::OpenRead($zip)
        try {
            $digest = -join ($hasher.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
        } finally {
            $stream.Dispose()
            $hasher.Dispose()
        }
        if ($digest -ne $build.Sha256.ToLowerInvariant()) {
            Remove-Item -LiteralPath $zip -Force
            throw "The SHA-256 of the download does not match the published value. $productName was not installed."
        }
    }

    Write-Host 'Unpacking the archive'
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $upgradeDir)
    Remove-Item -LiteralPath $zip -Force

    $stage = Join-Path $upgradeDir 'cerf.exe'
    if (-not (Test-Path -LiteralPath $stage)) { throw "$($build.Name) contains no cerf.exe. $productName was not installed." }
    Write-Host "Staged the new build in $upgradeDir"

    $arguments = @('--install')
    if ($desktopIcon) { $arguments += '--create-desktop-icon' }
    if ($startMenu) { $arguments += '--create-start-menu-entry' }
    if (-not $launchAfter) { $arguments += '--do-not-launch-after-install' }
    Start-Process -FilePath $stage -ArgumentList $arguments -WorkingDirectory $upgradeDir | Out-Null
}

Install-CeRuntimeFoundation
