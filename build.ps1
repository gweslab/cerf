param(
    [string]$Config = "Release",
    [ValidateSet("dev","production")]
    [string]$Mode   = "dev",
    [switch]$ForceKill,
    [switch]$Rebuild
)

# Run from the repo root, regardless of where the script is invoked from.
# Do NOT hardcode a drive letter -- this script ships in the repo and runs
# on whatever machine has it checked out (Z:\ on the maintainer's box,
# D:\a\cerf\cerf on a GitHub Actions runner, anything in between).
Set-Location $PSScriptRoot

# vcpkg MSBuild integration -- required for manifest-mode restore of libslirp + glib.
# One-time setup: run 'vcpkg integrate install' from the VS-bundled vcpkg at
# "<VS install>\VC\vcpkg\vcpkg.exe" (ships with the C++ desktop workload).
if (-not (Test-Path "$env:LOCALAPPDATA\vcpkg\vcpkg.user.props")) {
    Write-Host "[BUILD] FAILED! vcpkg MSBuild integration missing. Run 'vcpkg integrate install' from the vcpkg that ships with Visual Studio (path is '<VS install>\VC\vcpkg\vcpkg.exe' inside the VS install -- comes with the C++ desktop workload)."
    [Environment]::Exit(1)
}

$waitDeadline = (Get-Date).AddMinutes(7)
while ($true) {
    $blockingProcs = @()
    foreach ($n in @("cerf","MSBuild","cl","link")) {
        $blockingProcs += Get-Process -Name $n -ErrorAction SilentlyContinue
    }
    if (-not $blockingProcs) { break }

    if ($ForceKill) {
        foreach ($p in $blockingProcs) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $p | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
        }
        break
    }

    $names = ($blockingProcs | Select-Object -ExpandProperty Name -Unique) -join ", "
    if ((Get-Date) -ge $waitDeadline) {
        Write-Host "[BUILD] FAILED! The user OR other agent has been building/running CERF for more than 7 minutes (processes: $names)."
        Write-Host "[BUILD] If you are 100% sure that this is yours stuck build, then re-run with: build.ps1 -ForceKill"
        Write-Host "[BUILD] Otherwise, WAIT for the process to be closed and +~1 minute (recommended). DONT CORRUPT SOMEONE'S WORK."
        [Environment]::Exit(1)
    }

    $remaining = [int]($waitDeadline - (Get-Date)).TotalSeconds
    Write-Host "[BUILD] Waiting for: $names ($remaining s budget remaining)..."
    foreach ($p in $blockingProcs) {
        $rem = [int]($waitDeadline - (Get-Date)).TotalSeconds
        if ($rem -le 0) { break }
        $p | Wait-Process -Timeout $rem -ErrorAction SilentlyContinue
    }
    if ((Get-Date) -lt $waitDeadline) {
        Start-Sleep -Seconds 30
    }
}

if ($Config -match "^d(ebug)?$") { $Config = "Debug" }

Write-Host "============================================================"
Write-Host "[BUILD] Starting build: $Config Win32"
Write-Host "        Full rebuild might take 5+ minutes"
Write-Host "============================================================"

# Locate MSBuild via vswhere -- works for any VS edition / version installed
# at any path. vswhere ships with the VS Installer at a fixed location on
# every machine that has any VS install. -prerelease so VS preview/insider
# channels (e.g. early VS 2026 builds) are also picked up.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    Write-Host "[BUILD] FAILED! vswhere.exe not found at $vswhere. Install Visual Studio with the C++ desktop workload."
    [Environment]::Exit(1)
}
$msbuild = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\amd64\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild -or -not (Test-Path $msbuild)) {
    Write-Host "[BUILD] FAILED! MSBuild.exe not found via vswhere. Ensure Visual Studio's C++ desktop workload is installed."
    [Environment]::Exit(1)
}

# Reset $LASTEXITCODE so a stale value from outside the script can't
# make a throw-before-native-run look successful.
$global:LASTEXITCODE = 0
# PlatformToolset is intentionally NOT set here -- the .vcxproj defers to
# Microsoft.Cpp.Default.props, which picks whichever toolset the installed
# VS provides (v143 on VS 2022, v145 on VS 2026). Forcing a specific value
# from the build script is what made this script unportable in the first
# place.
$devModeFlag = if ($Mode -eq "production") { "0" } else { "1" }
$cerfDefines = "CERF_DEV_MODE=$devModeFlag"
Write-Host "[BUILD] Mode: $Mode (CERF_DEV_MODE=$devModeFlag)"

$buildsSucceeded = 0
$buildsFailed    = 0
$failedNames     = @()

$launcherBuild = Join-Path $PSScriptRoot "launcher\build.ps1"
if (Test-Path $launcherBuild) {
    Write-Host "[LAUNCHER]"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcherBuild -Config $Config
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[LAUNCHER] build returned $LASTEXITCODE"
        $buildsFailed++
        $failedNames += "launcher"
    } else {
        $buildsSucceeded++
    }
}

$cerfTarget = if ($Rebuild) { "/t:Rebuild" } else { "/t:Build" }
if ($Rebuild) { Write-Host "[BUILD] Clean rebuild requested (/t:Rebuild)" }
& $msbuild cerf.sln /p:Configuration=$Config /p:Platform=Win32 $cerfTarget /m /v:minimal /p:CerfExtraDefines=$cerfDefines /p:CerfMode=$Mode
$msbuildExit = $LASTEXITCODE
$exePath = "build\$Config\Win32\cerf.exe"

if ($msbuildExit -ne 0) {
    Write-Host "[BUILD] cerf.exe FAILED (msbuild exit=$msbuildExit)"
    $buildsFailed++
    $failedNames += "cerf.exe"
} elseif (-not (Test-Path $exePath)) {
    Write-Host "[BUILD] cerf.exe FAILED (msbuild reported success but binary not found at $exePath)"
    $buildsFailed++
    $failedNames += "cerf.exe"
} else {
    $exe = Get-Item $exePath
    Write-Host "[BUILD] cerf.exe OK: $($exe.FullName)"
    Write-Host "[BUILD] Size: $($exe.Length) bytes"
    Write-Host "[BUILD] Time: $($exe.LastWriteTime)"
    $buildsSucceeded++
}

$env:CE_APPS_CONFIG = $Config
$env:CE_APPS_MODE   = $Mode
foreach ($appDir in (Get-ChildItem -Path "$PSScriptRoot/ce_apps" -Directory -ErrorAction SilentlyContinue)) {
    $appBuild = Join-Path $appDir.FullName "build.ps1"
    if (Test-Path $appBuild) {
        Write-Host "[CE] $($appDir.Name)"
        & powershell -NoProfile -ExecutionPolicy Bypass -File $appBuild
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[CE] ce_apps/$($appDir.Name) build returned $LASTEXITCODE"
            $buildsFailed++
            $failedNames += "ce_apps/$($appDir.Name)"
        } else {
            $buildsSucceeded++
        }
    }
}
Write-Host "============================================================"
if ($buildsFailed -gt 0) {
    Write-Host "[BUILD] Failed: $($failedNames -join ', ')"
}
Write-Host "[BUILD] Summary: $buildsSucceeded succeeded, $buildsFailed failed"

# Guarantee a clean zero exit code -- `exit 0` has been known to be
# swallowed by `powershell.exe -File` in some invocation chains; the
# Environment.Exit call goes straight to the Win32 terminator.
if ($buildsFailed -gt 0) {
    [Environment]::Exit(1)
}
[Environment]::Exit(0)
