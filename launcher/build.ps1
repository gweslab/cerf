param(
    [string]$Config = "Release"
)

Set-Location $PSScriptRoot

# CPython 3.7.9 (x86) + PyInstaller 5.13.2 is the newest pair whose binaries load
# on Windows Vista, the launcher's OS floor (measured against YY-Thunks' per-OS
# export tables, see cerf/cerf.vcxproj):
#   - CPython 3.8+ (python3x.dll) imports kernel32!GetActiveProcessorCount, which
#     Windows 7 introduced -- so 3.7.9 is the newest CPython that loads on Vista.
#   - PyInstaller 6.x's bootloader imports kernel32!K32EnumProcessModules and
#     K32GetModuleFileNameExW (Windows 7); 5.13.2's bootloader is Vista-clean.
# python.org ships no portable 3.7 carrying tkinter (neither the embeddable zip
# nor the nuget package has it), so the installer is run in its quiet per-user
# mode into the gitignored cache: files only, nothing on PATH.
$PY37_VERSION = "3.7.9"
$PY37_SHA256  = "769bb7c74ad1df6d7d74071cc16a984ff6182e4016e11b8949b93db487977220"
$PY37_URL     = "https://www.python.org/ftp/python/$PY37_VERSION/python-$PY37_VERSION.exe"
$PYINSTALLER  = "5.13.2"

function Get-LauncherPython {
    $repoRoot  = Split-Path $PSScriptRoot -Parent
    $cacheRoot = Join-Path $repoRoot "references\python"
    $target    = Join-Path $cacheRoot "cpython-$PY37_VERSION-x86"
    $py        = Join-Path $target "python.exe"
    if (Test-Path $py) { return $py }

    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
    $installer = Join-Path $cacheRoot "python-$PY37_VERSION-x86.exe"
    $haveGood = (Test-Path $installer) -and
                ((Get-FileHash -Algorithm SHA256 -Path $installer).Hash.ToLower() -eq $PY37_SHA256)
    if (-not $haveGood) {
        Write-Host "[LAUNCHER] Downloading CPython $PY37_VERSION (x86, Vista-compatible) ..."
        $pp = $ProgressPreference; $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri $PY37_URL -OutFile $installer
        $ProgressPreference = $pp
        $got = (Get-FileHash -Algorithm SHA256 -Path $installer).Hash.ToLower()
        if ($got -ne $PY37_SHA256) {
            Write-Host "[LAUNCHER] FAILED! Python archive SHA256 mismatch (got $got, want $PY37_SHA256)."
            return $null
        }
    }
    Write-Host "[LAUNCHER] Extracting CPython $PY37_VERSION into references/python (per-user, not on PATH) ..."
    & $installer /quiet TargetDir=$target InstallAllUsers=0 PrependPath=0 `
        AssociateFiles=0 Shortcuts=0 Include_launcher=0 InstallLauncherAllUsers=0 `
        Include_test=0 Include_doc=0 | Out-Null
    if (-not (Test-Path $py)) {
        Write-Host "[LAUNCHER] FAILED! python.exe not present at $py after extract."
        return $null
    }
    return $py
}

function Get-UcrtRedistDir {
    $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Redist"
    if (-not (Test-Path $kits)) { return $null }
    $dirs = Get-ChildItem $kits -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending
    foreach ($d in $dirs) {
        $ucrt = Join-Path $d.FullName "ucrt\DLLs\x86"
        if (Test-Path $ucrt) { return $ucrt }
    }
    return $null
}

$python = Get-LauncherPython
if (-not $python) { [Environment]::Exit(1) }
$name = "launcher"

# Windows carries the Universal CRT in-box only from Windows 10; on Vista it is
# an update (KB2999226). Microsoft supports app-local UCRT deployment, so the
# build ships the redistributable inside the exe and needs no update.
$ucrt = Get-UcrtRedistDir
if (-not $ucrt) {
    Write-Host "[LAUNCHER] FAILED! UCRT redist (Windows Kits\10\Redist\<ver>\ucrt\DLLs\x86) not found; launcher.exe would not run on a Vista box without KB2999226."
    [Environment]::Exit(1)
}
$env:CERF_LAUNCHER_UCRT = $ucrt
$env:CERF_LAUNCHER_NAME = $name

$null = & $python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[LAUNCHER] PyInstaller not found in cached Python; installing pyinstaller==$PYINSTALLER..."
    & $python -m pip install --quiet --disable-pip-version-check "pyinstaller==$PYINSTALLER"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[LAUNCHER] FAILED! pip install pyinstaller==$PYINSTALLER returned $LASTEXITCODE"
        [Environment]::Exit(1)
    }
}

$build = Join-Path $PSScriptRoot "build"
$dist  = Join-Path $PSScriptRoot "dist"
if (Test-Path $build) { Remove-Item $build -Recurse -Force }
if (Test-Path $dist)  { Remove-Item $dist  -Recurse -Force }

Write-Host "[LAUNCHER] Building $name.exe ($Config)..."
& $python -m PyInstaller --noconfirm --clean --distpath $dist --workpath $build launcher.spec
if ($LASTEXITCODE -ne 0) {
    Write-Host "[LAUNCHER] FAILED! PyInstaller returned $LASTEXITCODE"
    [Environment]::Exit(1)
}

$built = Join-Path $dist "$name.exe"
if (-not (Test-Path $built)) {
    Write-Host "[LAUNCHER] FAILED! Expected $built not produced."
    [Environment]::Exit(1)
}

$bundledDir = Join-Path $PSScriptRoot "..\bundled"
if (-not (Test-Path $bundledDir)) { New-Item -ItemType Directory -Path $bundledDir -Force | Out-Null }
$bundledExe = Join-Path $bundledDir "$name.exe"
Copy-Item $built $bundledExe -Force

$exe = Get-Item $bundledExe
Write-Host "[LAUNCHER] OK: $($exe.FullName)"
Write-Host "[LAUNCHER] Size: $($exe.Length) bytes"
[Environment]::Exit(0)
