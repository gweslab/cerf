# Shared builder for CERF's CE 3.0 ARM apps and DLLs. Raising the
# subsystem stamp from 3.00 locks the resulting binaries out of CE3 kernels.
param(
    [Parameter(Mandatory)][ValidateSet("exe","dll")][string]$Type,
    [Parameter(Mandatory)][string]$Target,
    [string[]]$Sources = @("main.c"),
    [string]$Entry,
    [string[]]$Libs = @("coredll"),
    [string[]]$LinkExtras = @(),
    [string[]]$ExtraIncludes = @(),
    [string[]]$ExtraLibPaths = @(),
    [string]$ForcedInclude
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path "$PSScriptRoot/..").Path
$SDK  = Join-Path $RepoRoot "references/WindowsCE-Build-Tools"
$CL   = Join-Path $SDK "bin/I386/ARM/cl.exe"
$LINK = Join-Path $SDK "bin/I386/link.exe"

$IncDirs = @()
foreach ($i in $ExtraIncludes) { $IncDirs += (Resolve-Path $i).Path }
$IncDirs += @(
    (Join-Path $SDK "ce3-hpc2k/include"),
    (Join-Path $SDK "ce3-oak/INC"),
    $RepoRoot
)
$LIB       = Join-Path $SDK "ce42-standard/Lib/Armv4i"
$Subsystem = "windowsce,3.00"
$WceDef    = "_WIN32_WCE=300"

if (-not (Test-Path $CL))   { throw "WCE toolchain missing: $CL"   }
if (-not (Test-Path $LINK)) { throw "WCE toolchain missing: $LINK" }

# cl.exe and link.exe both depend on companion DLLs (c1.dll / c1xx.dll / c2.dll
# next to cl, mspdb*.dll under bin/I386). Wire PATH up before either is invoked.
$env:PATH = "$SDK\bin\I386\ARM;$SDK\bin\I386;" + $env:PATH

$Config = if ($env:CE_APPS_CONFIG) { $env:CE_APPS_CONFIG } else { "Release" }
$Mode   = if ($env:CE_APPS_MODE)   { $env:CE_APPS_MODE }   else { "dev" }
$devModeFlag = if ($Mode -eq "production") { "0" } else { "1" }
$OutDir = Join-Path $RepoRoot "build/$Config/Win32/ce_apps"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$StagedTarget = Join-Path $OutDir $Target

if (-not $Entry) {
    $Entry = if ($Type -eq "exe") { "WinMain" } else { "DllEntryPoint" }
}

# Mode-change marker — bust .obj cache if CERF_DEV_MODE flipped between runs.
$modeMarker = ".build_mode"
$cachedMode = if (Test-Path $modeMarker) { (Get-Content $modeMarker -Raw).Trim() } else { "" }
if ($cachedMode -ne $Mode) {
    Get-ChildItem -Filter "*.obj" -ErrorAction SilentlyContinue | Remove-Item -Force
    Set-Content -Path $modeMarker -Value $Mode -Encoding ASCII -NoNewline
}

# Compile: each .obj is co-located with its source in the per-app dir, so
# the per-app dir caches state between runs.
$objs = @()
foreach ($src in $Sources) {
    $obj = [System.IO.Path]::ChangeExtension((Split-Path $src -Leaf), ".obj")
    $objs += $obj
    $needCompile = -not (Test-Path $obj)
    if (-not $needCompile) {
        $needCompile = ((Get-Item $src).LastWriteTime -gt (Get-Item $obj).LastWriteTime)
    }
    if ($needCompile) {
        Write-Host "[CE] cl  $src"
        $incFlags = @()
        foreach ($i in $IncDirs) { $incFlags += @("/I", $i) }
        $fiFlag = @()
        if ($ForcedInclude) { $fiFlag = @("/FI", $ForcedInclude) }
        & $CL /nologo /c /W3 /WX /O2 /QRarch4T /QRinterwork-return /DUNICODE /D_UNICODE /DUNDER_CE /DARM /D_ARM_ /DARMV4I "/D$WceDef" "/DCERF_DEV_MODE=$devModeFlag" @incFlags @fiFlag $src
        if ($LASTEXITCODE -ne 0) { throw "Compile failed: $src" }
    }
}

# Link: staged target lives under build/<Config>/Win32/ce_apps/.
$needLink = -not (Test-Path $StagedTarget)
if (-not $needLink) {
    $stagedTime = (Get-Item $StagedTarget).LastWriteTime
    foreach ($obj in $objs) {
        if ((Get-Item $obj).LastWriteTime -gt $stagedTime) {
            $needLink = $true; break
        }
    }
}

if ($needLink) {
    Write-Host "[CE] link $Target -> $StagedTarget"
    $linkArgs = @("/nologo", "/subsystem:$Subsystem", "/entry:$Entry",
                  "/machine:THUMB", "/nodefaultlib", "/libpath:$LIB",
                  "/out:$StagedTarget")
    foreach ($p in $ExtraLibPaths) { $linkArgs += "/libpath:$((Resolve-Path $p).Path)" }
    if ($Type -eq "dll") {
        $implib = [System.IO.Path]::ChangeExtension($Target, ".lib")
        $linkArgs += "/dll"
        $linkArgs += "/implib:$implib"
        $defFile = [System.IO.Path]::ChangeExtension($Target, ".def")
        if (Test-Path $defFile) {
            $linkArgs += "/def:$defFile"
        }
    }
    foreach ($extra in $LinkExtras) { $linkArgs += $extra }
    $linkArgs += $objs
    foreach ($lib in $Libs) { $linkArgs += "$lib.lib" }
    & $LINK @linkArgs
    if ($LASTEXITCODE -ne 0) { throw "Link failed: $Target" }
    Write-Host "[CE]      $((Get-Item $StagedTarget).Length) bytes"
} else {
    Write-Host "[CE] $Target up-to-date"
}
