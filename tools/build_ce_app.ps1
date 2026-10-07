# Shared builder for CERF's CE apps and DLLs.
#
# Toolchain and SDK come from third_party/wince (eMbedded Visual C++ 4.0);
# see docs/ce_apps_setup.md for the layout contract and how to produce it.
# Outputs are staged per-arch under build/<cfg>/Win32/ce_apps/<arch>/.
param(
    [Parameter(Mandatory)][ValidateSet("exe","dll")][string]$Type,
    [Parameter(Mandatory)][string]$Target,
    [string[]]$Sources = @("main.c"),
    [string]$Entry,
    [string[]]$Libs = @("coredll"),
    [string[]]$LinkExtras = @(),
    [string[]]$ExtraIncludes = @(),
    [string[]]$ExtraLibPaths = @(),
    [string[]]$ForcedInclude = @(),
    [string]$DefFile,
    [string]$ObjDir = ".",
    [ValidateSet("arm","arm_thumb","mips","sh3")][string]$Arch = "arm",
    # MIPS ISA level (only with -Arch mips): mips4 = MIPS-IV soft-float (machine
    # MIPSFPU), mips2 = MIPS-II, mips1 = MIPS-I / R3000 (mips1 and mips2 both use
    # machine MIPS); must match the SDK coredll machine.
    [ValidateSet("mips4","mips2","mips1")][string]$MipsIsa = "mips4",
    # PE subsystem stamp. Default 3.00; lower it (e.g. "2.11") to let the
    # binary load on older H/PC Pro kernels - a lower stamp still loads on
    # CE3+, a higher one locks the binary out of older kernels.
    [string]$SubsystemVersion = "3.00",
    # _WIN32_WCE. The SDK is the same for every CE target; this and
    # $SubsystemVersion are what select the CE version a binary targets.
    [string]$WceVersion = "300",
    # Optional resource script (.rc) compiled to .res and linked in - e.g. to
    # give the EXE a shell/title-bar icon. Use classic BMP icon frames; CE's
    # shell does not render PNG-compressed (Vista) .ico entries.
    [string]$Rc = "",
    # When set, build a by-name coredll import lib from this .def and search it
    # before the SDK's ordinal coredll.lib, so coredll imports bind by name (the
    # stable cross-version contract) rather than by per-version ordinal.
    [string]$CoreDllDef = "",
    [string[]]$CoreDllDefLocal = @(),
    # Override the arch-default CRT import libs.
    [string[]]$CrtLibs = @(),
    # Stage under ce_apps/<OutSubdir> instead of the arch default (<MipsIsa> for
    # mips, <Arch> otherwise).
    [string]$OutSubdir = ""
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path "$PSScriptRoot/..").Path
$SDK  = Join-Path $RepoRoot "third_party/wince"
$BIN  = Join-Path $SDK "bin"
$LINK = Join-Path $BIN "link.exe"
# NB: not $RC - PowerShell variable names are case-insensitive, so $RC would
# alias the $Rc parameter (the .rc path) and clobber it.
$RESC = Join-Path $BIN "rc.exe"

if (-not (Test-Path $BIN)) {
    throw @"
CE toolchain not found at $SDK

Building ce_apps/ needs eMbedded Visual C++ 4.0. See docs/ce_apps_setup.md.
Verify with: powershell -File setup.ps1 -Check
"@
}

switch ($Arch) {
    "mips" {
        $CL = Join-Path $BIN "clmips.exe"
        if ($MipsIsa -eq "mips1") {
            # MIPS-I / R3000 (Toshiba TX39 core in Philips PR31500/PR31700). -QMmips1
            # restricts codegen to the MIPS-I ISA the R3000 accepts. Soft-float
            # (-QMFPE): the TX39 has no FPU.
            $Machine = "MIPS"
            $ArchFlags = @("-QMmips1", "-QMFPE", "-D_M_MRX000=3000", "-D_MIPS_", "-DR3000")
            $SdkSub = "Mipsii"
        } elseif ($MipsIsa -eq "mips2") {
            $Machine = "MIPS"
            $ArchFlags = @("-QMmips2", "-QMFPE", "-D_M_MRX000=4000", "-D_MIPS_", "-DR4000")
            $SdkSub = "Mipsii"
        } else {
            $Machine = "MIPSFPU"
            $ArchFlags = @("-QMmips4", "-QMn32", "-QMFPE", "-D_MIPS64", "-D_MIPS_", "-DR4000")
            $SdkSub = "Mipsiv"
        }
        # Bare MIPS platform macro: CE SDK headers gate arch blocks (e.g.
        # stdlib.h _JBLEN) on defined(MIPS).
        $CpuMacros = @("-DMIPS")
        # MIPS codegen emits shared prologue/epilogue register-save helpers
        # (__prologue_helper_s0_sN) from the C runtime, not auto-linked under
        # /nodefaultlib.
        $ImplicitLibs = @("corelibc")
    }
    "sh3" {
        $CL = Join-Path $BIN "clsh.exe"
        $Machine = "SH3"
        $ArchFlags = @("-Qsh3", "-DSH3", "-D_SH3_")
        $CpuMacros = @("-DSHx")
        $SdkSub = "Sh3"
        $ImplicitLibs = @()
    }
    "arm_thumb" {
        $CL = Join-Path $BIN "clarm.exe"
        $Machine = "THUMB"
        $ArchFlags = @("-QRarch4T", "-QRinterwork-return", "-DARMV4I")
        $CpuMacros = @("-DARM", "-D_ARM_")
        $SdkSub = "Armv4i"
        $ImplicitLibs = @()
    }
    default {
        $CL = Join-Path $BIN "clarm.exe"
        $Machine = "ARM"
        $ArchFlags = @("-QRarch4", "-DARMV4")
        $CpuMacros = @("-DARM", "-D_ARM_")
        $SdkSub = "Armv4"
        $ImplicitLibs = @()
    }
}

if ($CrtLibs.Count) { $ImplicitLibs = $CrtLibs }

$SdkInc = Join-Path $SDK "STANDARDSDK/Include/$SdkSub"
$LIB    = Join-Path $SDK "STANDARDSDK/Lib/$SdkSub"
foreach ($p in @($CL, $LINK, $SdkInc, $LIB)) {
    if (-not (Test-Path $p)) { throw "CE toolchain incomplete: $p is missing (see docs/ce_apps_setup.md)" }
}

$IncDirs = @()
foreach ($i in $ExtraIncludes) { $IncDirs += (Resolve-Path $i).Path }
$IncDirs += $SdkInc
$IncDirs += $RepoRoot

$Subsystem = "windowsce,$SubsystemVersion"
$WceDef    = "_WIN32_WCE=$WceVersion"

$env:PATH = "$BIN;" + $env:PATH

$Config = if ($env:CE_APPS_CONFIG) { $env:CE_APPS_CONFIG } else { "Release" }
$Mode   = if ($env:CE_APPS_MODE)   { $env:CE_APPS_MODE }   else { "dev" }
$devModeFlag = if ($Mode -eq "production") { "0" } else { "1" }
$ArchSub = if ($OutSubdir) { $OutSubdir } elseif ($Arch -eq "mips") { $MipsIsa } else { $Arch }
$OutDir = Join-Path $RepoRoot "build/$Config/Win32/ce_apps/$ArchSub"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$StagedTarget = Join-Path $OutDir $Target

if (-not $Entry) {
    $Entry = if ($Type -eq "exe") { "WinMain" } else { "DllEntryPoint" }
}

New-Item -ItemType Directory -Force -Path $ObjDir | Out-Null

if ($CoreDllDef) {
    $LIBTOOL = Join-Path $BIN "lib.exe"
    if (-not (Test-Path $LIBTOOL)) { throw "WCE lib tool missing: $LIBTOOL" }
    $coreLib = Join-Path $ObjDir "coredll.lib"
    $defPath = (Resolve-Path $CoreDllDef).Path
    if ($CoreDllDefLocal.Count -gt 0) {
        $trimmed = Join-Path $ObjDir "coredll_local_filtered.def"
        Get-Content $defPath | Where-Object { $_.Trim() -notin $CoreDllDefLocal } |
            Set-Content $trimmed -Encoding utf8
        $defPath = (Resolve-Path $trimmed).Path
    }
    & $LIBTOOL /nologo /machine:$Machine "/def:$defPath" "/out:$coreLib"
    if ($LASTEXITCODE -ne 0) { throw "by-name coredll import lib build failed: $CoreDllDef" }
}

$modeMarker = Join-Path $ObjDir ".build_mode"
$coreDllKey = if ($CoreDllDef) { (Get-FileHash -Path $defPath -Algorithm SHA256).Hash } else { "" }
$buildKey   = "$Mode-$Arch-$MipsIsa-$WceVersion-$SdkSub-$coreDllKey"
$cachedMode = if (Test-Path $modeMarker) { (Get-Content $modeMarker -Raw).Trim() } else { "" }
if ($cachedMode -ne $buildKey) {
    Get-ChildItem -Path (Join-Path $ObjDir "*") -Include "*.obj", "*.res" -File -ErrorAction SilentlyContinue |
        Remove-Item -Force
    Set-Content -Path $modeMarker -Value $buildKey -Encoding ASCII -NoNewline
}

# Compile: .obj files land in $ObjDir (default: the per-app dir, co-located
# with sources) so each variant keeps its own incremental cache.
# An incremental .cpp-mtime check does not see header edits, so a source whose
# object predates the newest header in its directory is recompiled too - a shared
# struct change otherwise ships as mismatched object layouts.
$srcDirs = @($Sources | ForEach-Object { Split-Path (Resolve-Path $_).Path -Parent } | Sort-Object -Unique)
$newestHdr = $null
foreach ($d in $srcDirs) {
    $h = Get-ChildItem -Path $d -Filter *.h -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($h -and (($null -eq $newestHdr) -or ($h.LastWriteTime -gt $newestHdr))) {
        $newestHdr = $h.LastWriteTime
    }
}

$objs = @()
foreach ($src in $Sources) {
    $obj = Join-Path $ObjDir ([System.IO.Path]::ChangeExtension((Split-Path $src -Leaf), ".obj"))
    $objs += $obj
    $needCompile = -not (Test-Path $obj)
    if (-not $needCompile) {
        $needCompile = ((Get-Item $src).LastWriteTime -gt (Get-Item $obj).LastWriteTime)
    }
    if (-not $needCompile -and $null -ne $newestHdr) {
        $needCompile = ($newestHdr -gt (Get-Item $obj).LastWriteTime)
    }
    if ($needCompile) {
        Write-Host "[CE] cl  $src"
        $incFlags = @()
        foreach ($i in $IncDirs) { $incFlags += @("/I", $i) }
        $fiFlag = @()
        foreach ($fi in $ForcedInclude) { $fiFlag += @("/FI", $fi) }
        & $CL /nologo /c /W3 /WX /O2 @ArchFlags @CpuMacros /DUNICODE /D_UNICODE /DUNDER_CE "/D$WceDef" "/DCERF_DEV_MODE=$devModeFlag" "/Fo$obj" @incFlags @fiFlag $src
        if ($LASTEXITCODE -ne 0) { throw "Compile failed: $src" }
    }
}

# Compile the optional resource script (.rc -> .res) for the EXE/DLL icon
# and other resources. rc.exe needs rcdll.dll, already on PATH via bin/.
$res = ""
if ($Rc) {
    if (-not (Test-Path $RESC)) { throw "WCE resource compiler missing: $RESC" }
    $rcPath = (Resolve-Path $Rc).Path
    $res = Join-Path $ObjDir ([System.IO.Path]::ChangeExtension((Split-Path $Rc -Leaf), ".res"))
    $needRc = -not (Test-Path $res)
    if (-not $needRc) {
        $needRc = ((Get-Item $rcPath).LastWriteTime -gt (Get-Item $res).LastWriteTime)
    }
    if ($needRc) {
        Write-Host "[CE] rc  $Rc"
        & $RESC /r /fo $res $rcPath
        if ($LASTEXITCODE -ne 0) { throw "Resource compile failed: $Rc" }
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
    if ($res -and (Get-Item $res).LastWriteTime -gt $stagedTime) { $needLink = $true }
}

if ($needLink) {
    Write-Host "[CE] link $Target -> $StagedTarget"
    $linkArgs = @("/nologo", "/subsystem:$Subsystem", "/entry:$Entry",
                  "/machine:$Machine", "/nodefaultlib", "/libpath:$LIB",
                  "/out:$StagedTarget")
    # Search the generated by-name coredll.lib before $LIB so coredll resolves by name.
    if ($CoreDllDef) { $linkArgs = @("/libpath:$ObjDir") + $linkArgs }
    foreach ($p in $ExtraLibPaths) { $linkArgs += "/libpath:$((Resolve-Path $p).Path)" }
    if ($Type -eq "dll") {
        $implib = [System.IO.Path]::ChangeExtension($Target, ".lib")
        $linkArgs += "/dll"
        $linkArgs += "/implib:$implib"
        $defFile = if ($DefFile) { $DefFile }
                   else { [System.IO.Path]::ChangeExtension($Target, ".def") }
        if (Test-Path $defFile) {
            $linkArgs += "/def:$defFile"
        }
    }
    foreach ($extra in $LinkExtras) { $linkArgs += $extra }
    $linkArgs += $objs
    if ($res) { $linkArgs += $res }
    foreach ($lib in $Libs) { $linkArgs += "$lib.lib" }
    foreach ($lib in $ImplicitLibs) { $linkArgs += "$lib.lib" }
    & $LINK @linkArgs
    if ($LASTEXITCODE -ne 0) { throw "Link failed: $Target" }
    Write-Host "[CE]      $((Get-Item $StagedTarget).Length) bytes"
} else {
    Write-Host "[CE] $Target up-to-date"
}
