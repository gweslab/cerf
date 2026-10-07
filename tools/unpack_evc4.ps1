# Assembles the CE toolchain + SDK that ce_apps/ builds against, from an
# unpacked eMbedded Visual C++ 4.0 CD. See docs/ce_apps_setup.md.
#
#   INPUT   third_party/evc4/     unpacked eVC4 CD (contributor-supplied)
#   OUTPUT  third_party/wince/    bin/ + STANDARDSDK/{Include,Lib}
param(
    [string]$Evc4Root = "",
    [string]$OutRoot  = "",
    [switch]$Force
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path "$PSScriptRoot/..").Path
if (-not $Evc4Root) { $Evc4Root = Join-Path $RepoRoot "third_party/evc4"  }
if (-not $OutRoot)  { $OutRoot  = Join-Path $RepoRoot "third_party/wince" }

$MsiRel     = "SDK/STANDARD_SDK.msi"
$ToolBinRel = "WCE/wce400/BIN"
$EvcBinRel  = "COMMON/EVC/BIN"

$EvcBinFiles = @("rc.exe", "rcdll.dll")

$RequiredTools = @(
    "clarm.exe", "clthumb.exe", "clmips.exe", "clsh.exe",
    "link.exe", "lib.exe", "rc.exe", "rcdll.dll", "cvtres.exe",
    "armasm.exe", "mipsasm.exe", "mspdb60.dll",
    "c1_arm.dll", "c1xx_arm.dll", "c2_arm.dll",
    "c1_mp.dll",  "c1xx_mp.dll",  "c2_mp.dll",
    "c1_sh.dll",  "c1xx_sh.dll",  "c2_sh.dll"
)
$RequiredArches = @("Armv4", "Armv4i", "Mipsii", "Mipsiv", "Sh3")

function Fail($msg) { Write-Host "[evc4] ERROR: $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host "[evc4] $msg" }

if (-not (Test-Path $Evc4Root)) {
    Fail @"
eVC4 media not found at:
    $Evc4Root

Download eMbedded Visual C++ 4.0 (English) and unpack the installer there.
Obtain it from HPC:Factor -- https://www.hpcfactor.com/developer/
Then re-run this script. See docs/ce_apps_setup.md.
"@
}

foreach ($rel in @($MsiRel, $ToolBinRel, $EvcBinRel)) {
    if (-not (Test-Path (Join-Path $Evc4Root $rel))) {
        Fail @"
$Evc4Root does not look like an unpacked eVC4 CD -- missing:
    $rel

Expected layout (a few landmarks):
    third_party/evc4/SDK/STANDARD_SDK.msi
    third_party/evc4/WCE/wce400/BIN/clarm.exe
    third_party/evc4/COMMON/EVC/BIN/rc.exe

Unpack the CD/ISO itself, not a subfolder of it. See docs/ce_apps_setup.md.
"@
    }
}

if ((Test-Path $OutRoot) -and -not $Force) {
    Fail "$OutRoot already exists. Re-run with -Force to rebuild it."
}
if (Test-Path $OutRoot) {
    Info "removing existing $OutRoot"
    Remove-Item -Recurse -Force $OutRoot
}
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

$msi = (Resolve-Path (Join-Path $Evc4Root $MsiRel)).Path
Info "expanding $MsiRel (msiexec /a, no installation)"
$p = Start-Process msiexec.exe `
        -ArgumentList "/a", "`"$msi`"", "/qn", "TARGETDIR=`"$OutRoot`"" `
        -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "msiexec /a failed with exit code $($p.ExitCode)" }

$sdkRoot = Join-Path $OutRoot "STANDARDSDK"
if (-not (Test-Path $sdkRoot)) { Fail "msiexec succeeded but $sdkRoot is absent" }

Get-ChildItem $OutRoot -Filter *.msi -File -ErrorAction SilentlyContinue |
    Remove-Item -Force

$binOut = Join-Path $OutRoot "bin"
New-Item -ItemType Directory -Force -Path $binOut | Out-Null

Info "copying toolchain from $ToolBinRel"
Copy-Item -Path (Join-Path $Evc4Root "$ToolBinRel/*") -Destination $binOut -Recurse -Force

Info "copying resource compiler from $EvcBinRel"
foreach ($f in $EvcBinFiles) {
    $src = Join-Path $Evc4Root "$EvcBinRel/$f"
    if (-not (Test-Path $src)) { Fail "missing $EvcBinRel/$f in the eVC4 media" }
    Copy-Item -Path $src -Destination $binOut -Force
}

$missing = @()
foreach ($t in $RequiredTools) {
    if (-not (Test-Path (Join-Path $binOut $t))) { $missing += "bin/$t" }
}
foreach ($a in $RequiredArches) {
    foreach ($sub in @("Include", "Lib")) {
        if (-not (Test-Path (Join-Path $sdkRoot "$sub/$a"))) {
            $missing += "STANDARDSDK/$sub/$a"
        }
    }
    if (-not (Test-Path (Join-Path $sdkRoot "Lib/$a/coredll.lib"))) {
        $missing += "STANDARDSDK/Lib/$a/coredll.lib"
    }
}
if ($missing.Count) {
    Fail ("assembled tree is incomplete -- missing:`n    " + ($missing -join "`n    "))
}

Write-Host ""
Info "OK -- toolchain + SDK assembled at:"
Info "    $OutRoot"
Info "  targets: $($RequiredArches -join ', ')"
Write-Host ""
Info "Verify at any time with:  powershell -File setup.ps1 -Check"
