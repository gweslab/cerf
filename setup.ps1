param([switch]$Check)

Set-Location $PSScriptRoot

$script:Results = @()
$script:Failed = $false

function Report($status, $key, $detail) {
    $script:Results += [pscustomobject]@{ Status = $status; Key = $key; Detail = $detail }
    if ($status -eq 'FAIL') { $script:Failed = $true }
}

function Test-GitRepo {
    $top = (git rev-parse --show-toplevel 2>$null)
    if (-not $top) {
        Report 'FAIL' 'git-repo' 'not a git repository'
        return $false
    }
    Report 'OK' 'git-repo' $top
    return $true
}

function Test-GitHooks {
    if (-not (Test-Path '.githooks/pre-commit')) {
        Report 'FAIL' 'git-hooks' '.githooks/pre-commit is missing from the working tree'
        return
    }
    $path = (git config --get core.hooksPath 2>$null)
    if ($path -eq '.githooks') {
        Report 'OK' 'git-hooks' 'core.hooksPath = .githooks'
    } elseif (-not $path) {
        Report 'FAIL' 'git-hooks' 'core.hooksPath is unset -- git hooks never run in this clone'
    } else {
        Report 'FAIL' 'git-hooks' "core.hooksPath = $path (expected .githooks)"
    }
}

function Test-StaleLocalHooks {
    $stale = Get-ChildItem '.git/hooks' -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -ne '.sample' }
    if ($stale) {
        $names = ($stale | ForEach-Object { $_.Name }) -join ', '
        Report 'WARN' 'stale-local-hooks' "$names in .git/hooks (shadowed by core.hooksPath, delete to avoid confusion)"
    } else {
        Report 'OK' 'stale-local-hooks' 'none'
    }
}

function Get-MissingSubmodules {
    if (-not (Test-Path '.gitmodules')) { return @() }
    $paths = git config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>$null |
             ForEach-Object { ($_ -split '\s+', 2)[1] }
    return @($paths | Where-Object {
        -not (Test-Path $_) -or -not (Get-ChildItem $_ -Force -ErrorAction SilentlyContinue)
    })
}

function Test-Submodules {
    if (-not (Test-Path '.gitmodules')) {
        Report 'OK' 'submodules' 'none declared'
        return
    }
    $missing = Get-MissingSubmodules
    if ($missing.Count -gt 0) {
        Report 'FAIL' 'submodules' ("not initialised: " + ($missing -join ', '))
    } else {
        Report 'OK' 'submodules' 'all initialised'
    }
}

function Test-Python {
    $ver = (py -3 --version 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Report 'FAIL' 'python' "py -3 not runnable -- every .claude hook is a no-op without it ($ver)"
    } else {
        Report 'OK' 'python' $ver
    }
}

function Test-ClaudeHooks {
    if (-not (Test-Path '.claude/settings.json')) {
        Report 'FAIL' 'claude-hooks' '.claude/settings.json is missing'
        return
    }
    try {
        $raw = Get-Content '.claude/settings.json' -Raw
        $null = $raw | ConvertFrom-Json
    } catch {
        Report 'FAIL' 'claude-hooks' ".claude/settings.json does not parse: $($_.Exception.Message)"
        return
    }
    $referenced = [regex]::Matches($raw, '\.claude/hooks/([A-Za-z0-9_]+\.py)') |
                  ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    if (-not $referenced) {
        Report 'FAIL' 'claude-hooks' 'settings.json references no hook scripts'
        return
    }
    $missing = $referenced | Where-Object { -not (Test-Path (Join-Path '.claude/hooks' $_)) }
    if ($missing) {
        Report 'FAIL' 'claude-hooks' ("scripts referenced but absent: " + ($missing -join ', '))
        return
    }
    $broken = @()
    foreach ($h in $referenced) {
        $null = (py -3 -m py_compile (Join-Path '.claude/hooks' $h) 2>&1)
        if ($LASTEXITCODE -ne 0) { $broken += $h }
    }
    if ($broken) {
        Report 'FAIL' 'claude-hooks' ("scripts fail to compile under py -3: " + ($broken -join ', '))
    } else {
        Report 'OK' 'claude-hooks' "$($referenced.Count) hooks present and compiling"
    }
}

function Test-Vcpkg {
    if (Test-Path "$env:LOCALAPPDATA\vcpkg\vcpkg.user.props") {
        Report 'OK' 'vcpkg' 'MSBuild integration present'
    } else {
        Report 'FAIL' 'vcpkg' "run 'vcpkg integrate install' from '<VS install>\VC\vcpkg\vcpkg.exe' -- build.ps1 refuses to build without it"
    }
}

# docs/ce_apps_setup.md
function Test-CeToolchain {
    $root = 'third_party/wince'
    if (-not (Test-Path $root)) {
        Report 'WARN' 'ce-toolchain' "absent -- optional; needed only to build ce_apps/ (see docs/ce_apps_setup.md)"
        return
    }
    $tools = @('clarm.exe', 'clthumb.exe', 'clmips.exe', 'clsh.exe', 'link.exe', 'lib.exe', 'rc.exe')
    $arches = @('Armv4', 'Armv4i', 'Mipsii', 'Mipsiv', 'Sh3')
    $missing = @($tools | Where-Object { -not (Test-Path (Join-Path "$root/bin" $_)) })
    foreach ($a in $arches) {
        if (-not (Test-Path (Join-Path $root "STANDARDSDK/Include/$a")))       { $missing += "Include/$a" }
        if (-not (Test-Path (Join-Path $root "STANDARDSDK/Lib/$a/coredll.lib"))) { $missing += "Lib/$a/coredll.lib" }
    }
    if ($missing.Count) {
        Report 'FAIL' 'ce-toolchain' ("incomplete -- missing: " + ($missing -join ', ') + " (re-run tools/unpack_evc4.ps1 -Force)")
    } else {
        Report 'OK' 'ce-toolchain' ($arches -join ', ')
    }
}

function Invoke-Checks {
    if (-not (Test-GitRepo)) { return }
    Test-GitHooks
    Test-StaleLocalHooks
    Test-Submodules
    Test-Python
    Test-ClaudeHooks
    Test-Vcpkg
    Test-CeToolchain
}

if ($Check) {
    Invoke-Checks
    foreach ($r in $script:Results) { "$($r.Status)`t$($r.Key)`t$($r.Detail)" }
    if ($script:Failed) { exit 1 }
    exit 0
}

Write-Host ""
Write-Host "CERF setup" -ForegroundColor Cyan
Write-Host ""

if (-not (git rev-parse --show-toplevel 2>$null)) {
    Write-Host "  FAIL  not a git repository -- run setup.cmd from a cloned CERF tree" -ForegroundColor Red
    exit 1
}

git config core.hooksPath .githooks
Write-Host "  set   core.hooksPath = .githooks" -ForegroundColor Green

$missingSubmodules = Get-MissingSubmodules
foreach ($m in $missingSubmodules) {
    Write-Host "  init  submodule $m" -ForegroundColor Green
    git submodule update --init --recursive -- $m
}
if ($missingSubmodules.Count -eq 0) {
    Write-Host "  skip  submodules already initialised (left untouched)" -ForegroundColor DarkGray
}

Write-Host ""

Invoke-Checks

foreach ($r in $script:Results) {
    $color = switch ($r.Status) { 'OK' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
    Write-Host ("  {0,-5} {1,-20} {2}" -f $r.Status, $r.Key, $r.Detail) -ForegroundColor $color
}

Write-Host ""
if ($script:Failed) {
    Write-Host "Setup incomplete -- resolve the FAIL lines above, then re-run setup.cmd." -ForegroundColor Red
    exit 1
}
Write-Host "Ready. Build with build.cmd, launch the Claude dev environment with run_claude.cmd." -ForegroundColor Cyan
exit 0
