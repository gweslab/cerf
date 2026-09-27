Set-Location $PSScriptRoot
. (Join-Path $PSScriptRoot "tools\cerf_locks.ps1")

$RunnerExitUsage   = 2
$RunnerExitMissing = 3
$RunnerExitTimeout = 124
$RunnerExitUnknown = 125

$buildLock = New-CerfLock -Path (Join-Path $PSScriptRoot ".build_lock") -StaleSeconds 300 -Label "RUNNER"
$runLocks  = @(New-CerfRunLocks -Root $PSScriptRoot -Label "RUNNER")

function Show-RunnerUsage {
    Write-Host "claude_cerf_runner.ps1 - run cerf.exe under a time limit and a CERF run slot"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File claude_cerf_runner.ps1 --timeout=SECONDS --log-file=PATH --device=NAME [cerf.exe args...]"
    Write-Host ""
    Write-Host "Mandatory:"
    Write-Host "  --timeout=SECONDS   Forwarded to cerf.exe. cerf.exe stops the run and exits with code $RunnerExitTimeout."
    Write-Host "                      If cerf.exe is still alive 10 s later, the runner stops it."
    Write-Host "                      This replaces GNU timeout. Do not wrap this script in timeout."
    Write-Host "                      An external kill leaves its .cerf_lock.N slot behind."
    Write-Host "  --log-file=PATH     Forwarded to cerf.exe. It keeps the stock cerf.log intact."
    Write-Host "                      msys and mixed-slash paths (/z/tmp/x.log, Z:/tmp/x.log) become Z:\tmp\x.log."
    Write-Host "  --device=NAME       Forwarded to cerf.exe. Without it, cerf boots stock cerfos."
    Write-Host ""
    Write-Host "The runner forwards every other argument to cerf.exe unchanged, and it adds --no-focus:"
    Write-Host "cerf.exe windows never take the foreground from another application."
    Write-Host "It waits for .build_lock, and it holds one run slot (.cerf_lock.1 to .cerf_lock.$($runLocks.Count)) while cerf.exe runs."
    Write-Host "At most $($runLocks.Count) runs occur at the same time. When every slot is held, the next run waits for a free slot."
    Write-Host ""
    Write-Host "Exit codes: the exit code of cerf.exe, $RunnerExitTimeout on timeout, $RunnerExitUsage on a bad argument,"
    Write-Host "            $RunnerExitMissing when cerf.exe is absent, $RunnerExitUnknown when the exit code is not available."
}

function ConvertTo-WindowsPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $p = $Path.Trim().Trim('"').Trim("'")
    if ($p -match '^/cygdrive/([A-Za-z])/(.*)$' -or $p -match '^/([A-Za-z])/(.*)$') {
        $p = $matches[1].ToUpper() + ':/' + $matches[2]
    }
    $p = $p -replace '/', '\'
    if (-not [IO.Path]::IsPathRooted($p)) { $p = Join-Path $PSScriptRoot $p }
    [IO.Path]::GetFullPath($p)
}

function ConvertTo-RunnerArgToken {
    param([Parameter(Mandatory = $true)][string]$Arg)
    if ($Arg -notmatch '[\s"]') { return $Arg }
    $out = '"'
    $bs  = 0
    foreach ($ch in $Arg.ToCharArray()) {
        if ($ch -eq '\') { $bs++; continue }
        if ($ch -eq '"') { $out += ('\' * ($bs * 2 + 1)) + '"'; $bs = 0; continue }
        $out += ('\' * $bs) + $ch
        $bs = 0
    }
    $out += ('\' * ($bs * 2)) + '"'
    return $out
}

function Format-RunnerSize {
    param([Parameter(Mandatory = $true)][long]$Bytes)
    if ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N1} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Show-RunnerFileFact {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Path,
        [datetime]$StaleBefore = [datetime]::MinValue,
        [switch]$AgeFromNow
    )
    if (-not (Test-Path $Path)) {
        Write-Host ("[RUNNER] {0,-14}: absent" -f $Label)
        return
    }
    $f = Get-Item -LiteralPath $Path
    $note = ""
    if ($AgeFromNow) {
        $note = ", built {0:N1} min ago" -f ((Get-Date) - $f.LastWriteTime).TotalMinutes
    } elseif ($StaleBefore -ne [datetime]::MinValue -and $f.LastWriteTime -lt $StaleBefore) {
        $note = "  <-- older than this run"
    }
    $stamp = if ($f.LastWriteTime.Date -eq (Get-Date).Date) { $f.LastWriteTime.ToString("HH:mm:ss") }
             else { $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") }
    Write-Host ("[RUNNER] {0,-14}: {1}, {2}{3}" -f $Label, (Format-RunnerSize $f.Length), $stamp, $note)
}

$timeoutRaw = $null
$logFileRaw = $null
$device     = $null
$forward    = @()

foreach ($a in $args) {
    $s = [string]$a
    if ($s -like "--timeout=*") {
        $timeoutRaw = $s.Substring("--timeout=".Length)
    } elseif ($s -like "--log-file=*") {
        $logFileRaw = $s.Substring("--log-file=".Length)
    } else {
        if ($s -like "--device=*") { $device = $s.Substring("--device=".Length) }
        $forward += $s
    }
}

$problems = @()
$timeout  = 0
if (-not $timeoutRaw) {
    $problems += "--timeout=SECONDS is mandatory"
} elseif (-not [int]::TryParse($timeoutRaw, [ref]$timeout) -or $timeout -le 0 -or $timeout -gt 86400) {
    $problems += "--timeout must be a whole number of seconds in 1..86400 (got '$timeoutRaw')"
}
if (-not $logFileRaw) { $problems += "--log-file=PATH is mandatory (it keeps the stock cerf.log intact)" }
if (-not $device)     { $problems += "--device=NAME is mandatory (without it, cerf boots stock cerfos)" }

if ($problems.Count -gt 0) {
    Show-RunnerUsage
    Write-Host ""
    foreach ($p in $problems) { Write-Host "[RUNNER] FAILED! $p" }
    [Environment]::Exit($RunnerExitUsage)
}

$logFile = ConvertTo-WindowsPath $logFileRaw
$logDir  = Split-Path -Parent $logFile
if ($logDir -and -not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}
$forward += "--log-file=$logFile"
$forward += "--timeout=$timeout"
$forward += "--no-focus"
$emergencyKill = $timeout + 10

$exeDir    = Join-Path $PSScriptRoot "build\Release\Win32"
$exePath   = Join-Path $exeDir "cerf.exe"
$crashLog  = Join-Path $exeDir "cerf.crash.log"
$liveState = Join-Path $exeDir "devices\$device\live_state.png"

$stdoutSink = Join-Path ([IO.Path]::GetTempPath()) "cerf_runner_out_$PID.tmp"
$stderrSink = Join-Path ([IO.Path]::GetTempPath()) "cerf_runner_err_$PID.tmp"

function Remove-RunnerSinks {
    foreach ($s in @($stdoutSink, $stderrSink)) {
        if ($s -and (Test-Path $s)) { Remove-Item $s -Force -ErrorAction SilentlyContinue }
    }
}

function Stop-Runner {
    param([int]$Code)
    Remove-RunnerSinks
    Exit-CerfLockSlot $runLocks
    [Environment]::Exit($Code)
}

trap { Remove-RunnerSinks; Exit-CerfLockSlot $runLocks; break }

$logNote = if ($logFile -ne $logFileRaw) { " (converted from '$logFileRaw')" } else { "" }
Write-Host "[RUNNER] $device, timeout $timeout s, emergency kill $emergencyKill s, log $logFile$logNote"

while ($true) {
    Wait-CerfLock $buildLock
    $runSlot = Enter-CerfLockSlot $runLocks
    if (-not (Get-CerfLockHolder $buildLock)) { break }
    Write-Host "[RUNNER] a build took .build_lock: releasing $(Split-Path -Leaf $runSlot.Path) and waiting for the build"
    Exit-CerfLock $runSlot
}
Write-Host "[RUNNER] run slot $(Split-Path -Leaf $runSlot.Path)"

if (-not (Test-Path $exePath)) {
    Write-Host "[RUNNER] FAILED! cerf.exe is absent at $exePath. Build it first."
    Stop-Runner $RunnerExitMissing
}

$argLine = ($forward | ForEach-Object { ConvertTo-RunnerArgToken $_ }) -join ' '

$runStart = Get-Date
$stopwatch = [Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process -FilePath $exePath -ArgumentList $argLine -WorkingDirectory $exeDir -PassThru `
    -RedirectStandardOutput $stdoutSink -RedirectStandardError $stderrSink -NoNewWindow
if (-not $proc) {
    Write-Host "[RUNNER] FAILED! cerf.exe did not start."
    Stop-Runner $RunnerExitMissing
}
$null = $proc.Handle
Write-Host "[RUNNER] cerf.exe PID $($proc.Id): $argLine"

$exitedOnOwn = $proc.WaitForExit($emergencyKill * 1000)
$stopwatch.Stop()

if ($exitedOnOwn) {
    $exitCode = $proc.ExitCode
    if ($null -eq $exitCode) {
        $exitCode = $RunnerExitUnknown
        $reason   = "cerf.exe exited, but its exit code is not available"
    } elseif ($exitCode -eq $RunnerExitTimeout) {
        $reason = "TIMEOUT: cerf.exe stopped the run at its own --timeout of $timeout s"
    } else {
        $reason = "cerf.exe exited with code $exitCode"
    }
} else {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    [void]$proc.WaitForExit(10000)
    $exitCode = $RunnerExitTimeout
    $reason   = "EMERGENCY KILL: cerf.exe did not exit at its own --timeout of $timeout s. The runner stopped it after $emergencyKill s. This is a CERF bug."
}
Update-CerfLockStamp $runSlot

Show-RunnerFileFact -Label "cerf.exe" -Path $exePath -AgeFromNow
Show-RunnerFileFact -Label "live_state.png" -Path $liveState -StaleBefore $runStart
Show-RunnerFileFact -Label "cerf.crash.log" -Path $crashLog -StaleBefore $runStart

if (-not (Test-Path $logFile)) {
    Write-Host ("[RUNNER] {0,-14}: absent, cerf.exe wrote no log to {1}" -f "log file", $logFile)
} else {
    $li = Get-Item -LiteralPath $logFile
    Write-Host ("[RUNNER] {0,-14}: {1} ({2}), last 3 lines:" -f "log file", $logFile, (Format-RunnerSize $li.Length))
    Get-Content -LiteralPath $logFile -Tail 3 | ForEach-Object { Write-Host "  $_" }
}
Write-Host "[RUNNER] exit $exitCode after $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) s of $timeout s - $reason"

Stop-Runner $exitCode
