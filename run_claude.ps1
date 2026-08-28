# Launcher for the CERF Claude Code agent.
#
# Concatenates the mandatory CLAUDE.md subdoc set into a single system prompt
# and hands it to `claude`, so the agent can't "skip reading the reference
# pages" - the reference pages are already in its system prompt.
#
# Format (matches the spec in the original task):
#   <file[0].content>                  # first entry is the system-prompt base (no header)
#
#   <file[1].name>:
#   <file[1].content>
#
#   <file[2].name>:
#   <file[2].content>
#   ...
#
# CLAUDE.md always comes first. Add new mandatory subdocs by appending to
# $files below - priority is top-down.
#
# Memory watchdog: claude.exe occasionally leaks. A background runspace polls
# its working set every $PollSeconds and force-kills it if it exceeds
# $MemoryLimitGB, then offers a restart. The runspace runs in-process, so
# it doesn't disturb the TUI.
#
# clangd watchdog: a second runspace sweeps ALL clangd.exe instances every
# $PollSeconds and force-kills any whose private bytes exceed
# $ClangdMemoryLimitGB. No prompt, no restart - the editor respawns clangd
# on demand.

# Parse our own flags out of $args manually instead of using a param() block.
# A param() block makes PS reject unknown switches like --resume / --continue,
# which we need to forward verbatim to claude. PS 5.1's
# [Parameter(ValueFromRemainingArguments)] only captures POSITIONAL leftovers,
# not switch-style args, so it doesn't help here.
$MemoryLimitGB       = 4.2
$ClangdMemoryLimitGB = 1.5
$PollSeconds         = 3
$claudeArgs          = @()
$i = 0
while ($i -lt $args.Count) {
    $a = $args[$i]
    switch -CaseSensitive ($a) {
        '-MemoryLimitGB'        { $MemoryLimitGB       = [double]$args[$i+1]; $i += 2; continue }
        '--memory-limit-gb'     { $MemoryLimitGB       = [double]$args[$i+1]; $i += 2; continue }
        '-ClangdLimitGB'        { $ClangdMemoryLimitGB = [double]$args[$i+1]; $i += 2; continue }
        '--clangd-limit-gb'     { $ClangdMemoryLimitGB = [double]$args[$i+1]; $i += 2; continue }
        '-PollSeconds'          { $PollSeconds         = [int]   $args[$i+1]; $i += 2; continue }
        '--poll-seconds'        { $PollSeconds         = [int]   $args[$i+1]; $i += 2; continue }
        default                 { $claudeArgs += $a; $i += 1 }
    }
}

Set-Location -LiteralPath $PSScriptRoot
Clear-Host

# First-run gate. Until the user has acknowledged what this launcher does, show
# a one-time welcome + warnings and wait for Enter. The acknowledgement is
# recorded by creating .claude_gate (gitignored, per-machine); once it exists
# the intro never shows again and the launcher runs straight through.
$gateFile = Join-Path $PSScriptRoot '.claude_gate'
if (-not (Test-Path -LiteralPath $gateFile)) {
    Write-Host ""
    Write-Host "  Welcome to the CERF Claude development environment" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  run_claude launches Claude Code with a custom system prompt that injects"
    Write-Host "  the ENTIRE project documentation (CLAUDE.md + every agent_docs reference"
    Write-Host "  page) into every agent, so each session starts fully briefed on the"
    Write-Host "  project's rules, architecture, and subsystems."
    Write-Host ""
    Write-Host "  WARNING: Claude runs in skip-permissions mode. It can execute ABSOLUTELY" -ForegroundColor Yellow
    Write-Host "  ANYTHING on this machine without asking: edit files, run shell commands," -ForegroundColor Yellow
    Write-Host "  delete data, hit the network." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  WARNING: this launcher polls for memory leaks. It will FORCE-KILL its own" -ForegroundColor Yellow
    Write-Host "  Claude instance if it leaks past its limit, and it will FORCE-KILL ANY" -ForegroundColor Yellow
    Write-Host "  clangd.exe on this machine that leaks past its limit - not just ones it" -ForegroundColor Yellow
    Write-Host "  started." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Tip: once inside, start by running  /cerf  to see the special skills this" -ForegroundColor Green
    Write-Host "  project provides (including /start-board-implementation to bring up a ROM)." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Press Enter to proceed (this message will never be shown again)." -ForegroundColor Cyan
    [void](Read-Host)
    try {
        New-Item -ItemType File -Path $gateFile -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Could not create gate file '$gateFile': $($_.Exception.Message)"
        exit 1
    }
    Clear-Host
}

# Ordered list of mandatory documents. Matches CLAUDE.md's "Reference Pages"
# section (the MANDATORY bullets - the lazy-read set is intentionally omitted).
$files = @(
    @{ Name = $null;                                 Path = 'CLAUDE.md' },
    @{ Name = 'README_SOURCE.md';                    Path = 'README_SOURCE.md' },
    @{ Name = 'agent_docs/workflow.md';              Path = 'agent_docs\workflow.md' },
    @{ Name = 'agent_docs/workflow_examples.md';     Path = 'agent_docs\workflow_examples.md' },
    @{ Name = 'agent_docs/subsystems.md';            Path = 'agent_docs\subsystems.md' },
    @{ Name = 'agent_docs/boot_loaders.md';          Path = 'agent_docs\boot_loaders.md' },
    @{ Name = 'agent_docs/rom_acceptance.md';        Path = 'agent_docs\rom_acceptance.md' },
    @{ Name = 'agent_docs/jit.md';                   Path = 'agent_docs\jit.md' },
    @{ Name = 'agent_docs/rules.md';                 Path = 'agent_docs\rules.md' },
    @{ Name = 'agent_docs/hibernation.md';           Path = 'agent_docs\hibernation.md' },
    @{ Name = 'agent_docs/code_style.md';            Path = 'agent_docs\code_style.md' },
    @{ Name = 'agent_docs/debugging.md';             Path = 'agent_docs\debugging.md' }
    @{ Name = 'agent_docs/guest_additions.md';       Path = 'agent_docs\guest_additions.md' }
    @{ Name = 'agent_docs/deep_sleep.md';            Path = 'agent_docs\deep_sleep.md' }
    @{ Name = 'agent_docs/launcher.md';              Path = 'agent_docs\launcher.md' }
    @{ Name = 'agent_docs/psychological_support.md'; Path = 'agent_docs\psychological_support.md' }
    @{ Name = 'agent_docs/leds.md';                  Path = 'agent_docs\leds.md' }
)

do {
    $restart = $false

    # Rebuild on every iteration so a doc edit between restarts is picked up.
    $parts = foreach ($entry in $files) {
        $fullPath = Join-Path $PSScriptRoot $entry.Path
        if (-not (Test-Path -LiteralPath $fullPath)) {
            Write-Error "Mandatory document missing: $fullPath"
            exit 1
        }
        # Must use .NET ReadAllText with explicit UTF-8, NOT Get-Content -Raw.
        # Windows PowerShell 5.1's Get-Content defaults to the legacy ANSI
        # codepage and mis-decodes UTF-8-without-BOM source files - a single
        # em-dash ends up as three garbage codepoints in the system prompt.
        $content = [System.IO.File]::ReadAllText($fullPath, [System.Text.Encoding]::UTF8)
        if ($null -eq $entry.Name) {
            # System-prompt base: no header, just the raw content.
            $content
        } else {
            "$($entry.Name):`n$content"
        }
    }

    $combined = $parts -join "`n`n"

    # Replace the %USE_PWD_TO_FIND_OUT_IF_YOU_READ_THIS% tag in CLAUDE.md with
    # the project root (this script's own directory). If this script didn't run
    # - e.g. the user launched `claude --system-prompt-file CLAUDE.md` directly
    # - the tag stays literal in the prompt, which is itself a hint to the
    # agent that `pwd` is the authoritative source for the project root.
    $combined = $combined.Replace(
        '%USE_PWD_TO_FIND_OUT_IF_YOU_READ_THIS%',
        $PSScriptRoot
    )

    # Can't pass this on the command line: Windows' CreateProcess caps the command
    # line at 32767 chars; the concatenated mandatory docs are ~80 KB. Route it
    # through a temp file via --system-prompt-file instead. File is deleted in
    # the finally block once claude exits.
    $tempFile = [System.IO.Path]::Combine(
        $env:TEMP,
        "cerf_sysprompt_$([System.Guid]::NewGuid().ToString('N')).md"
    )

    # UTF-8 without BOM. Windows PowerShell 5.1's `-Encoding utf8` writes a BOM,
    # which would show up as a stray U+FEFF at the very top of the system prompt.
    [System.IO.File]::WriteAllText(
        $tempFile,
        $combined,
        (New-Object System.Text.UTF8Encoding($false))
    )

    # Shared state with the monitor runspace. Synchronized hashtable so writes
    # from the runspace are visible here without locks.
    $monitorState = [hashtable]::Synchronized(@{
        Killed    = $false
        PeakBytes = [long]0
        TargetPid = $null
    })

    # Snapshot pre-existing claude.exe PIDs HERE in the parent (before the
    # runspace starts). Avoids any race between runspace startup and `&
    # claude` spawning - anything that appears later is "ours."
    $preExistingPids = @{}
    Get-Process -Name claude -ErrorAction SilentlyContinue | ForEach-Object {
        $preExistingPids[$_.Id] = $true
    }

    $watchdogLog = [System.IO.Path]::Combine($env:TEMP, 'cerf_watchdog.log')

    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('state',           $monitorState)
    $rs.SessionStateProxy.SetVariable('preExistingPids', $preExistingPids)
    $rs.SessionStateProxy.SetVariable('limitBytes',      [long]($MemoryLimitGB * 1GB))
    $rs.SessionStateProxy.SetVariable('pollSeconds',     $PollSeconds)
    $rs.SessionStateProxy.SetVariable('watchdogLog',     $watchdogLog)
    $rs.SessionStateProxy.SetVariable('limitGB',         $MemoryLimitGB)

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        # Diagnostic log - read %TEMP%\cerf_watchdog.log post-mortem if the
        # watchdog didn't fire as expected. Writes can fail silently under
        # extreme memory pressure; that's fine, the kill path is what matters.
        function Log([string]$msg) {
            try {
                Add-Content -LiteralPath $watchdogLog `
                    -Value ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $msg) `
                    -ErrorAction SilentlyContinue
            } catch {}
        }
        Log "----- watchdog start, limit=$limitGB GB, poll=${pollSeconds}s -----"
        Log "preExisting claude.exe pids: $(($preExistingPids.Keys | Sort-Object) -join ',')"

        # Snapshot-diff: any claude.exe that wasn't running pre-launch is ours.
        # Robust against `claude` being a .cmd/node shim - we don't need to be
        # claude.exe's direct parent. 30 s timeout in case claude never starts.
        $targetPid = $null
        $deadline  = (Get-Date).AddSeconds(30)
        while (-not $targetPid -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 300
            $candidates = Get-Process -Name claude -ErrorAction SilentlyContinue |
                          Where-Object { -not $preExistingPids.ContainsKey($_.Id) }
            if ($candidates) {
                $targetPid = ($candidates | Sort-Object StartTime | Select-Object -First 1).Id
            }
        }
        if (-not $targetPid) {
            Log "TIMED OUT -- no new claude.exe appeared within 30s. Watchdog inactive."
            return
        }
        $state.TargetPid = $targetPid
        Log "monitoring pid=$targetPid (private-bytes metric, threshold=$limitBytes)"

        while ($true) {
            Start-Sleep -Seconds $pollSeconds
            try {
                $p     = Get-Process -Id $targetPid -ErrorAction Stop
                # PrivateMemorySize64 = committed memory unique to this process.
                # Matches System Informer's "Private bytes" column. Working set
                # (RSS) gets paged out under pressure and underreports leaks.
                $bytes = $p.PrivateMemorySize64
                if ($bytes -gt $state.PeakBytes) { $state.PeakBytes = $bytes }
                Log ("private={0:N0} bytes ({1:N2} GB)" -f $bytes, ($bytes / 1GB))
                if ($bytes -gt $limitBytes) {
                    Log "OVER LIMIT -- killing pid=$targetPid"
                    $state.Killed = $true
                    Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
                    break
                }
            } catch {
                Log "process gone (exited normally or already killed): $($_.Exception.Message)"
                break
            }
        }
        Log "----- watchdog exit -----"
    })
    $async = $ps.BeginInvoke()

    # clangd.exe watchdog. Unlike the claude watchdog there is no single target
    # pid - every clangd.exe on the machine is fair game, and the sweep runs
    # for the whole claude session (clangd instances come and go as editors
    # restart them). Same private-bytes metric as above.
    $rsClangd = [runspacefactory]::CreateRunspace()
    $rsClangd.Open()
    $rsClangd.SessionStateProxy.SetVariable('clangdLimitBytes', [long]($ClangdMemoryLimitGB * 1GB))
    $rsClangd.SessionStateProxy.SetVariable('pollSeconds',      $PollSeconds)
    $rsClangd.SessionStateProxy.SetVariable('watchdogLog',      $watchdogLog)
    $rsClangd.SessionStateProxy.SetVariable('clangdLimitGB',    $ClangdMemoryLimitGB)

    $psClangd = [powershell]::Create()
    $psClangd.Runspace = $rsClangd
    [void]$psClangd.AddScript({
        function Log([string]$msg) {
            try {
                Add-Content -LiteralPath $watchdogLog `
                    -Value ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $msg) `
                    -ErrorAction SilentlyContinue
            } catch {}
        }
        Log "----- clangd watchdog start, limit=$clangdLimitGB GB, poll=${pollSeconds}s -----"
        while ($true) {
            Start-Sleep -Seconds $pollSeconds
            foreach ($p in (Get-Process -Name clangd -ErrorAction SilentlyContinue)) {
                $bytes = $p.PrivateMemorySize64
                if ($bytes -gt $clangdLimitBytes) {
                    Log ("clangd OVER LIMIT -- killing pid={0} private={1:N0} bytes ({2:N2} GB)" -f `
                        $p.Id, $bytes, ($bytes / 1GB))
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
    })
    $asyncClangd = $psClangd.BeginInvoke()

    try {
        & claude --effort high `
                 --allow-dangerously-skip-permissions `
                 --permission-mode bypassPermissions `
                 --system-prompt-file $tempFile `
                 @claudeArgs
    } finally {
        # Monitor exits on its own when claude.exe is gone. Stop+dispose to
        # be safe in case it's still in Start-Sleep. The clangd sweep loops
        # forever by design - Stop() is its only exit path.
        try { $ps.Stop()          } catch {}
        try { $ps.Dispose()       } catch {}
        try { $rs.Dispose()       } catch {}
        try { $psClangd.Stop()    } catch {}
        try { $psClangd.Dispose() } catch {}
        try { $rsClangd.Dispose() } catch {}
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }

    if ($monitorState.Killed) {
        # Best-effort terminal reset - claude leaves the console in alt-screen
        # raw mode when killed mid-run. Leave alt screen, show cursor, reset SGR.
        # `e is a PS 6+ escape; this script must work on Windows PowerShell 5.1.
        $esc = [char]27
        [Console]::Write("$esc[?1049l$esc[?25h$esc[0m")
        # Wipe the dangling claude TUI output before showing the restart prompt.
        Clear-Host
        Write-Host ""
        Write-Host ("[run_claude] claude.exe exceeded {0} GB and was killed (peak private bytes: {1:N2} GB, pid {2})." -f `
            $MemoryLimitGB, ($monitorState.PeakBytes / 1GB), $monitorState.TargetPid) `
            -ForegroundColor Yellow
        Write-Host "[run_claude] watchdog log: $env:TEMP\cerf_watchdog.log" -ForegroundColor DarkGray
        $reply = Read-Host "Restart claude? [Y/n]"
        if ($reply -eq '' -or $reply -match '^[Yy]') {
            $restart = $true
            Clear-Host
        }
    }
} while ($restart)
