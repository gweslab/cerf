# Launcher for the CERF Claude Code agent.
#
# Concatenates the mandatory CLAUDE.md subdoc set into a single system prompt
# and hands it to `claude`, so the agent can't "skip reading the reference
# pages" — the reference pages are already in its system prompt.
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
# $files below — priority is top-down.
#
# Memory watchdog: claude.exe occasionally leaks. A background runspace polls
# its working set every $PollSeconds and force-kills it if it exceeds
# $MemoryLimitGB, then offers a restart. The runspace runs in-process, so
# it doesn't disturb the TUI.

# Parse our own flags out of $args manually instead of using a param() block.
# A param() block makes PS reject unknown switches like --resume / --continue,
# which we need to forward verbatim to claude. PS 5.1's
# [Parameter(ValueFromRemainingArguments)] only captures POSITIONAL leftovers,
# not switch-style args, so it doesn't help here.
$MemoryLimitGB = 4.2
$PollSeconds   = 3
$claudeArgs    = @()
$i = 0
while ($i -lt $args.Count) {
    $a = $args[$i]
    switch -CaseSensitive ($a) {
        '-MemoryLimitGB'      { $MemoryLimitGB = [double]$args[$i+1]; $i += 2; continue }
        '--memory-limit-gb'   { $MemoryLimitGB = [double]$args[$i+1]; $i += 2; continue }
        '-PollSeconds'        { $PollSeconds   = [int]   $args[$i+1]; $i += 2; continue }
        '--poll-seconds'      { $PollSeconds   = [int]   $args[$i+1]; $i += 2; continue }
        default               { $claudeArgs += $a; $i += 1 }
    }
}

Set-Location -LiteralPath $PSScriptRoot
Clear-Host

# Ordered list of mandatory documents. Matches CLAUDE.md's "Reference Pages"
# section (the MANDATORY bullets — the lazy-read set is intentionally omitted).
$files = @(
    @{ Name = $null;                      Path = 'CLAUDE.md' },
    @{ Name = 'README.md';                Path = 'README_SOURCE.md' },
    @{ Name = 'agent_docs/workflow.md';   Path = 'agent_docs\workflow.md' },
    @{ Name = 'agent_docs/subsystems.md'; Path = 'agent_docs\subsystems.md' },
    @{ Name = 'agent_docs/jit.md';        Path = 'agent_docs\jit.md' },
    @{ Name = 'agent_docs/rules.md';      Path = 'agent_docs\rules.md' },
    @{ Name = 'agent_docs/code_style.md'; Path = 'agent_docs\code_style.md' },
    @{ Name = 'agent_docs/debugging.md'; Path = 'agent_docs\debugging.md' }
    @{ Name = 'agent_docs/psychological_support.md'; Path = 'agent_docs\psychological_support.md' }
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
        # codepage and mis-decodes UTF-8-without-BOM source files — a single
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
    # — e.g. the user launched `claude --system-prompt-file CLAUDE.md` directly
    # — the tag stays literal in the prompt, which is itself a hint to the
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
    # claude` spawning — anything that appears later is "ours."
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
        # Diagnostic log — read %TEMP%\cerf_watchdog.log post-mortem if the
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
        # Robust against `claude` being a .cmd/node shim — we don't need to be
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

    try {
        & claude --effort high `
                 --allow-dangerously-skip-permissions `
                 --permission-mode bypassPermissions `
                 --system-prompt-file $tempFile `
                 @claudeArgs
    } finally {
        # Monitor exits on its own when claude.exe is gone. Stop+dispose to
        # be safe in case it's still in Start-Sleep.
        try { $ps.Stop()    } catch {}
        try { $ps.Dispose() } catch {}
        try { $rs.Dispose() } catch {}
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }

    if ($monitorState.Killed) {
        # Best-effort terminal reset — claude leaves the console in alt-screen
        # raw mode when killed mid-run. Leave alt screen, show cursor, reset SGR.
        # `e is a PS 6+ escape; this script must work on Windows PowerShell 5.1.
        $esc = [char]27
        [Console]::Write("$esc[?1049l$esc[?25h$esc[0m")
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
