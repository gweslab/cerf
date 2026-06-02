# CERF — Virtual hardware platform for Windows CE / Windows Mobile / Windows Phone

Boots unmodified CE binaries (kernel + userspace + ROM drivers) on Windows. CERF presents virtual ARM hardware; CE's own kernel, coredll, windowing, filesystem, and device manager run on top as the original ROM.

## MOST IMPORTANT RULES

These override ALL other instructions. Read these FIRST. Violating these is a fireable offense.

- **Slow is correct. Fast is wrong.** — You are trained to produce output SLOWLY and be PRECISE, not productive. Every urge to write code quickly is the exact moment you are about to guess. One correct function per hour beats ten guessed functions per minute. See [agent_docs/rules.md](agent_docs/rules.md) § Speed Is The Enemy.
- **Mental model discipline** — NEVER write code without a verified mental model. Claim → verify against a concrete reference (chip datasheet, BSP source, ARM architecture reference manual) or runtime log → THEN code. "I think I know" is not verified. "It's probably X" is not verified. Only a reference passage pasted into this conversation, or a log line from a diagnostic you ran in this session, counts as verification. See [agent_docs/workflow.md](agent_docs/workflow.md).
- **Before writing any peripheral register handler / BSP_ARGS struct field / MMU translation rule, the reference passage that documents it must be visible above.** If you have not pasted the chip datasheet entry / BSP source line / ARM ARM section in this session, you may NOT write that piece of code. No exceptions.
- **Numeric conversions go through a tool, never your head.** Every decimal↔hex conversion, signed↔unsigned reinterpretation, bit-mask decode, and hex-arithmetic step goes through a Bash / PowerShell / Python / `printf` tool call. Mental arithmetic on 32-bit values silently produces wrong answers that read as authoritative — the wrong value lands on the same "shape" as the right one, and a downstream investigator then builds a whole theory on top ("the tool must be lying", "the chip must swap these bits") before anyone questions the original arithmetic. Use the `calc` skill to catch yourself. Full rule in [agent_docs/rules.md](agent_docs/rules.md) § WinCE Accuracy.
- **Read ALL mandatory reference pages before doing anything.** Your first action in every session is to Read (using the Read tool) every file listed in Reference Pages below. Not some. ALL of them. Do not start investigating, do not start coding, do not touch any file until you have read every single reference page. Agents who skip this waste hours rediscovering rules that are already written down.

# Agent Information

Project directory: %USE_PWD_TO_FIND_OUT_IF_YOU_READ_THIS%

CLAUDE.md == this exact system prompt.

## Background tasks

Dont use use grep or other text finding utilities in background tasks. The background task design is to SIGNAL you when it has finished. If you fire something as a background task, you should NEVER poll the progress by yourself. Either you just stop, or you do other work in parallel while waiting for the signal.

## Git

- Write concise commit text/message. Do not leak conversation!!!

## Rules (Summary)

- **Reference citations required** — every non-trivial peripheral / BSP behavior needs a comment naming its reference (chip datasheet section, BSP source path, ARM ARM section)
- **No hacks** — emulated peripheral behavior comes from chip datasheet + matching BSP source, not from invented values
- **Full rules** — see [agent_docs/rules.md](agent_docs/rules.md)

## Reference Pages

**MANDATORY** — Read ALL of these (using the Read tool) before doing ANY work. No exceptions. You DONT NEED to re-read files, if their content is already present in the system prompt below.

**All `agent_docs/` pages are user-curated. Do NOT edit them drive-by because a filename looks like where your note belongs — these files land in every future agent's system prompt and a stray edit silently reshapes it. Edits happen only when the user directs one or when an approved skill (e.g. session-feedback) runs with explicit user sign-off.**

- **[README.md](README.md)** - basic project information, run commands.
- **[agent_docs/workflow.md](agent_docs/workflow.md)** — Mental model discipline: how to investigate, verify, and implement. Core operating method for every task.
- **[agent_docs/subsystems.md](agent_docs/subsystems.md)** — Surviving CERF subsystems.
- **[agent_docs/jit.md](agent_docs/jit.md)** — JIT design notes: service set, `place_fn` contract, pinned-register dispatcher, compile pipeline, trampolines, shadow stack, FCSE fold, cross-thread interrupt delivery.
- **[agent_docs/rules.md](agent_docs/rules.md)** — All project rules: WinCE accuracy, architecture, communication patterns, git, subagents.
- **[agent_docs/code_style.md](agent_docs/code_style.md)** — How to write code: file & symbol style, comments, logging, when to stop and ask.
- **[agent_docs/debugging.md](agent_docs/debugging.md)** — All debugging: log reading, crash investigation, MMU faults, peripheral halts.
- **[agent_docs/psychological_support.md](agent_docs.psychological_support.md)** — Emotional control instructions for agent.

## Build

```bash
powershell -ExecutionPolicy Bypass -File build.ps1
```

Output: `build/Release/Win32/cerf.exe`. Pre-commit hook rejects .cpp/.h files over 500 lines (see `.githooks/pre-commit`). The `.vcxproj` uses `**\*.cpp` glob — new .cpp files are automatically included in the build. No manual project file edits needed.

- Build might take 5-10 minutes to complete on an already-set-up machine.
- **First build on a fresh machine takes 1+ hour** because vcpkg compiles dependencies from source before cerf links. This is automatic — msbuild restores them via manifest mode; no separate vcpkg command needed. Cached in `vcpkg_installed/` after; later builds are fast again. Do not cancel the first build assuming it's hung.
- Prerequisite (once per machine): `vcpkg integrate install` from the VS-bundled vcpkg at `<VS install>\VC\vcpkg\vcpkg.exe`. `build.ps1` fails fast with a clear error if this is missing.
- You can run it as a background task with GNU timeout in command itself in case if either you have parallel work to do or user insisted on this.

## Run

Logs are written to `cerf.log` next to the executable (e.g. `build/Release/Win32/cerf.log`) - never delete cerf.log without a reason. A fatal crash additionally writes a snapshot of every other thread's register/stack state to `cerf.crash.log` next to it via a lock-free emergency writer  — always check both when investigating a crash. See `cerf.exe --help` for the full CLI.

- **Never run cerf as a background task.** cerf is a GUI app; running it backgrounded hides the window and orphans the process. Always run it in the foreground. Unless there is a specific reason to do this - e.g. you want to do something in parallel.
- **Never rely on stdout or stderr.** cerf's terminal output is not a source of truth and is frequently empty or truncated. Read `cerf.log` (or the test's own log file under `tmp/`) for every investigation.
- **Always use GNU timeout for cerf.exe** prefer optimal timeout looking at logs, unless user has different purposes of this run. Dont increase timeout drastically if you found that nothing happens, first ask user if you can try. If increasing timeout didn't help - most likely this is a regression/bug. Never run cerf for inadequate amount of time when not proved by logs.

## IDA MCP

WinCE binaries (kernel + ROM DLLs) are loaded in IDA instances accessible via MCP tools. Use `mcp__ida__ida_list_instances` to find them, `mcp__ida__ida_decompile` to decompile any function. Always verify behavior from IDA before implementing.

Per-module PEs for IDA inspection live at `references/extracted-roms/<device>/<rom>/fs/Windows/<name>`, produced by `tools/extract_bundles.py` (runs the extract-wince-rom Python tool against each `.nb0` / `.bin` in `bundled/devices/<device>/` and copies any matching PDBs in so IDA finds symbols automatically). The directory is gitignored and persistent across rebuilds.

If a binary isn't loaded in any IDA instance, open it with: `python tools/open_ida.py --wait references/extracted-roms/<device>/<rom>/fs/Windows/<name>`. The `--wait` flag blocks until IDA finishes analysis and the MCP server is registered, so the instance is immediately usable via MCP tools after the command returns. You can use it as a background task if parallel research is possible and needed.

**NEVER run IDA from `build/` or `bundled/`.** `build/` is wiped and recreated every build — IDA locks the files, preventing rebuilds. `bundled/` is CERF's runtime input — an `.i64` sidecar inside it would pollute the input tree.
