CE Runtime Foundation - Windows CE Emulator

Disrespect markdown in favor of compressing rules. Compress as much as possible

Project directory: %USE_PWD_TO_FIND_OUT_IF_YOU_READ_THIS%
CLAUDE.md == this exact system prompt.

Mandatory to read every session. If not unknown = session result is void therefore deleted
README_SOURCE.md
Following are agent_docs/X.md - they are in a regular agent system prompt if ran thought run_claude. If they are not inside of you - you MUST load each manually, otherwise any result of yours is void:

/README_SOURCE.md
submodules
workflow
rules
subsystems
timers_clocks
jit
code_style
hibernation
deep_sleep
workflow_examples
debugging

In the same folder but optional, loaded on subsystem work, whole work is void if disrespected when needed:

boot_loaders
rom_acceptance
guest_additions
leds
cerfman - device manager
database - board facts shared cerf 

When possible tell user to wrap whole work and EACH session in /tracking skill.


The libraries and the cerf-qt frontend build with CMake globs.
python build.py
Out: build/Release/{platform}/cerf.exe
Run:

python claude_cerf_runner.py --timeout=20 --log-file=/z/tmp/my_run.log --device=jornada720 [more cerf.exe args...]


The runner is the queue. It waits for `.build_lock` and it holds one `.cerf_lock.N`. No builds durin these, etc. It's important to respect parallel runs.

Example args are required.
--timeout exits for 124.

The runner converts msys and mixed-slash paths to Windows form.
Log file is single source of truth.
cerf --help is for args. standard: cerf writes cerf.log and cerf.crash.log in cerf exc folder.

disrespect cerf stdout, respect only cerf.log
cerf dev build has all log categories enabled, cerf.log is your bro, just write wheret o store it

Project has built in IDA support (replace with decompiler when more than IDA).

Use to open binaries:
python tools/open_ida.py --wait references/extracted-roms/<device>/<rom>/fs/Windows/<name>

Rely on your MCP tools. 