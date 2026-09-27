# Workflow Examples

Proven investigation recipes. Use the matching recipe before you invent your own.

## Parallel IDA sweep - one question across many guest binaries

Use this recipe when a question spans many modules at once: "which driver owns SYSINTR N",
"who touches register X", "does ANY module in the ROM validate this value".

1. If the per-module PEs are absent, extract them
   (`references/extracted-roms/<device>/<rom>/fs/Windows/`, see debugging.md § IDA discipline).
2. Preload EVERY needed IDA instance yourself: `python tools/open_ida.py --wait <module>`.
   Verify that each one prints its port and "IDA IS READY!".
3. Verify the stack with `mcp__ida_mcp__ida_list_instances`. Note the port of each module.
4. Spawn parallel subagents restricted to `mcp__ida_mcp__*` tools ONLY - no Bash, no
   PowerShell, no file ops, no open or close of IDA instances. Each prompt names its exact
   ports and 1-3 modules. Each prompt requires an IDA address cited for every claim,
   UNDETERMINED plus a blocking reason instead of a guess, and raw-data output, not prose.
5. Before you trust either side, verify contradictions between agent reports with your own
   targeted decompile or disasm.
6. BEFORE you call the sweep done, persist the consolidated map into the durable document of
   the investigation (the tracking doc, or a map file that it points at).

## Using Guest OS

Sometimes you need to run an EXE in the guest headlessly - for example, explorer with a URL.
On a Guest Additions run, use the autorun list: `--ga-autorun=<guest path>`, or the
`guest_additions.autorun` array in `cerf.json` / `cerf-user.json`.

For a complex or unusual case, temporarily modify `ce_apps/cerf_guest`. Drive the action from
the Guest Additions driver. Examples of such a case are an action that needs a delay, a window
message, or a file write. You have full access to the user space of the guest OS.

Both routes replace the display driver, so the behavior is not hardware-faithful. If you need the
stock driver and the stock behavior, these routes do not apply.

Delete such temporary code when you no longer need it.

## Emulator Features

- If you want to test hibernation, inject touch, inject keyboard presses - you always can create
  a temporary trace file which does that invasively for you. Delete that file in the same reply
  that reports what it measured. Write it, build, run, read the log, then remove it before you
  say what it showed. A report of a measurement is a moment that always arrives. The end of a
  task is not, and on a hunt across sessions that moment never comes. Do not keep the probe
  because you need it again. Its text is in the reply that just used it, and to write it again
  costs a minute. A probe that survives drives the board on every later run, and it reads as a
  hardware fault.
- If you want to insert a PC Card, simply temporary modify the code. We usually auto-insert NE2000
  into one slot if guest OS is CE 4+. For CE <= 3, NE2000 interrupts a welcome wizard with a config dialog
  and combine that with not calibrated touch panel.
- Emulator generates a screenshot into a device directory `live_state.png` every 10 seconds. Deleted at graceful
  shutdown - wont be deleted if you are using GNU timeout
- If you need own files to be accessible inside guest OS, you can boot GA with `--ga-share-folder=...` (spawned as ``\CERF Storage\*``) or
  generate FAT16/FAT32 CF PCCard and insert it the same temp scaffolding (usually visible as ``\Storage Card\*``).

## Env-variable gate for temporary scaffolding

Temp scaffolding reads a host environment variable. It never reads that value from a constant
in the file. An absent or zero value leaves it inert, so one build serves both the stock run and
the invasive run. The variable carries a value, not only an on/off flag - a delay, a count, a
guest address. The variable goes in front of the runner command. A user-facing option is a
CLI flag instead.

## Autonomous board development

Claude can implement a board end-to-end without user interaction through the following loop.

Hit fatal exit -> Implemented the feature -> Ran - it works -> Spawning Skill(verify) until LEGIT -> Repeat

It is also suggested for user to set /goal harness, which demands UI working rendering and device confirmed to be usable. In the same /goal user should demand autonomous workflow per project rules and invoking /bad, /verify-options, /bailout on turn ends.

The user also should manually invoke /tracking skill on session boundaries (never agent invoked).

Skill(verify) wont let agent smuggle guesses and rule violations into the tree. This is expensive but works extremely well. Applies not just to board development, but to any development cycles, usually.

That also aligns with the AI-preferred model. AI can build an enormous system accross many session, but can't in one prompt. Everything AI builds here is a simple, dumb fatal <-> implement case, each is a separate chunk. Prompt "AI, implement enormous subsystem now" would give you broken subsystem where AI replaces implementations with broken stubs. Fatal <-> implement loop gives AI an ability to split chunk clearly: from fatal to implementation and repeat with static verification. That's a resolution to all AI problems at once and also is an incredible verification pattern.

All fatals are usually up to shell boot, once there is no fatal the investigation starts. It's either about "why no fatal and no shell" or "why touch/key interactions give no shell". The end result is having an interactive basic device, with everything rendering, and the most important interaction devices being implemented. 
