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

Sometimes you would need to run some EXEs headlessly. Or, for example, you would need to run explorer
to open internet page headlessly. You can temporary modify `ce_apps/cerf_guest` and use Guest Additions
driver to drive the actions on the guest OS. You can, for example add a thread with a 5-10s delay and
do `CreateProcess` there. Basically you receive a full access to the user space of guest OS.

The con here is that display driver is replaced fully and the behaviour is not hardware-faithful anymore.
So this will work in most cases unless you specifically need a stock driver and stock behaviour.

Such temp code must be deleted once not needed.

## Emulator Features

- If you want to test hibernation, inject touch, inject keyboard presses - you always can create
  a temporary trace file which does that invasively for you.
- If you want to insert a PC Card, simply temporary modify the code. We usually auto-insert NE2000
  into one slot if guest OS is CE 4+. For CE <= 3, NE2000 interrupts a welcome wizard with a config dialog
  and combine that with not calibrated touch panel.
- Emulator generates a screenshot into a device directory `live_state.png` every 10 seconds. Deleted at graceful
  shutdown - wont be deleted if you are using GNU timeout
- If you need own files to be accessible inside guest OS, you can boot GA with `--share-folder=...` or
  generate FAT16/FAT32 CF PCCard and insert it the same temp scaffolding.
- Dont forget to remove your temp invasive scaffoldings once you are done with the task you needed
  those for.

## Env-variable gate for temporary scaffolding

Temp scaffolding can read a host environment variable instead of a hardcoded constant. An
absent or zero value leaves it inert, so one build serves both the stock run and the invasive
run. The variable carries a value, not only an on/off flag - a delay, a count, a guest address.
Set the variable in front of the runner.
`cerf/host/presented_frame_renderer.cpp` reads `CERF_LCD_STALL_MS` this way. The gate is
scaffolding, so it goes when the task ends. A user-facing option is a CLI flag instead.
