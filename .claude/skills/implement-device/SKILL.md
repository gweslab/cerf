---
name: implement-device
description: Start the bring-up of a new board or ROM in CERF.
---

# Start Board Implementation - new-board bring-up

`CLAUDE.md` and every `agent_docs/` page override this skill.

The ROM is the only trusted starting point. A stated SoC or board is a hint.
Establish the board, the SoC, the CPU and the existing CERF support yourself,
from the ROM bytes and the internet. A bring-up that starts from an unverified
assumption wastes dozens of sessions.

Edit no file in the source tree before the first run of the bundle in Phase D.

## Phase 0 - Welcome

Before Gate A1, write this welcome to the user:

> 🎉 Welcome - and thank you for contributing a new board to CERF! I'll start
> from your ROM, confirm the board/SoC facts myself, and lay out what the
> bring-up will take before we commit to it.

Use one or two lines for it. Then start Gate A1 in the same reply.

## Phase A - Gates

### Gate A1 - Find the ROM

The user can name the board without a path. The development ROMs are in
`bundled/devices/`.

1. If the user names a board, run `ls bundled/devices/`. Match the name by
   family, not by exact string. Accept a different variant, generation, letter
   or separator. For example, "simpad cl4", "simpad sl4" and "SIMpad SL4" all
   match the `simpad_sl4_*` bundles. Do not use `cerf.json` for the match.
2. If the user gives a path inside `bundled/devices/`, make sure that the path
   exists. Then use it.
3. If the user gives a path outside `bundled/devices/`, ask whether to copy the
   ROM into `bundled/devices/` first. Continue after the copy, or when the user
   tells you to run the ROM in place.
4. If one bundle matches, record its ROM path.
5. If several bundles match the same board, they are ROM generations of one
   board id. Name the generations. Then take the newest one, or ask "which
   generation?".

If `ls` shows a bundle that plausibly belongs to the named family, the ROM is
found. Do not report "not found" in that case. Do not state from memory that a
bundle is present or absent.

If `ls` shows no plausible bundle, stop and write:

> ❌ I couldn't find any ROM for "<what the user said>" under `bundled/devices/`.
> Point me at the ROM path directly, then re-run `/implement-device`.

### Gate A2 - IDA MCP

The bring-up depends on reverse engineering in IDA.

1. Find the tool that lists the IDA instances: use `ToolSearch` with the query
   `ida`. Load the schema of the tool and call it.
2. If the call succeeds, the IDA MCP runs. A result of 0 instances is normal,
   because you open IDA when a step needs it.
3. If no such tool exists, the IDA MCP does not run. Do not fail. Write this
   warning and wait for the answer:

   > ⚠️ No IDA MCP detected. Without reverse engineering I'm badly limited -
   > bring-up is decompile-driven (cracking the kernel OEMAddressTable for page
   > tables, decoding which driver touches each register), and going blind tends
   > to dead-end and burn far more sessions. The MCP server lives in this repo:
   > `tools/ida_server.py` (load inside IDA) + `tools/claude_ida.py` (the MCP
   > client); `tools/open_ida.py --wait <pe>` opens a module. Install those and
   > reconnect for a real shot.
   >
   > Continue anyway without RE? `[yes|no]`

If the answer is no, stop. If the answer is yes, continue, and mark with ⚠️
each table row that depends on reverse engineering.

## Phase B - Establish the facts

Phase B and Phase C change no file in the source tree. Do the minimum work
that fills the table of Phase C. Give a source for each fact.

### B0 - Acceptance pipeline

Decide which pipeline of `agent_docs/rom_acceptance.md` accepts the file. If
the file is a raw bus capture, normalize it first. The result tells you whether
the extractor of B1 can read the file.

### B1 - Modules

Extract the ROM with `tools/extract_bundles.py`. Open its modules with
`tools/open_ida.py --wait`. Record the names of the kernel, the system modules
and the drivers. A driver name can show the SoC. For example, `*_mx31.dll`
shows the i.MX31.

### B2 - Board identity

The declared `board_id` selects the `BoardContext`. Make sure that the
declaration names the silicon that the ROM uses. `meta.soc_family` and the word
of the user are hints. Use this evidence, the strongest first:

1. The names of the drivers and modules from B1. An OEM names its drivers after
   its own silicon.
2. The register bases that the OAL addresses.
3. The model string of the OEM, if the ROM has one.

A byte match is evidence only after you show that the bytes are a string.

### B3 - Board family

Find the devices that the vendor built on this platform: rebadges, regional
models, revisions, and panel and size variants. Search Linux, NetBSD
(`references/netbsd/sys/arch/hpc/hpc/platid_name.c` and the port code),
Rockbox, vendor pages, and Wikipedia in every language. Save each page that you
cite under `references/board_families/<vendor>/`.

Then read the `board_families` and `boards` directories of `libCerfCore/db/`.
List `libCerfCore/src/boards/` and `bundled/devices/`. Decide one result: the
family is present, the board is present, or both are absent.

### B4 - SoC and CPU

Find the SoC, its CPU architecture, and the core with its ISA level. Use the
identity of B2 and the driver names. Make sure that a datasheet, the Linux or
QEMU source, or a device specification agrees. The word of the user is not such
a source.

### B5 - SoC support in CERF

Read the `socs` and `cpu_configs` directories of `libCerfCore/db/`. List
`libCerfCore/src/socs/` and `libCerfCore/src/cpu/`. Record whether CERF has the
SoC, a `cpu_configs` row for it, and the strategy set of its core. If CERF
lacks the SoC, name the closest SoC or core that the bring-up can reuse.

## Phase C - Readiness table

Write exactly this table. Keep the columns, the rows and their order the same
in every run. `Finding` is the fact and its source. `Status` is one emoji: ✅
for present or reusable, ⚠️ for new work or an uncertain fact, ❌ for missing.

```
## /implement-device - bring-up readiness

| # | Check                          | Finding                                   | Status |
|---|--------------------------------|-------------------------------------------|--------|
| 1 | ROM acquired                   | <bundle / path>                           | ✅/❌  |
| 2 | IDA MCP connectivity           | <running, N instances | not running>      | ✅/⚠️  |
| 3 | Board identity                 | <declared board.id> confirmed by <tells>  | ✅/⚠️  |
| 4 | Board already in CERF          | <board row exists | absent>               | ✅/❌  |
| 5 | SoC / CPU family               | <SoC>, <core>, <CpuArch + isa level>      | ✅/⚠️  |
| 6 | SoC implemented in CERF        | <libCerfCore/src/socs/<x> present | absent>           | ✅/❌  |
| 7 | Reusable / similar SoC or core | <what reuses what | none - from scratch>  | ✅/⚠️  |
```

Under the table, give the session estimate from rows 6 and 7. If CERF supports
the SoC and its peripherals are reusable, the estimate is about 5-40 sessions.
For a new CPU or SoC, the estimate is about 40-100 sessions or more.

Then ask on a line of its own:

> Start the bring-up? `[yes|no]`

Stop and wait for the answer. Do not start work and do not create a document
before `yes`. If user pre-approved you may start. You also may suggest Skill(implement-device-goal) for a good /goal harness text.

## Phase D - Start

### D1 - Create the tracking document

The `yes` authorizes one `/tracking create`. Create an umbrella tracker for the
bring-up. Put these items in it:

- In `TASK & WHY`: the board, its bundles, and the reason for the bring-up.
- A standing `VERIFY GATE` line: "A chunk is the guest routine at the PC of a
  halt line, run to its end. Each chunk passes `/verify` before the next chunk
  starts. Record the verdict in the `/tracking update` of that session, under
  CODE STATE, verbatim with file:line. Never skip the gate on a JIT, MMU or CPU
  change."
- A standing `PROCEDURE` line: "Follow
  `.claude/skills/implement-device/SKILL.md` § The bring-up loop." Copy the
  steps and the chunk rules of the loop under that line.
- `Session 0`: the readiness table of Phase C, verbatim. The work starts at
  Session 1.

### D2 - Make the first run

Run each bundle of the task on the untouched tree. Do not edit a file before
this run. The first halt line of this run names chunk 1. Then follow § The
bring-up loop from step 2.

## The bring-up loop

CERF halts when the board needs something that CERF does not have. The halt
line in the log names that thing: a board id, a service, or a physical address
with a guest PC.

A halt line opens a chunk. Its task is the guest routine at the PC of the
halt, run to its end, together with the routines that it calls. The chunk ends
when the halt leaves that routine. A halt line with no guest PC, such as a
board id or a service, opens a chunk for that one item.

1. Run the bundle.
2. Find the first halt line in the log. Write that line in your reply before
   you edit a file.
3. Read the guest routine at the PC of the halt, from its entry to its return.
   Also read the routines that it calls. List every register and every unit
   that they read or write. That list is the chunk. For a physical address,
   find the peripheral block of each register in the memory map of the
   datasheet.
4. Research the items of the list only. Read the manual entry of each one and
   the guest code that touches it. Save the excerpt that you cite under
   `references/<soc>/`.
5. Implement every item of the list fully.
6. Build. Make sure that the build succeeded.
7. Run the bundle again. If the new halt line is still inside the routine, the
   list missed an item. Add the item to the list. Then go to step 4.
8. When the halt line leaves the routine, run `/verify` on the chunk. Correct
   each `CRITICAL PROBLEM FOUND`. Repeat until the verdict is `LEGIT`.
9. Go to step 2 with the new halt line.

Continue until the guest shows its GUI. Then continue until the user can
operate the device.

Chunk rules:

- Do not create or edit a file that the current chunk does not ask for.
- Do not research an item that the routine of the current chunk does not touch.
- Do not write code for the next chunk before the current chunk is `LEGIT`.
  The user wipes a working tree that mixes chunks.
- If two rules conflict on the current chunk, settle the conflict from the guest
  and agent_docs in the same turn.
- Never mix two chunks unless the work requires it.

The rule "implement all checklist steps as one body of work" in
`agent_docs/workflow.md` § Scope Rules does not apply to a bring-up.
