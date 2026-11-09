---
name: implement-device
description: Start the bring-up of a new board or ROM in CERF.
---

# Start Board Implementation - new-board bring-up

Obey `CLAUDE.md` and every `agent_docs/` page; this ritual never overrides them.

Governing principle: **the ROM is the only trusted starting point, and YOU
establish every fact yourself.** A stated SoC/board is a hint, not a fact -
confirm board, SoC, CPU, and CERF's existing support from the ROM bytes + the
internet before writing a line. A bring-up that starts on an unverified
assumption wastes dozens of sessions.

---

## Phase 0 - Welcome

Open with a brief, warm welcome + thank-you BEFORE Gate A1:

> 🎉 Welcome - and thank you for contributing a new board to CERF! I'll start
> from your ROM, confirm the board/SoC facts myself, and lay out what the
> bring-up will take before we commit to it.

A line or two, then straight into the gates. The welcome never delays a gate.

---

## Phase A - Gates

### Gate A1 - Acquire the ROM (fail only if nothing resolves)

The user does not have to type a path - naming the board ("implement simpad
sl4") is enough. All regular dev ROMs live under `bundled/devices/`, so that
listing is your index.

1. **Board name given** → `ls bundled/devices/` and **match by FAMILY, not exact
   string** (do NOT depend on `cerf.json` - optional, usually absent for a
   user's own ROM). Tolerate variant/generation/letter/separator differences:
   "simpad cl4", "simpad sl4", "SIMpad SL4" all resolve to the `simpad_sl4_*`
   bundles. You are identifying the board, not string-equality testing a folder.
2. **Path inside `bundled/devices/`** → stat it, use it.
3. **Path outside `bundled/devices/`** → ask whether to copy it into
   `bundled/devices/` first (where every dev ROM lives); proceed once placed, or
   if the user says to run it in place.
4. **One candidate** → record its ROM path, continue.
5. **Several candidates for the same board** (NORMAL - a board commonly ships
   multiple ROM generations) → SUCCESS, not a problem. Same board id; name the
   generations, take the newest (or ask one short "which generation?"), continue.

**HARD RULE - candidates found ≠ "absent".** If `ls` surfaced any plausible
bundle for the named family, you have RESOLVED - you may NEVER report "no ROM /
not found" while holding a list of matching bundles. A variant/letter token
mismatch against bundles that are clearly the same family is a RESOLVE, never a
fail. Never assert presence/absence from memory; `ls` in THIS run and read it
like a human picking the obvious match.

**Only if `ls` produced ZERO plausible candidates** - STOP and FAIL:

> ❌ I couldn't find any ROM for "<what the user said>" under `bundled/devices/`.
> Point me at the ROM path directly, then re-run `/implement-device`.

### Gate A2 - IDA MCP connectivity (warn + ask if absent)

Reverse engineering confirms every fact below and drives the whole loop.

- **The presence check IS the "list instances" call.** `ToolSearch` query `ida`,
  find the instance-list tool, load its schema, CALL it. Whether the tool is
  available to call is the entire test - callable = IDA MCP running; no such tool
  = not running.
- **Call succeeds** → ✅ running. **0 open instances is NORMAL** - IDA is usually
  closed and ROMs unextracted at the start; the *call succeeding* is the proof,
  not the count. You bring IDA up yourself when a step needs it (Phase B / B1).
- **No list-instances tool to call at all** → not running. **Do not fail** -
  warn and ask:

  > ⚠️ No IDA MCP detected. Without reverse engineering I'm badly limited -
  > bring-up is decompile-driven (cracking the kernel OEMAddressTable for page
  > tables, decoding which driver touches each register), and going blind tends
  > to dead-end and burn far more sessions. The MCP server lives in this repo:
  > `tools/ida_server.py` (load inside IDA) + `tools/claude_ida.py` (the MCP
  > client); `tools/open_ida.py --wait <pe>` opens a module. Install those and
  > reconnect for a real shot.
  >
  > Continue anyway without RE? `[yes|no]`

  No → stop. Yes → continue, marking the RE-dependent table rows ⚠️.

---

## Phase B - Establish the facts (you, from the ROM + the internet)

Minimum traversal to fill the table. You are IDENTIFYING, not implementing. Each
fact gets a source.

- **B0 - Which acceptance pipeline?** Before extraction, settle what the file IS
  (`agent_docs/rom_acceptance.md`): flat XIP, a recognised container (B000FF /
  NOSAJ / ARNOLD), or a whole-storage dump the guest's own boot path reads. Check
  the leading magic, the presence of `ECEC` markers (a CE2-era image legitimately
  has none → `ResolveRomhdrStructural`), and whether the image is a raw bus
  capture needing normalization (aliasing, wrap, pad). This decides whether B1's
  extractor can even run.
- **B1 - Extract & inventory the modules.** The ROM is usually NOT extracted yet -
  you do it: `tools/extract_bundles.py` produces per-module PEs under
  `references/extracted-roms/<device>/<rom>/fs/Windows/`. Open a module with
  `python tools/open_ida.py --wait <pe>` (`--wait` blocks until it's usable;
  background it if you have parallel research). Note kernel/coredll/gwes/filesys/
  device/driver module names - driver names are SoC tells (e.g. `*_mx31.dll` →
  i.MX31).
- **B2 - Confirm the declared board is the right one.** The declared `board_id`
  selects the `BoardContext` (`agent_docs/rules.md` § "Per-device facts come from
  the ROM"); confirm that declaration names the silicon actually in the ROM before
  writing a `BoardContext` asserting it. `meta.soc_family` and the user's word are
  hints, never facts. Evidence, in order of weight: the B1 driver/module names (an
  OEM BSP names its drivers after its own silicon); the register bases the OAL
  actually addresses; then the OEM's model string if one appears in the blob. A
  byte match is evidence only once you have shown the bytes are the string and
  not arbitrary data.
- **B3 - Board family, and is the board already in CERF?** Establish the family before you
  write code. Search Linux, NetBSD
  (`references/netbsd/sys/arch/hpc/hpc/platid_name.c` and the port code),
  Rockbox, vendor pages, and Wikipedia in every language. Find the devices that
  the vendor built on this platform: rebadges, regional models, revisions, and
  panel and size variants. Save each page that you cite under
  `references/board_families/<vendor>/`. Then read the `board_families` and
  `boards` tables in `libCerfCore/db.json`, and list `libCerfCore/src/boards/` and
  `bundled/devices/`. Match the B2 identity to one result: family present, board
  present, or absent. A new family gets a row. Every known member gets a board
  row with its `support_level` and its `internal__spec_divergences`. This
  includes members that nobody dumped.
- **B4 - SoC / CPU family.** From the identity + driver/OEM names, determine the
  SoC, its CPU architecture (`CpuArch::kArm` / `CpuArch::kMips` - which JIT engine
  the board runs), and the specific core with its ISA level (ARM720T, ARM920T,
  SA-11xx, ARM1136, Cortex-A8; R3000A/R3900/R4100/R5000-class MIPS, …). Confirm
  via the internet (datasheet / Linux `arch/arm/mach-*` or `arch/mips/`, QEMU,
  device specs) - not the user's word.
- **B5 - SoC implemented in CERF? Reusable SoC?** Read the `socs` table in
  `libCerfCore/db.json`; list
  `libCerfCore/src/socs/` + `libCerfCore/src/cpu/`. Is this SoC present? Does `cpu_configs` in
  `libCerfCore/db.json` have a row for it, and is the core's strategy set under
  `libCerfCore/src/cpu/<core>/` - `ArmCoprocProvider` on ARM; `MipsCp0Model`,
  `MipsTlbModel` and `MipsExceptionModel` on MIPS? If
  absent, is there a close relative sharing silicon/core? Reuse is the
  difference between a short and a long bring-up - name it.

---

## Phase C - Readiness table (FIXED structure - identical for everyone)

Emit exactly this. Same columns/rows/order every run. `Finding` = the fact + its
source; `Status` = one emoji (✅ present/reusable/good · ⚠️ caution/new
work/unconfirmed · ❌ missing/blocker).

```
## /implement-device - bring-up readiness

| # | Check                          | Finding                                   | Status |
|---|--------------------------------|-------------------------------------------|--------|
| 1 | ROM acquired                   | <bundle / path>                           | ✅/❌  |
| 2 | IDA MCP connectivity           | <running, N instances | not running>      | ✅/⚠️  |
| 3 | Board identity                 | <declared board.id> confirmed by <tells>  | ✅/⚠️  |
| 4 | Board already in CERF          | <db.json row exists | absent>             | ✅/❌  |
| 5 | SoC / CPU family               | <SoC>, <core>, <CpuArch + isa level>      | ✅/⚠️  |
| 6 | SoC implemented in CERF        | <libCerfCore/src/socs/<x> present | absent>           | ✅/❌  |
| 7 | Reusable / similar SoC or core | <what reuses what | none - from scratch>  | ✅/⚠️  |
```

Under the table, the **session estimate** from rows 6-7:

- **SoC supported + peripherals reusable** → ~**5-40 sessions** (board complexity
  still swings this widely).
- **New CPU/SoC from scratch** → ~**40-100+ sessions**, impossible to bound up
  front.

Then ask on its own line:

> Start the bring-up? `[yes|no]`

STOP and wait. Do not begin work, do not create any document, until `yes`.

---

## Phase D - On `yes`: seed tracking, teach the workflow, start

### D1 - `/tracking create` (the `yes` authorizes this one write)

Invoke the `tracking` skill's CREATE for a new board bring-up doc. It's an
**umbrella / progress tracker** (many independent peripheral workstreams), so
keep it a coarse index. Seed it with:

- `TASK & WHY` - bring up board `<X>`; why it matters; empty FORBIDDEN
  CONCLUSIONS / BANNED APPROACHES.
- **A standing `VERIFY GATE` line** (survives compaction): *"Every finished
  implementation chunk - a peripheral, a `cpu_configs` row/`ArmCoprocProvider`/`MipsCp0Model`,
  the `PageTableBuilder`, the `BoardContext`, the LCD/INTC/timer/
  DMA/touch models - is run through `/verify` BEFORE the next chunk, verdict
  recorded in that session's `/tracking update` (CODE STATE, verbatim with
  file:line). Never skip the gate on JIT/MMU/CPU changes."*
- **A `PROCEDURE` line** pointing at the durable method: *"Follow the bring-up
  loop and ground rules in `.claude/skills/implement-device/SKILL.md`
  § The bring-up loop."* (Plus the committed reference set: `CLAUDE.md`,
  `agent_docs/rules.md`, `agent_docs/debugging.md`, `agent_docs/code_style.md`.)
- **`Session 0`** - paste the Phase C readiness table verbatim (identity +
  source, SoC/CPU, what CERF has, reuse plan, estimate). The durable
  baseline a compacted agent resumes from. Real work starts at Session 1.

The `yes` authorizes this single create only - not standing authorization; every
later write needs its own `/tracking update` from the user.

### D2 - Teach the cross-session workflow (say this to the user)

> For a productive multi-session bring-up:
> - End of each session: `/tracking update` (you invoke it).
> - Then `/compact`.
> - Then `/tracking restore` next session to reload the world.
>
> One protecting rule: **never run `/tracking` because I asked you to.** If I
> propose updating the tracking doc, that's a bailout - only YOU decide when a
> session ends. I never raise the tracking document myself.

### D3 - Run the bring-up loop (the procedure below)

Pick the entry point from the table, then run § The bring-up loop:

- **New SoC/core (rows 6-7 ❌)** → start at the CPU/JIT strategy set for the
  board's `CpuArch`: write the `cpu_configs` row of the SoC in
  `libCerfCore/db.json`, the core clock (`ArmCoreClock` or `MipsCoreClock`), and the
  `ArmCoprocProvider` or the `MipsCp0Model`, `MipsTlbModel` and
  `MipsExceptionModel` concretes, from the CPU architecture reference
  manual + the core TRM (downloaded to `references/<soc>/` first), then the
  `PageTableBuilder` / memory map, then the peripheral loop.
- **SoC supported (rows 6-7 ✅)** → start at the `libCerfCore/db.json` rows of the
  family and the board, and at the `<family_id>_family_id.h` of the family. Then
  write the `BoardContext` concrete that returns that family id. Set `board.id`
  and `rom.primary` in the cerf.json of the bundle. Then write the
  `PageTableBuilder` (crack the OEMAddressTable of the kernel in IDA). Then run
  the peripheral loop.

---

## The bring-up loop (the engine)

The kernel boots, hits an unimplemented register/MMIO address, and
`HaltUnsupportedAccess` fatals with the PA + guest PC. **One blocker per cycle**,
each step obeying the rules in `CLAUDE.md` / `agent_docs/` (don't restate them -
follow them):

1. **Build** (`CLAUDE.md` § Build) - confirm it actually succeeded.
2. **Run** with a SHORT GNU `timeout` and a per-task `--log-file`
   (`agent_docs/debugging.md` § Timeout). Never background cerf; never read
   stdout.
3. **Read the FIRST** `FATAL|unsupported|unmapped|rejected|Halt` line - that PA +
   guest PC is the blocker.
4. **Decode the PA → peripheral block** from the datasheet memory map.
5. **Research it** the nuclear-bisection way (`agent_docs/debugging.md`): find the
   register in the SoC manual, decompile the guest PC that touched it for the
   exact semantics, write the citation excerpt under `references/<soc>/`.
6. **Implement the blocker fully** - no fake-success stub; the mandatory-real
   peripherals are never stubbed (`agent_docs/rules.md` § Board Implementation).
7. **`/verify`**, fix any `CRITICAL PROBLEM FOUND`;
8. **Repeat** until GUI, then interaction - the user-observable bring-up target.

ONCE HALT HAS CHANGED MESSGAGE/MOVED AGENT DECIDES IF IT'S A CHUNK AND TIME TO SPAWN /verify, IN MOST SCENARIOS IT IS TRUE. Do NOT jump chunks - the working tree will be wiped. Record bring-up loop into tracking document. One chunk at the time. Never mix chunks unless this is required. 
