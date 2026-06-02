# Debugging — v2

CERF's host-side surface is virtual hardware: peripherals, MMU, JIT, ROM
loader. CE-side code is real ARM running through the JIT. Crashes
therefore land in one of a small number of shapes. This page is the
playbook for each.

## Core workflow — Nuclear bisection (MANDATORY, NO DEVIATIONS)

When CERF behaves wrong: **breakpoint everything, theorize nothing.**
Theories, guesses, hypotheses, "I think the bug is X", "this is most
likely Y", numbered lists of candidate causes — all forbidden. The
only valid output of an investigation is a hook that fired (data) or
a hook that didn't fire (also data). Anything else is commentary; do
not produce it.

The method is mechanical: install a hook on every candidate, run, see
which fire, narrow. Repeat until the dead branch is named in the log.
No step is skippable. "I already know what it is" is never permitted
to replace a hook — write the hook anyway.

### New session? Compaction? Lost context?

Then see what trace hooks you created in previous session(s). See all pre-existing hooks.
If you are working on a problem accross multiple session (basically on any problem)
then most likely you already hooked the entire path. 

If it's at least the second session you are continuing working on a problem,
propose (strongly recommended) user to create a tracking document, otherwise
in 3rd session you will drift and do literally everything you did in 1st session.

This entire section exists to prevent you from drifting into rediscovery/destruction path.
If you are working for more than 1 session on the problem, it most likely already has 
tons of debugging details stored. Never rediscover. Never destroy wallet to repeat entire
debuggin setup session. Ask user if he has a tracking document for current bug. Always
check pre-existing tracing setup so you don't accidentally spend huge money
to setup tracing hooks which already exist.

### The reference is the guest binary — you ALWAYS have one

The ground truth for "what is correct" is the guest binary itself. Every
ROM module — kernel, drivers, the app — ran on real hardware, so its code
IS the spec: at each function the decompiled guest states exactly what
value it expects CERF's virtual hardware to return, and every binary is
open in IDA. There is no captured hardware trace and none is needed — so
**"I have no reference" / "I'd need a real-hardware trace or a TX log" is
never true and never a stop condition; it is a bailout.** Diff CERF's
behavior against the guest code, not against any external capture.

The method is always nuclear bisection: drill into the last function,
deeper through each layer / binary / library, hooking each candidate,
until the single dead branch is named. The divergence is the first hop
where CERF returns a value the guest code does not expect — a wrong
register read, MMU/translate result, API return, or memory value — found
by comparing CERF's actual value to what the decompiled guest at that hop
expects.

**The dead branch is always a CERF defect** — a JIT, MMU, or peripheral
bug, or (rarely) a ROM-placement bug. It is never "the real device would
fail here too" / "the app is buggy"; the ROM shipped and worked on
hardware (`agent_docs/rules.md` § "Bug reports describe verified
real-device behavior").

The layer is almost never simple and almost always far deeper than it
looks. A symptom like "the app asked to render and nothing painted" rarely
bottoms out in the top-level library it entered — it bottoms out many
layers down in a DRIVER reached through complex PSL traps and indirection.
For example, a blank UI can trace down to an on-screen-keyboard driver
whose parse hits a JIT defect — nowhere near where the draw call started,
and not in any imported library directly. Reaching that depth is
mechanical and strict: drill the LAST function deeper, one layer at a
time — resolve each PSL trap the ROM uses, identify each wait object and
what signals it, hook to learn where a stall/WSO actually originates,
follow the call into the next function and the next binary. Never jump
sideways to a different surface and never theorize a cause. Each new layer
is progress, never a stop — drill the last functions until the one dead
branch is named.

### Steps

1. **Find the divergence.** Diff CERF's runtime output against the
   reference. Identify the last common line and the first missing
   line CERF never produces. That gap is your target. For UART
   divergence specifically, grep `cerf.log` for `[SOC_UART] UART1
   TX:` lines and compare line-for-line.

2. **Name the suspect chain in IDA.** Map the first missing line
   back to the function that emits it. Walk callers / branches up
   the chain (`ida_decompile`, `ida_get_xrefs`) until you have a
   list of every function and decision point between "last known
   good" and "first missing." **Don't filter the list by
   likelihood — list everything.**

3. **Install one TraceManager `OnPc` hook per candidate** in a
   trace file under `cerf/tracing/<bundle>/` (see § TraceManager
   below). `tm.OnPc(addr, handler)` per function entry. Tag names
   must be unique and grep-friendly. Capture R0..R3, LR, SP at
   minimum — the input arguments and the caller. **Hook the WHOLE
   chain. Do not prune to "likely culprits."**

4. **Build, run with a SHORT timeout.** Use GNU `timeout` in the
   command itself (`timeout 15s ./cerf.exe ...`), never the Bash
   tool's timeout parameter — it doesn't kill the cerf child and
   orphans the process. Boot-time bugs are visible within seconds.

5. **Read the fires.** `grep "<your_tag>" cerf.log`. The hook that
   fired LAST + the hook below it that NEVER fired defines the
   dead-branch boundary. The function whose hook didn't fire is
   the call you didn't reach.

6. **Drill into the last-fired function.** Decompile its body in
   IDA. List every helper call it makes (RegOpenKey wrappers,
   enumerators, value reads, alloc/load helpers, callback
   dispatchers). Hook every one. Don't be selective.

7. **Build, run, read fires. Repeat.** Each iteration narrows the
   dead range. Keep going until the dead branch is a single
   conditional. At that point the broken state is named and the
   investigation can pivot to fixing the cause (peripheral
   missing, registry mis-encoded, MMU mapping wrong, etc.).

### Discipline

- **Hook every candidate, not just the "likely" ones.** Speculation
  about which branch is broken wastes iterations. Hooking 10
  functions is 10 lines of C++; guessing wrong is a full build +
  run cycle.
- **A hook that never fires is data.** It tells you the branch was
  never taken. Don't dismiss it — it's the answer.
- **Theories / hypotheses / "most likely…" lists are forbidden
  investigation output.** See `agent_docs/rules.md` § "Hypothesis
  enumeration is forbidden investigation output". When evidence is
  not available, name the missing hook and add it. Do not fill the
  gap with a numbered list of guesses.
- **Cosmetic differences** (e.g. `Revision=0` vs `Revision=1`) can
  be noted but are usually downstream of the real bug. Focus on
  the first place CERF stops producing output the reference
  produces.
- **Don't bury fires in log noise.** Spammy LOG sites that print
  every register read/write of a peripheral drown out the trace
  fires. Move high-frequency state observation into a trace file
  (gated by bundle CRC32, excluded from production); permanent
  LOGs are for low-frequency milestones only.

### Example shapes (concrete forms of the same method)

- **Stack overflow?** PC hook every function in the suspected
  chain. The one whose fire count reaches hundreds is your
  recursion.
- **Infinite loop?** PC hook the entry of every function that
  could loop. The one that floods the log is your loop.
- **Wrong value?** Hook `OnPc` at the writer instruction (find it
  in IDA via a memory-write xref to the field), read the value via
  `c.ReadVa8/16/32(va)` inside the handler. The PC at which the
  value changes from correct to wrong is your bug. There is no
  `OnRead` / `OnWrite` primitive — see `subsystems.md` § TraceManager
  for why.
- **Missing call?** PC hook the function that should be called.
  No fire = trace backwards by hooking its expected caller.
- **Any mystery?** Add hooks. Run. Read. The answer is always in
  the data, never in your head.

## Logs are the source of truth

- **`cerf.log`** sits next to `cerf.exe`. Every category logs verbosely
  by default. Read it for every investigation. `--quiet` disables it
  for perf runs only.
- **`cerf.crash.log`** is written by the lock-free emergency writer on
  a fatal crash. Contains every other thread's RIP / RSP / RBP and a
  16-slot stack snapshot at the time the dying thread aborted. Use it
  when the FATAL message comes from a thread whose state you need to
  cross-reference with another thread.
- Stdout / stderr are NOT a source of truth — frequently truncated.
  Always read the file.

Filtering log channels with `--log=Boot,Mmu,Periph` (etc.) helps
narrow output during a long boot, but `--log=ALL` (default) is what
you want when a crash already happened — read the tail and grep
upward.

## Timeout selection for cerf runs

CERF runs MUST use GNU `timeout` in the command itself
(`timeout 15s ./cerf.exe ...`). Picking the right number is part of
the diagnostic, not an afterthought — too short and you miss the
target; too long and every iteration wastes user budget on idle
guest-time after the target already fired.

### Choosing the initial number

Base the timeout on **when the target data is expected to appear**,
not on a generic round number. The rule:

- If the latest observed target timestamp is `t+12s`, use **15-20s**,
  not 60s.
- If the target hasn't been observed yet, pick the smallest
  reasonable upper bound from a sibling milestone — a related log
  line that appeared at `t+8s` in a prior run → use ~15s.
- A timeout that worked for one investigation is **a target-specific
  baseline**, not a default. The number for "boot far enough to see
  X" is generally not the number for "boot far enough to see Y".

A run that ends at 60s when the target fired at t+12 wasted 48s of
guest time × N runs × however many sessions. Pick small numbers.

### Single failure = re-run, not bump

A run missing its target at the chosen timeout is data, but data of
two possible shapes:

- **Variance** — boot timing varies run-to-run (scheduler decisions,
  libslirp, peripheral cadence, host-clock jitter). A single missed
  target on a previously-working timeout is most likely variance.
- **Regression** — recent code or diagnostic changes added overhead
  so each host second produces fewer guest seconds.

You cannot distinguish these from one run. **Re-run with the same
timeout.** If 2-3 re-runs in a row miss the target, it's a
regression, not variance.

### Bumping the timeout

A bump must satisfy ALL of:

- **Evidence of forward progress at the cutoff** — the log's last
  entries show the guest still executing (peripheral writes, JIT
  compile lines, new progress markers), not parked (idle loops,
  the same peripheral register being polled with no other activity,
  no new milestones for several seconds). If the guest went idle
  before the cutoff, more time gives it more time to stay idle;
  find the idle cause first.
- **Tiny increment: +5s.** Not +10, not +30, not +60, not "let's
  just try 120". The increment is small enough that the next run's
  log immediately tells you whether it was enough.
- **The bump is a hypothesis to verify.** After the bumped run, read
  the log and confirm the new cutoff actually fell past where the
  target should have fired. If it didn't, the bump was wrong AND
  there's a slowdown to investigate separately.

### Forbidden values and patterns

- Any **single bump ≥1.5× the working baseline** (65→90, 60→120, 30→60).
- Any **round abnormal value picked without log evidence** (90s,
  120s, 180s, 300s, 600s, 1h, "let's try a minute", "ten minutes").
- Repeatedly bumping by +5 until the run succeeds — that's laziness
  in slow motion. After 2-3 +5 increments without reaching the
  target, stop bumping and investigate the slowdown.

### Diagnosing slowdown instead of bumping

If repeated runs at the working baseline consistently miss the
target, the response is **find what slowed down**, not extend the
window. Read the log's last few seconds and ask: is the guest
making forward progress, or is it idle / spinning / waiting?

- **Idle / waiting** — find what it's waiting for. An interrupt
  that didn't fire, a peripheral that didn't respond, a kernel
  primitive blocking on an event that never gets signalled.
- **Forward progress but slower than before** — the recent change
  added per-instruction or per-iteration overhead. Bisect the
  change, profile, or remove the heaviest contributor.

Once the slowdown is fixed, re-run at the original timeout. The
target should now fire within it.

## Crash shape #1 — guest hits an undecodable ARM instruction

The JIT decoder couldn't translate an instruction at some guest PC.
v2 doesn't halt CERF in this case; `ArmCpu::RaiseUndefinedException`
vectors the guest into its own Undefined-mode handler at vector 0x4
and the guest decides what to do (most CE kernels fault the
offending thread). The symptom on the CERF side is therefore a
guest-side fault / hang / wrong behavior, not a `[FATAL]` line. To
catch it early, hook the Undefined-exception path in the JIT (set
`OnPc` at `ArmCpu::RaiseUndefinedExceptionHelper`'s entry) and log
the offending PC + insn bytes. The instruction bytes at `pc` are
not what the kernel or driver expects to be there. **Almost always
not a JIT bug** — the bytes at that PA in DRAM are wrong because
something corrupted them.

Investigation:

1. Convert `pc` to its corresponding PA via the SoC's `VaToPa` mapping
   (or directly if the kernel was running PA-mode pre-MMU).
2. Identify which module was loaded at that PA. The CERF ROM parser
   logs its module list with load VAs during boot — grep cerf.log
   for the boot trace and find the module whose
   `load_va` ≤ `pc` < `load_va + vsize`. The decomposed-for-IDA tree
   under `references/extracted-roms/<device>/<rom>/fs/Windows/` is
   useful for cross-checking the same module's PE bytes.
3. Open that module's PE in IDA (from
   `references/extracted-roms/<device>/<rom>/fs/Windows/<name>`) and
   disassemble at the corresponding RVA. The IDA bytes are the
   EXPECTED bytes.
4. Compare expected bytes vs `insn=0x…` in the crash. If they differ,
   something overwrote the module's `.text` after the kernel placed
   it in DRAM.
5. Most common causes: CERF's ROM parser placed wrong bytes at that
   PA (decompression bug, wrong `o32_dataptr`, wrong `o32_psize`),
   the kernel's own loader did the wrong thing with the `o32_rom`
   record, or runtime corruption from another module's write into
   that range.

## Crash shape #2 — MMU translation fault

```
[FATAL] Mmu translation fault on read|write|fetch vaddr=0xNNNNNNNN: <reason> (SCTLR=0x… TTBR0=0x… DACR=0x…)
```

Means: the kernel's page table walker (or CERF's MMU emulator) couldn't
resolve the VA to a PA. Either:

- The kernel is dereferencing a NULL or bogus pointer (genuine
  kernel-side bug surfaced by CERF being faithful).
- The kernel's L1 / L2 entries for that VA region are stale or absent
  (kernel hasn't mapped that VA yet, or expects CERF to have set
  something up that CERF didn't).

Investigation:

1. Note `SCTLR` bit 0 (M). If 0, MMU is off and VA == PA; the fault
   message uses identity. If 1, MMU is on and TTBR0 walks apply.
2. With MMU on: the L1 entry for `vaddr` is at `TTBR0 + (vaddr >> 20)
   * 4`. Read that PA via a diagnostic LOG to see whether the entry
   is present and what its type is (Section / Coarse / Fault).
3. Compare against what the kernel SHOULD have written. The kernel
   walks its own OEMAddressTable to populate L1 entries; check the
   OEMAddressTable inside the kernel binary (in IDA, or by reading
   bytes around the kernel's known OAT VA) for the expected (VA, PA,
   size) triplets.
4. If the fault is on a low VA (e.g. `vaddr < 0x10000`), it's a NULL
   deref in the kernel — find the function the kernel was running by
   looking at the recent UART output (kernel debug serial usually
   prints a function name shortly before crashing) and decompile it
   in IDA.

## Crash shape #3 — peripheral MMIO halt

```
[FATAL] EmulatedMemory::Translate unmapped 0xNNNNNNNN
```

or

```
[FATAL] <SocPeripheral>::<ReadWord|WriteWord> unsupported access at 0x…
```

Means: the kernel / OAL / driver tried to access an MMIO address that
no peripheral handles. Either:

- A peripheral block that exists on the real chip isn't emulated yet.
- A register offset within an emulated peripheral isn't handled by its
  read/write switch.

Investigation:

1. Decode the PA: top byte (`PA >> 24`) usually identifies the SoC
   peripheral block (e.g. S3C2410: `0x48xxxxxx` memctrl, `0x4A` intc,
   `0x4C` clkpwr, `0x4D` LCD, `0x50` UART, `0x53` watchdog, `0x56`
   ioport, `0x58` ADC, …). Per-SoC layout is in the chip datasheet
   under `references/`.
2. Locate the peripheral block in the chip datasheet and the matching
   BSP source (e.g.
   `references/WINCE600/PLATFORM/DEVICEEMULATOR/SRC/INC/<chip>_<peripheral>.h`)
   — what register sits at that offset, what does the OAL do with it.
3. Implement the register's read/write per the datasheet entry +
   matching BSP source. **Do NOT guess values.** No hacks; the
   datasheet entry must be visible above before you write the handler.

## Crash shape #4 — kernel debug serial says something useful

The OAL writes diagnostic strings to UART1. CERF's S3C2410 UART
peripheral routes those bytes to a `SocUart` channel line buffer and
logs each line. Search `cerf.log` for `[SOC_UART]` and `UART1 TX:` to
find the kernel's own boot trace, which often names the function that
crashed shortly before the fault.

If the kernel printed something like `OEMAddressTable = 0x00000000` or
`*pTOC->ulRAMFree changed in OEMInit` immediately before the fault,
that's the kernel telling you which structure is wrong. Look at the
parsed ROM values CERF placed in DRAM (boot trace in cerf.log shows
the published ROMHDR / TOCentry / `e32_rom` / `o32_rom` values) and
compare against the byte-for-byte reference at
`references/extracted-roms/<device>/<rom>/`.

## Adding diagnostics — discipline

**You may NOT write fix code until you have a log line identifying the
exact problem.** "I think X causes Y" is not enough. "LOG shows X
recurses to depth 999" is enough. "LOG shows value changes from A to B
at this point" is enough.

If you don't have evidence yet, add a `LOG()` at the suspected path
first and re-run. Build, run, read `cerf.log`. Repeat until the
mechanism is named in writing.

When your fix crashes:

- STOP editing, start investigating. Treat the new crash as a fresh
  investigation — read the crash log, decompile the crashing function,
  trace the data. Do not "tweak the fix" — that's the cascading-hack
  trigger. If your fix caused a crash, your understanding was wrong;
  go back to debugging.

## TraceManager — where bug-specific diagnostics belong

Permanent `LOG()` sites are for low-frequency state observation across
the codebase. Bug-specific diagnostics — register dumps at one
particular guest PC, value-change pollers, watches on one specific
guest VA, one-shot startup audits, function-entry fire-or-no-fire
bisections — belong in **device-specific trace files** under
`cerf/tracing/<bundle>/`, not in permanent code.

See `agent_docs/subsystems.md` § TraceManager for the framework's
hook surfaces (`OnPc`, `OnPcFiltered`, `OnRunLoopIter`) and how
device-specific files key off the bundle CRC32. **There is no
`OnRead` / `OnWrite` memory-watch primitive** — see subsystems.md for
the full reason; the short version is that page-level slow-path
exclusion altered guest IRQ delivery alignment enough to manufacture
Heisenbugs that did not exist in production CERF.

### `OnPc` / `OnPcFiltered` — picking a hook VA

`OnPc(va, handler)` triggers on every guest execution of `va`. The VA
is matched as-is — the JIT does the lookup, the handler fires.

**Kernel-VA hooks** (PC ≥ `0x80000000`) — kernel image, the `k.*`
kernel-mode twins, filesys/gwes/devmgr internals — are constant
across all guest processes. A hook here fires exactly when that
specific code runs. Pick this whenever you can.

**User-VA hooks** (low addresses, e.g. `0x11B68` for an EXE entry,
`0x40035C1C` for a coredll PSL stub) are not unambiguous: CE switches
the currently-running process's address space into the low VAs of
the active slot, so the SAME user-VA can resolve to DIFFERENT
physical pages depending on which process is on-CPU. Two EXEs whose
code happens to land at the same offset within their slot will both
fire your hook. The `LR` captured in the handler is also a user-VA
and has the same property — it doesn't identify the caller's process.

To filter a user-VA hook to a specific process, use
`OnPcFiltered(va, predicate, handler)`. The predicate runs at fire
time and returns `true` to admit the call. Typical predicate body:
read `emu.Get<ArmMmu>().State()->process_id & 0x7Fu` and compare
against the target process's slot. Acquiring the target's slot
number is CE-version-specific — observe it via a kernel-VA hook on
process creation in your trace file and store name → slot.

If a user-VA hook isn't strictly required, prefer a kernel-VA
chokepoint that uniquely identifies the caller. Examples that come
up often:

- `xxx_*` PSL trap landings in `k.coredll` (every user-mode call from
  any process funnels through here)
- `filesys.dll!FS_SignalStarted(dw)` — `dw` is the RunApps
  `Launch%NN` index, which uniquely names the launched EXE
- Per-subsystem kernel routines that take a `pProc` argument

These produce identifying data inline, without needing a per-process
filter.

**Duplicate-registration guard.** Two unfiltered `OnPc` at the same
VA halts CERF — registration is exclusive and surfaced at startup,
never silently stomped. `OnPcFiltered` instances at the same VA
coexist with each other and with one unfiltered handler; each
filtered handler is responsible for its own predicate-distinct
admission.

**Attribute a user-VA fire by instruction-byte signature when a
name/slot resolver can't be trusted.** A per-process (low) VA hook can
fire under any process whose code aliases that VA. When the resolver
that maps a fire to a process is unreliable, identify the firing
process by reading the runtime bytes at the hook PC (`c.ReadVa32`) and
matching them against each candidate module's extracted `.text` — each
module is byte-unique at a given VA, so the match is unambiguous where
a name lookup is not.

### When to use TraceManager vs. a permanent LOG

| You want to … | Where it goes |
| --- | --- |
| Log every call to a host C++ function with its args / state at the call site | Permanent `LOG(<chan>, ...)` at that call site |
| Log a host-side state transition that happens on a slow cadence (boot milestone, IRQ, mode switch) | Permanent `LOG(<chan>, ...)` at the transition |
| Watch a specific guest VA for write — to see when it changes | Trace file `tm.OnPc(writer_pc, ...)` at every writer instruction PC + `c.ReadVa8/16/32(va)` inside the handler |
| Watch a specific guest VA for value-change with unknown writers | Trace file `tm.OnRunLoopIter(...)` polling the value via `c.ReadVa8/16/32(va)` |
| Dump full register state every time a specific guest PC is reached | Trace file calling `tm.OnPc` |
| Poll a guest-memory value and log every change | Trace file calling `tm.OnRunLoopIter` |
| Dump a region of guest memory once at startup | Trace file calling `tm.OnRunLoopIter` with a one-shot flag |
| Permanent high-frequency LOG site (per-clock, per-register-access, per-instruction) | NEVER. High-frequency logs buried the actual UART TX bytes once already; an agent had to write a script to reconstruct them from `cerf.log`. Move to a trace file. |

### Adding a trace file

1. Pick a directory: `cerf/tracing/<bundle_human_name>/` (e.g.
   `cerf/tracing/wm5_smdk2410_devemu/`). Create it if it doesn't exist.
2. Add a `bundle.h` (or `<bundle>_bundle.h`) declaring
   `constexpr uint32_t kBundleCrc32 = 0x<actual>;`. To get the CRC,
   either run `python -c "import zlib; print(hex(zlib.crc32(open('path-to-rom.bin','rb').read())))"`
   (concatenate every loaded partition in load order if there's more
   than one), or just boot CERF once and read the `[TRACE] bundle
   CRC32 = 0x…` line.
3. Create a `.cpp` named after the investigation (e.g.
   `wm5_msh_handle_corruption.cpp`). Define one `Service` subclass
   whose `OnReady` calls `emu_.Get<TraceManager>().RegisterForBundle(
   kBundleCrc32, [&]{ ... });`. Inside the lambda, call `OnPc` and
   `OnRunLoopIter` as needed. Read memory inside handlers via
   `c.ReadVa8/16/32(va)` — there is no `OnRead`/`OnWrite`
   primitive.
4. `REGISTER_SERVICE(YourTraceClass);` at the bottom.
5. Build with `build.ps1` (default `-Mode dev`). The trace file is
   compiled in. `build.ps1 -Mode production` excludes the entire
   `cerf/tracing/<bundle>/` subtree from the build.

Trace files are committed and kept. They're gated by bundle CRC32
(silent no-op on any other bundle) and excluded from production
builds, so they cost nothing at runtime and serve as regression
alarms + documentation of the hooks that pinned each bug. Don't
delete them on a whim. Cleanup is a board-level operation done once
a board is fully implemented, not per-investigation.

## Reading cerf.crash.log effectively

The crash log is a thread dump. The crashing thread's RIP is in the
FATAL message; other threads' state is in the `=== All other threads'
state at crash (frozen) ===` block.

For each thread:

- `RIP` = where the thread was when frozen
- `RSP+0..78` = top 16 stack slots; 8-byte values that may be return
  addresses, args, or saved registers depending on calling convention
- Many threads will be in `WaitForSingleObject` / similar host-side
  blocking calls — those are normal worker threads, not interesting
- Threads with RIP inside CERF code (e.g. `0x00007FF7…` ranges that
  fall inside `cerf.exe`'s mapped image) are doing CERF work;
  cross-reference with the crashing thread's stack via `dbghelp`
  symbols if you need a host-side back trace

The crashing thread's own stack trace (the `[FATAL] [N]
FunctionName+0xXX` list) is at the bottom of `cerf.crash.log` — that's
your first read.

## IDA discipline

The kernel binary, every ROM DLL, and the per-SoC reference binaries
are loadable in IDA via MCP (`mcp__ida__*`). Use them. Decompile the
function at the crashing PC. Read the actual bytes, not what you
assume the bytes should be.

Per-module PEs live under
`references/extracted-roms/<device>/<rom>/fs/Windows/<name>`,
produced by `tools/extract_bundles.py` running
`references/extract-wince-rom` against each `.nb0` / `.bin` in
`bundled/devices/<device>/`. Matching PDBs from
`bundled/devices/<device>/pdbs/` are copied next to the modules
automatically, so IDA finds symbols without any extra step.
`references/extracted-roms/` is gitignored and persistent across
rebuilds — point IDA at it directly:

```
python tools/open_ida.py --wait references/extracted-roms/<device>/<rom>/fs/Windows/<name>
```

The `--wait` flag blocks until IDA finishes analysis and the MCP
server is registered.

**The extracted PEs are reconstructions, not runtime captures.**
`extract-wince-rom` rebuilds each module by placing its bytes at
link-time RVAs and appending a `.cerom` section; the result is faithful
for disassembly / decompilation but is NOT ground truth for PE
structure or for how the module looks in live guest memory after the
kernel loader maps it. Trust it for reading code, never for runtime
layout questions — to learn how it diverges from live memory, read the
extractor source rather than assuming the file mirrors the loader's
output.

Never run IDA from `build/` or `bundled/`. `build/` is wiped on
rebuild and IDA holds locks; `bundled/` is CERF's runtime input — an
`.i64` sidecar inside it would pollute the input tree.
