# Debugging - v2

CERF's host-side surface is virtual hardware: peripherals, MMU, JIT, ROM
loader. CE-side code is real guest code that runs through the JIT.
Crashes therefore have one of a small number of shapes. This page is the
playbook for each shape.

## Core workflow - Nuclear bisection (MANDATORY, NO DEVIATIONS)

If CERF behaves wrong: **breakpoint everything, theorize nothing.**
Theories, guesses, hypotheses, "I think the bug is X", "this is most
likely Y", and numbered lists of candidate causes are all forbidden. The
only valid output of an investigation is a hook that fired (data) or a
hook that did not fire (also data). Anything else is commentary. Do not
produce it.

The method is mechanical. Install a hook on every candidate. Run. See
which hooks fire. Narrow the range. Repeat until the log names the dead
branch. No step is skippable. "I already know what it is" never
replaces a hook - write the hook anyway.

### New session? Compaction? Lost context?

Then read the trace hooks you created in previous session(s). Read all
pre-existing hooks. If you work on a problem across multiple sessions
(basically on any problem), then most likely you already hooked the
entire path.

If this is at least the second session on a problem, propose to the user
that he creates a tracking document. This proposal is strongly
recommended. Otherwise, in the 3rd session you will drift and do
literally everything you did in the 1st session.

This entire section exists to keep you off the rediscovery and
destruction path. If you work more than 1 session on the problem, the
problem most likely already has tons of debugging details stored. Never
rediscover. Never destroy the wallet to repeat an entire debug setup
session. Ask the user if he has a tracking document for the current bug.
Always verify the pre-existing tracing setup, so that you do not
accidentally spend huge money to create tracing hooks which already
exist.

### The reference is the guest binary - you ALWAYS have one

The ground truth for "what is correct" is the guest binary itself. Every
ROM module - kernel, drivers, the app - ran on real hardware, so its code
IS the spec. At each function the decompiled guest states exactly what
value it expects CERF's virtual hardware to return. Every binary is open
in IDA. There is no captured hardware trace, and none is needed - so
**"I have no reference" and "I would need a real-hardware trace or a TX
log" are never true and never a stop condition. Both are a bailout.**
Diff CERF's behavior against the guest code, not against any external
capture.

Escalation to the user to *supply* the unobtainable is equally forbidden
- a real-device log, an NDA datasheet, or a request to buy, wire-tap, or
dump a physical unit. The boards CERF emulates are obscure and often
unpurchasable. The user has no such artifacts and cannot get them, and
such a request is a bailout that stalls the work. The guest binary in
IDA plus public datasheets, Linux, and QEMU are the complete reference
set. If a fact is not in them, decompile harder. Never escalate to
hardware.

The method is always nuclear bisection. Drill into the last function,
deeper through each layer, binary, and library. Hook each candidate.
Continue until the single dead branch is named. The divergence is the
first hop where CERF returns a value the guest code does not expect - a
wrong register read, MMU/translate result, API return, or memory value.
You find the divergence when you compare CERF's actual value to the
value the decompiled guest expects at that hop.

For a documented standard off-chip part (codec, NIC, PMIC), split the
labor. Use the guest driver only to pin WHAT it requires - the register
or bit it polls, the dead branch. Then ground the part's register map
and bit semantics in its datasheet, the Linux driver, and QEMU. Do not
reverse-engineer the whole part from the guest.

**The dead branch is always a CERF defect** - a JIT, MMU, or peripheral
bug, or (rarely) a ROM-placement bug. It is never "the real device would
fail here too" or "the app is buggy". The ROM shipped and worked on
hardware (`agent_docs/rules.md` § "Bug reports describe verified
real-device behavior").

The layer is almost never simple and almost always far deeper than it
looks. A symptom like "the app asked to render and nothing painted"
rarely ends in the top-level library it entered - it ends many layers
down in a DRIVER reached through complex PSL traps and indirection. For
example, a blank UI can trace to an on-screen-keyboard driver whose
parse hits a JIT defect - nowhere near where the draw call started, and
not in any imported library directly. To reach that depth is mechanical
and strict. Drill the LAST function deeper, one layer at a time. Resolve
each PSL trap the ROM uses. Identify each wait object and what signals
it. Hook to learn where a stall or WSO actually originates. Follow the
call into the next function and the next binary. Never jump sideways to
a different surface, and never theorize a cause. Each new layer is
progress, never a stop - drill the last functions until the one dead
branch is named.

### Steps

1. **Find the divergence.** Diff CERF's runtime output against the
   reference. Identify the last common line and the first missing
   line CERF never produces. That gap is your target. For guest
   debug-output divergence specifically, grep `cerf.log` for
   `[NKDBG]` lines and compare line-for-line.

2. **Name the suspect chain in IDA.** Map the first missing line
   back to the function that emits it. Walk callers / branches up
   the chain (`ida_decompile`, `ida_get_xrefs`) until you have a
   list of every function and decision point between "last known
   good" and "first missing." **Do not filter the list by
   likelihood - list everything.**

3. **Install one TraceManager `OnPc` hook per candidate** in a
   trace file under `cerf/tracing/<bundle>/` (see § TraceManager
   below). `tm.OnPc(addr, handler)` per function entry. Tag names
   must be unique and grep-friendly. Capture R0..R3, LR, SP at
   minimum - the input arguments and the caller. **Hook the WHOLE
   chain. Do not prune to "likely culprits."**

4. **Build, run with a SHORT timeout.** Use GNU `timeout` in the
   command itself (`timeout 15s ./cerf.exe ...`), never the Bash
   tool's timeout parameter - it does not kill the cerf child and
   orphans the process. Boot-time bugs are visible within seconds.

5. **Read the fires.** `grep "<your_tag>" cerf.log`. The hook that
   fired LAST + the hook below it that NEVER fired defines the
   dead-branch boundary. The function whose hook did not fire is
   the call you did not reach.

6. **Drill into the last-fired function.** Decompile its body in
   IDA. List every helper call it makes (RegOpenKey wrappers,
   enumerators, value reads, alloc/load helpers, callback
   dispatchers). Hook every one. Do not be selective.

7. **Build, run, read fires. Repeat.** Each iteration narrows the
   dead range. Continue until the dead branch is a single
   conditional. At that point the broken state is named, and the
   investigation can pivot to the correction of the cause
   (peripheral missing, registry mis-encoded, MMU mapping wrong,
   and more).

### Discipline

- **Hook every candidate, not just the "likely" ones.** Speculation
  about which branch is broken wastes iterations. 10 hooks on 10
  functions are 10 lines of C++. A wrong guess is a full build and
  run cycle.
- **A hook that never fires is data.** It tells you the branch was
  never taken. Do not dismiss it - it is the answer.
- **Theories / hypotheses / "most likely…" lists are forbidden
  investigation output.** See `agent_docs/rules.md` § "Hypothesis
  enumeration is forbidden investigation output". When evidence is
  not available, name the missing hook and add it. Do not fill the
  gap with a numbered list of guesses.
- **Cosmetic differences** (for example `Revision=0` vs
  `Revision=1`) can be noted, but they are usually downstream of
  the real bug. Focus on the first place where CERF no longer
  produces output that the reference produces.
- **Do not bury fires in log noise.** Spammy LOG sites that print
  every register read and write of a peripheral hide the trace
  fires. Move high-frequency state observation into a trace file
  (gated by bundle CRC32, excluded from production). Permanent
  LOGs are for low-frequency milestones only.

### Example shapes (concrete forms of the same method)

- **Stack overflow?** PC hook every function in the suspected
  chain. The one whose fire count reaches hundreds is your
  recursion.
- **Infinite loop?** PC hook the entry of every function that
  can loop. The one that floods the log is your loop.
- **Wrong value?** Hook `OnPc` at the writer instruction (find it
  in IDA via a memory-write xref to the field). Read the value via
  `c.ReadVa8/16/32(va)` inside the handler. The PC at which the
  value changes from correct to wrong is your bug.
- **Missing call?** PC hook the function you expect the guest to
  call. If no fire occurs, trace backwards and hook its expected
  caller.
- **Guest powers off / "deep sleeps" seconds after boot?** That IS a
  kernel panic - CE's PowerOffSystem / sleep path doubles as the
  unrecoverable-fault halt, and no device sleeps right after boot. Do
  NOT model it as suspend / resume. Hunt the fault that triggered it
  (heavy aborts, a lock timeout) through the guest debug output above.
  Invariants:
   - Your GPIO or something else emulates a power button hold
   - The emulated timer or clock is too fast and makes the OS go to the
     standard idle sleep mode
   - The emulated battery reports low power (this one is recurrent,
     complex to prevent, complex to debug)
- **Any mystery?** Add hooks. Run. Read. The answer is always in
  the data, never in your head.

## Logs are the source of truth

- **`cerf.log`** sits next to `cerf.exe`. Every category logs verbosely
  by default. Read it for every investigation. `--quiet` disables it
  for perf runs only.
- **`cerf.crash.log`** comes from the lock-free emergency writer on
  a fatal crash. It contains three kinds of data:
  - the recent `[CAUTION]` lines - the fatal reason and the guest
    register dump
  - every other thread's RIP / RSP / RBP with a 16-slot stack snapshot
    at the time the dying thread aborted
  - the last log lines, which `cerf.log` does not have

  Use it when the FATAL message comes from a thread whose state you
  must cross-reference with another thread.
- Stdout / stderr is flood-controlled and silently drops lines - it is
  NEVER a valid log source, and to read it is prohibited. Pass
  `--log-file=<repo>/tmp/<unique>.log` on every run and read ONLY that
  file. Verify that the file exists before you read it. If `--log-file`
  did not produce it, re-run with a corrected path. Never use stdout
  instead.
- **On every failure, scan the guest's own debug output with a WIDE net
  first.** Before you reverse-engineer, grep the log across all guest
  output channels - UART / serial TX and NKDBG / OEM-debug strings - for
  the guest's self-reported diagnosis: exception / abort register dumps,
  semaphore / lock timeouts, power-off / "deep sleep", panic banners.
  Re-scan after each failed run. A pre-narrowed keyword filter
  (`abort|exception` only) hides the very line that names the failure -
  dump the distinct message vocabulary (collapse high-frequency noise)
  and read what the guest actually says.

A filter on log channels with `--log=Boot,Mmu,Periph` (and more) helps
to narrow the output during a long boot. If a crash already happened,
use `--log=ALL` (the default) - read the tail and grep upward.

## Timeout selection for cerf runs

CERF runs MUST use GNU `timeout` in the command itself
(`timeout 15s ./cerf.exe ...`). The choice of the right number is part
of the diagnostic, not an afterthought. A number too short makes you
miss the target. A number too long makes every iteration waste user
budget on idle guest-time after the target already fired.

### Choosing the initial number

Base the timeout on **when you expect the target data to appear**,
not on a generic round number. The rule is:

- If the latest observed target timestamp is `t+12s`, use **15-20s**,
  not 60s.
- If you have not observed the target yet, pick the smallest
  reasonable upper bound from a sibling milestone - a related log
  line that appeared at `t+8s` in a prior run → use ~15s.
- A timeout that worked for one investigation is **a target-specific
  baseline**, not a default. The number for "boot far enough to see
  X" is generally not the number for "boot far enough to see Y".

A run that ends at 60s when the target fired at t+12 wasted 48s of
guest time × N runs × however many sessions. Pick small numbers.

### Single failure = re-run, not bump

A run that misses its target at the chosen timeout is data, but data of
two possible shapes:

- **Variance** - boot timing varies run-to-run (scheduler decisions,
  libslirp, peripheral cadence, host-clock jitter). A single missed
  target on a previously-working timeout is most likely variance.
- **Regression** - recent code or diagnostic changes added overhead
  so each host second produces fewer guest seconds.

You cannot distinguish these from one run. **Re-run with the same
timeout.** If 2-3 re-runs in a row miss the target, the cause is a
regression, not variance.

### Bumping the timeout

A bump must satisfy ALL of:

- **Evidence of forward progress at the cutoff** - the log's last
  entries show the guest still in execution (peripheral writes, JIT
  compile lines, new progress markers), not parked (idle loops,
  a poll of the same peripheral register with no other activity,
  no new milestones for several seconds). If the guest went idle
  before the cutoff, more time gives it more time to stay idle.
  Find the idle cause first.
- **Tiny increment: +5s.** Not +10, not +30, not +60, not "let's
  just try 120". The increment is small enough that the next run's
  log immediately tells you whether it was enough.
- **The bump is a hypothesis to verify.** After the bumped run, read
  the log and verify that the new cutoff actually fell past the point
  where the target had to fire. If it did not, the bump was wrong AND
  a slowdown exists that you must investigate separately.

### Forbidden values and patterns

- Any **single bump ≥1.5× the working baseline** (65→90, 60→120, 30→60).
- Any **round abnormal value chosen without log evidence** (90s,
  120s, 180s, 300s, 600s, 1h, "let's try a minute", "ten minutes").
- Repeated +5 bumps until the run succeeds - that is laziness
  in slow motion. After 2-3 +5 increments that do not reach the
  target, stop the bumps and investigate the slowdown.

### Diagnosing slowdown instead of bumping

If repeated runs at the working baseline consistently miss the
target, **find what slowed down**. Do not extend the window. Read the
log's last few seconds and ask: does the guest make forward progress,
or is it idle / spinning / in a wait?

- **Idle / waiting** - find what it waits for. An interrupt
  that did not fire, a peripheral that did not respond, or a kernel
  primitive blocked on an event that nothing ever signals.
- **Forward progress but slower than before** - the recent change
  added per-instruction or per-iteration overhead. Bisect the
  change, profile, or remove the heaviest contributor.

After the correction of the slowdown, re-run at the original timeout.
The target will now fire within it.

## Crash shape #1 - guest hits an undecodable instruction

The JIT decoder was not able to translate an instruction at some guest PC.
The two engines diverge here. The **ARM engine** does not halt CERF.
`ArmCpu::RaiseUndefinedException` vectors the guest into its own
Undefined-mode handler at vector 0x4, and the guest decides what to do
(most CE kernels fault the offending thread). The symptom is therefore a
guest-side fault / hang / wrong behavior, not a `[FATAL]` line - to
catch it early, hook `OnPc` at the entry of
`ArmCpu::RaiseUndefinedExceptionHelper` and log the offending PC + insn
bytes. The **MIPS engine** instead loud-fatals through its
`UnimplementedHelper` (logs op + PC, then `CerfFatalExit`), so
an undecodable / unimplemented MIPS opcode surfaces as a `[FATAL]`
directly. Either way the instruction bytes at `pc` are not the bytes the
kernel or driver expects. **Almost always not a JIT bug** - the bytes at
that PA in DRAM are wrong because something corrupted them.

Investigation:

1. Convert `pc` to its corresponding PA via the SoC's `VaToPa` mapping
   (or directly if the kernel was running PA-mode pre-MMU).
2. Identify which module the ROM loader placed at that PA. The CERF ROM
   parser logs its module list with load VAs during boot - grep cerf.log
   for the boot trace and find the module whose
   `load_va` ≤ `pc` < `load_va + vsize`. The decomposed-for-IDA tree
   under `references/extracted-roms/<device>/<rom>/fs/Windows/` helps
   you cross-verify the same module's PE bytes.
3. Open that module's PE in IDA (from
   `references/extracted-roms/<device>/<rom>/fs/Windows/<name>`) and
   disassemble at the corresponding RVA. The IDA bytes are the
   EXPECTED bytes.
4. Compare expected bytes vs `insn=0x…` in the crash. If they differ,
   something overwrote the module's `.text` after the kernel placed
   it in DRAM.
5. The most common causes are three. CERF's ROM parser placed wrong
   bytes at that PA (decompression bug, wrong `o32_dataptr`, wrong
   `o32_psize`). The kernel's own loader did the wrong thing with the
   `o32_rom` record. Another module wrote into that range at runtime
   and corrupted it.

## Crash shape #2 - MMU translation fault

```
[FATAL] Mmu translation fault on read|write|fetch vaddr=0xNNNNNNNN: <reason> (SCTLR=0x… TTBR0=0x… DACR=0x…)
```

This is the ARM engine's fault shape (the cp15 register dump identifies
it). The MIPS engine does not fatal on a normal TLB miss. The MIPS
engine delivers the miss to the guest as a CP0 `TLBL` / `TLBS` exception
(`RaiseTlbException` / `DeliverFetchTlbException`) and the
guest's own refill handler runs. A MIPS access that is genuinely
unmapped surfaces through the peripheral / unmapped-PA path (shape #3).

Means: the kernel's page table walker (or CERF's MMU emulator) was not
able to resolve the VA to a PA. One of two conditions applies:

- The kernel dereferences a NULL or bogus pointer (a genuine
  kernel-side bug that CERF surfaces because CERF is faithful).
- The kernel's L1 / L2 entries for that VA region are stale or absent
  (the kernel did not map that VA yet, or the kernel expects a setup
  that CERF did not do).

Investigation:

1. Note `SCTLR` bit 0 (M). If the bit is 0, the MMU is off and VA == PA.
   The fault message then uses identity. If the bit is 1, the MMU is on
   and TTBR0 walks apply.
2. With the MMU on, the L1 entry for `vaddr` is at `TTBR0 + (vaddr >>
   20) * 4`. Read that PA via a diagnostic LOG. Verify whether the entry
   is present and what its type is (Section / Coarse / Fault).
3. Compare against what the kernel MUST have written. The kernel
   walks its own OEMAddressTable to populate L1 entries. Verify the
   OEMAddressTable inside the kernel binary (in IDA, or read the
   bytes around the kernel's known OAT VA) for the expected (VA, PA,
   size) triplets.
4. If the fault is on a low VA (for example `vaddr < 0x10000`), the
   cause is a NULL deref in the kernel. Read the recent UART output to
   find the function the kernel ran (kernel debug serial usually prints
   a function name shortly before the crash). Then decompile that
   function in IDA.

## Crash shape #3 - peripheral MMIO halt

```
[CAUTION] EmulatedMemory::Translate unmapped 0xNNNNNNNN
```

or

```
[CAUTION] <SocPeripheral>::<ReadWord|WriteWord> unsupported access at 0x…
```

Means: the kernel / OAL / driver tried to access an MMIO address that
no peripheral handles. One of two conditions applies:

- A peripheral block that exists on the real chip is not emulated yet.
- The read/write switch of an emulated peripheral does not handle a
  register offset.

Investigation:

1. Decode the PA. The top byte (`PA >> 24`) usually identifies the SoC
   peripheral block (for example S3C2410: `0x48xxxxxx` memctrl, `0x4A`
   intc, `0x4C` clkpwr, `0x4D` LCD, `0x50` UART, `0x53` watchdog, `0x56`
   ioport, `0x58` ADC, …). The per-SoC layout is in the chip datasheet
   under `references/`.
2. Locate the peripheral block in the chip datasheet. Find the register
   at that offset. Find what the device does when the guest writes it.
3. Implement the register's read/write per the datasheet entry. **Do
   NOT guess values.** No hacks. The datasheet entry must be visible
   above before you write the handler.

## Crash shape #4 - kernel debug serial says something useful

The OAL writes diagnostic strings to a UART, or - when the OEM nulls
the debug path - to a sink hooked by a `cerf/tracing/<bundle>/nkdbg/`
file. CERF routes all such guest debug text through `KernelDebugSink`
to the `Nkdbg` channel. Search `cerf.log` for `[NKDBG]` to
find the kernel's own boot trace, which often names the function that
crashed shortly before the fault.

If the kernel printed a line such as `OEMAddressTable = 0x00000000` or
`*pTOC->ulRAMFree changed in OEMInit` immediately before the fault,
the kernel tells you which structure is wrong. Read the parsed ROM
values CERF placed in DRAM (the boot trace in cerf.log shows the
published ROMHDR / TOCentry / `e32_rom` / `o32_rom` values) and
compare them against the byte-for-byte reference at
`references/extracted-roms/<device>/<rom>/`.

## Adding diagnostics - discipline

**You must NOT write fix code until you have a log line that identifies
the exact error.** "I think X causes Y" is not enough. "LOG shows X
recurses to depth 999" is enough. "LOG shows value changes from A to B
at this point" is enough.

If you do not have evidence yet, add a `LOG()` at the suspected path
first and re-run. Build, run, read `cerf.log`. Repeat until the
mechanism is named in writing.

When your fix crashes:

- STOP the edits, start the investigation. Treat the new crash as a
  fresh investigation - read the crash log, decompile the crashing
  function, trace the data. Do not "tweak the fix" - that is the
  cascading-hack trigger. If your fix caused a crash, your understanding
  was wrong. Return to debugging.

## TraceManager - where bug-specific diagnostics belong

Permanent `LOG()` sites are for low-frequency state observation across
the codebase. Bug-specific diagnostics belong in **device-specific trace
files** under `cerf/tracing/<bundle>/`, not in permanent code.
Bug-specific diagnostics are register dumps at one particular guest PC,
value-change pollers, watches on one specific guest VA, one-shot startup
audits, and function-entry fire-or-no-fire bisections.

See `agent_docs/subsystems.md` § TraceManager for the framework's
hook surfaces (`OnPc`, `OnPcFiltered`, `OnRunLoopIter`) and how the
bundle CRC32 gates device-specific files.

### `OnPc` / `OnPcFiltered` - picking a hook VA

`OnPc(va, handler)` triggers on every guest execution of `va`. The JIT
matches the VA as-is, does the lookup, and fires the handler.

**Kernel-VA hooks** (PC ≥ `0x80000000`) - kernel image, the `k.*`
kernel-mode twins, filesys/gwes/devmgr internals - are constant
across all guest processes. A hook here fires exactly when that
specific code runs. Pick this whenever you can.

**XIP ROM modules execute at their link VA, not the RomParser
loadVA** - if you hook a ROM DLL/EXE with `OnPc`, use the raw IDA VA
of the extracted module. The computation `loadVA + (ida - base)`
produces hooks that never fire. If a hook on an XIP module never
fires, suspect this cause before anything else.

**User-VA hooks** (low addresses, for example `0x11B68` for an EXE
entry, `0x40035C1C` for a coredll PSL stub) are not unambiguous. CE
switches the address space of the current process into the low VAs of
the active slot, so the SAME user-VA can resolve to DIFFERENT
physical pages per the process on-CPU. Two EXEs whose code lands at
the same offset within their slot will both fire your hook. The `LR`
captured in the handler is also a user-VA and has the same property -
the `LR` does not identify the caller's process.

To filter a user-VA hook to a specific process, use
`OnPcFiltered(va, predicate, handler)`. The predicate runs at fire
time and returns `true` to admit the call. A typical predicate body
reads `emu.Get<ArmMmu>().State()->process_id & 0x7Fu` and compares it
against the target process's slot. The way to acquire the target's
slot number is CE-version-specific - observe the slot via a kernel-VA
hook on process creation in your trace file and store name → slot.

If a user-VA hook is not strictly required, prefer a kernel-VA
chokepoint that uniquely identifies the caller. Frequent examples:

- `xxx_*` PSL trap landings in `k.coredll` (every user-mode call from
  any process funnels through here)
- `filesys.dll!FS_SignalStarted(dw)` - `dw` is the RunApps
  `Launch%NN` index, which uniquely names the launched EXE
- Per-subsystem kernel routines that take a `pProc` argument

These produce identifying data inline, without a per-process filter.

**Duplicate-registration guard.** Two unfiltered `OnPc` registrations at
the same VA halt CERF. Registration is exclusive, and CERF surfaces the
conflict at startup. CERF never silently stomps a registration.
`OnPcFiltered` instances at the same VA coexist with each other and with
one unfiltered handler. Each filtered handler is responsible for its own
predicate-distinct admission.

**If a name/slot resolver is not trustworthy, attribute a user-VA fire
by instruction-byte signature.** A per-process (low) VA hook can fire
under any process whose code aliases that VA. If the resolver that maps
a fire to a process is unreliable, identify the firing process from the
runtime bytes at the hook PC (`c.ReadVa32`). Match those bytes against
each candidate module's extracted `.text` - each module is byte-unique
at a given VA, so the match is unambiguous where a name lookup is not.

### When to use TraceManager vs. a permanent LOG

| You want to … | Where it goes |
| --- | --- |
| Log every call to a host C++ function with its args / state at the call site | Permanent `LOG(<chan>, ...)` at that call site |
| Log a host-side state transition that happens on a slow cadence (boot milestone, IRQ, mode switch) | Permanent `LOG(<chan>, ...)` at the transition |
| Watch a specific guest VA for write - to see when it changes | Trace file `tm.OnPc(writer_pc, ...)` at every writer instruction PC + `c.ReadVa8/16/32(va)` inside the handler |
| Watch a specific guest VA for value-change with unknown writers | Trace file `tm.OnRunLoopIter(...)` polling the value via `c.ReadVa8/16/32(va)` |
| Dump full register state every time a specific guest PC is reached | Trace file calling `tm.OnPc` |
| Poll a guest-memory value and log every change | Trace file calling `tm.OnRunLoopIter` |
| Dump a region of guest memory once at startup | Trace file calling `tm.OnRunLoopIter` with a one-shot flag |
| Permanent high-frequency LOG site (per-clock, per-register-access, per-instruction) | NEVER. High-frequency logs bury the signal a future reader needs. Move it to a trace file. |

### Adding a trace file

1. Pick a directory: `cerf/tracing/<bundle_human_name>/` (for example
   `cerf/tracing/wm5_smdk2410_devemu/`). If it does not exist, create it.
2. Add a `bundle.h` (or `<bundle>_bundle.h`) that declares
   `constexpr uint32_t kBundleCrc32 = 0x<actual>;`. To get the CRC,
   either run `python -c "import zlib; print(hex(zlib.crc32(open('path-to-rom.bin','rb').read())))"`
   (concatenate every loaded partition in load order if there is more
   than one), or just boot CERF once and read the `[TRACE] bundle
   CRC32 = 0x…` line.
3. Create a `.cpp` named after the guest PE it hooks. A trace file is
   normally bound to ONE target module, so the usual shape is one file
   per executable: `nk.exe` → `nk_trace.cpp`, `coredll.dll` →
   `coredll_trace.cpp`, `gwes.exe` → `gwes_trace.cpp`. When you need
   more data from an address in a module you already hook, extend the
   existing hooks in that module's file. Do not open a second file for
   the same PE. An investigation that crosses several modules - a touch
   path through the driver, the kernel and gwes - is still one file per
   module, never one file for the investigation. The module the hook
   lands in names the file, not the bug you chase. Name a file after the
   investigation (for example `wm5_msh_handle_corruption.cpp`) only when
   its hooks belong to no PE at all, for example addresses outside every
   loaded module. Define one `Service` subclass
   whose `OnReady` calls `emu_.Get<TraceManager>().RegisterForBundle(
   kBundleCrc32, [&]{ ... });`. Inside the lambda, call `OnPc` and
   `OnRunLoopIter` as the investigation requires. Read memory inside
   handlers via `c.ReadVa8/16/32(va)`.
4. `REGISTER_SERVICE(YourTraceClass);` at the bottom.
5. Build with `build.ps1` (default `-Mode dev`). The build includes the
   trace file. `build.ps1 -Mode production` excludes the entire
   `cerf/tracing/<bundle>/` subtree from the build.

Per-device trace files are gitignored - personal debugging
scaffolding, not committed source. Git tracks only each
`cerf/tracing/<bundle>/` directory's `nkdbg/` hooks and `*bundle*.h` CRC
header. The rest stays on your disk and persists across your local
sessions, but never enters the repo. Verify your existing hooks before
you re-derive a path. The bundle CRC32 gates them (silent no-op on any
other bundle), and production builds exclude them, so they cost nothing
at runtime.

## Reading cerf.crash.log effectively

The crash log is a thread dump. The crashing thread's RIP is in the
FATAL message. Other threads' state is in the `=== All other threads'
state at crash (frozen) ===` block.

For each thread:

- `RIP` = where the thread was when frozen
- `RSP+0..78` = top 16 stack slots. These are 8-byte values that can
  be return addresses, args, or saved registers, per the calling
  convention
- Many threads will be in `WaitForSingleObject` / similar host-side
  blocking calls - those are normal worker threads, not interesting
- Threads with RIP inside CERF code (for example `0x00007FF7…` ranges
  that fall inside `cerf.exe`'s mapped image) do CERF work. If you need
  a host-side back trace, cross-reference with the crashing thread's
  stack via `dbghelp` symbols

The crashing thread's own stack trace (the `[FATAL] [N]
FunctionName+0xXX` list) is at the bottom of `cerf.crash.log` - that is
your first read.

## IDA discipline

The kernel binary, every ROM DLL, and the per-SoC reference binaries
are loadable in IDA via MCP (`mcp__ida__*`). Use them. Decompile the
function at the crashing PC. Read the actual bytes, not the bytes you
assume.

Per-module PEs live under
`references/extracted-roms/<device>/<rom>/fs/Windows/<name>`.
`tools/extract_bundles.py` produces them, and it runs
`references/extract-wince-rom` against each `.nb0` / `.bin` in
`bundled/devices/<device>/`. The tool copies matching PDBs from
`bundled/devices/<device>/pdbs/` next to the modules
automatically, so IDA finds symbols without any extra step.
`references/extracted-roms/` is gitignored and persistent across
rebuilds - point IDA at it directly:

```
python tools/open_ida.py --wait references/extracted-roms/<device>/<rom>/fs/Windows/<name>
```

The `--wait` flag blocks until IDA finishes analysis and registers the
MCP server.

**The extracted PEs are reconstructions, not runtime captures.**
`extract-wince-rom` rebuilds each module: it places the module bytes at
link-time RVAs and appends a `.cerom` section. The result is faithful
for disassembly / decompilation, but it is NOT ground truth for PE
structure, and NOT ground truth for how the module looks in live guest
memory after the kernel loader maps it. Trust it to read code, never for
runtime layout questions - to learn how it diverges from live memory,
read the extractor source. Never assume that the file mirrors the
loader's output.

**A guest binary is read in IDA, as an extracted PE - never with capstone
or a hand-rolled scan over the ROM container.** If the extractor does not
produce the PE you need, make it produce it (fix the extractor, add the
container format, extract the inner XIP first) - a disassembly heuristic
over compressed / packed ROM bytes is always worse than the work you
avoided, and its output is not evidence.

Never run IDA from `build/` or `bundled/`. A rebuild wipes `build/`, and
IDA holds locks there. `bundled/` is CERF's runtime input - an `.i64`
sidecar inside it pollutes the input tree.
