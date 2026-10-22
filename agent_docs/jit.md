# JIT - guest ISA → host block translator

The JIT translates guest code to native host code at the first
execution of each block, and caches the translation. CERF implements
the ARM (ARM-mode + Thumb) and MIPS (MIPS IV, 64-bit) guest ISAs. A
board runs exactly one of them, chosen by `BoardContext::GetCpuArch()`.

## Where the parts live

| Path | What is there |
|---|---|
| `libCerfEngine/include/cerfengine/engine.h`, `engine_setup.h`, `*_host.h` | the engine, the setup that the host fills, the host interfaces and hooks, and the host functions that the engine declares |
| `libCerfEngine/include/cerfengine/guest_engine.h` | the ISA-neutral engine interface `JitRunner` drives |
| `libCerfCore/src/execution/*engine_bridge*` | the CERF owner of the engine |
| `libCerfCore/include/cerfcore/execution/jit_runner.h`, `libCerfCore/src/execution/jit_runner.cpp` | the host thread that owns the dispatch loop |
| `libCerfEngine/src/jit_code_arena.{h,cpp}` | the executable-memory allocator |
| `libCerfEngine/include/cerfengine/isa_block_space.h`, `jit_block_index.h` | the translation index and jump cache |
| `libCerfEngine/src/x86_emit*.h` | host x86 encoding helpers, from Intel SDM Vol. 2 |
| `libCerfEngine/src/a64_emit*.h` | AArch64 encoding helpers for the host, from ARM DDI 0487 |
| `libCerfEngine/src/host_fp_env.h` | the host layer that runs a guest floating-point operation and reads its exception flags |
| `libCerfEngine/src/arm/`, `libCerfEngine/src/mips/` | the two engines |
| `libCerfEngine/include/cerfengine/arm/arm_insn_kind.h`, `include/cerfengine/mips/mips_insn_kind.h` | the instruction kinds that the decoders produce |
| `libCerfEngine/src/cerfir/` | CerfIR, the guest-neutral block IR |
| `libCerfEngine/src/cerfir/cerfir_guest_model.h` | the guest data that a lowering reads |
| `libCerfEngine/src/cerfir/cerfir_host_lowering.h` | the file that selects the host lowering |
| `libCerfEngine/src/cerfir/x86/` | the x86-32 and x86-64 lowering of CerfIR |
| `libCerfEngine/src/cerfir/a64/` | the AArch64 lowering of CerfIR |
| `libCerfEngine/src/arm/cerfir/`, `libCerfEngine/src/mips/cerfir/` | the ARM and MIPS frontends of CerfIR |
| `libCerfCore/src/cpu/arm/`, `libCerfCore/src/cpu/mips/`, `libCerfCore/src/cpu/<core>/` | the page-walk, coprocessor, TLB and exception models that CERF gives the engine, for each ISA and for each core |

## The `GuestEngine` seam

`JitRunner` drives an abstract `GuestEngine` service and never names a
concrete engine. `ArmJit` and `MipsJit` each register as that base
inside the engine, and `Setup::isa` selects which one wins the slot.
CERF sets `Setup::isa` from the `CpuArch` of the board.

The seam is ISA-neutral throughout. Hibernation, reset, deep sleep and
guest-additions injection all reach the engine through it. The state
and power layers therefore carry no ISA knowledge.

## Boundary

libCerfEngine covers this, and nothing else:

- Translation, from decode to emit
- The dispatch loop
- The architectural CPU state and exception entry
- The TLB, its inline fast path, and the FCSE fold
- The cross-thread interrupt channel
- The halt and unwind wrapper around a run

The host supplies the rest. The engine declares, in namespace
`cerfengine::host`, each host function that its own code calls while guest
code runs. The program that links the engine defines them, so each call is
direct. A hook is a function pointer with its context. The host gives one
where it selects the function at run time, for example for each MIPS core.
Calls off the hot path go through the host interfaces.

The engine does not cover CE userspace or kernel behavior. Those are guest
code that runs in the cache. If `coredll.dll` does something wrong,
the fix is not in the JIT.

## Errors

`Engine::Start` returns a setup error to its caller. In a build with no
execution backend for its host, `Start` refuses. A consumer that names
engine classes links only on a host that has a lowering. Only a build
for such a host compiles the whole engine.

The x86 lowering has no Windows x64 calling convention. On a Win64 build it
refuses every call to a host function, so a block that makes such a call
does not lower there.

`Engine::Halt` stops a run on a guest condition that the engine does not
model. It unwinds to the wrapper around block execution or block
compilation in `Run()`, so it is valid only there. `Run()` then returns
`kHalted`, and `LastHalt()` holds the reason.

`Engine::Panic` reports a broken engine invariant to the host and does
not return. A service-locator error inside the engine goes the same way.

## How a block is translated

A block is a straight-line run of guest instructions. The engine
translates the first instruction and takes its physical address as the
block's identity. It then decodes forward until one of these ends the
span:

- the end of the page
- a write to the PC
- a context synchronization operation
- a decode reject
- a failed translate

The engine then allocates one arena slab and places the block record
at the slab head. It builds the CerfIR of the block, lowers it into
host code, then returns the unused tail to the arena.

A block that outgrows its slab evicts itself. It flushes the arena and
the block index, then compiles once more.

A block returns to the dispatcher at its end. The dispatcher resolves
the next block through the jump cache. The guest PC must be live in
CPU state before that exit, because the dispatcher reads the next PC
from there.

Both engines chain a direct branch whose target lies in the same page
as the block. A branch to the start of its own block jumps to that
entry and does not return. An exit to another page goes through the
jump cache in emitted code.

A block whose code continues on another page is never a chain target.
When the mapping of that page changes, the engine must not enter the
old translation again. The MIPS dispatcher examines that page each time
it enters such a block. On ARM, a TLB invalidation of that page removes
the block from the jump cache. The compiler also examines the page
before it reuses the block. A chained jump does neither.

An ARM block continues on another page only when its first instruction
is a wide Thumb instruction that crosses into a new 4 KB page. A core
with Thumb-2 has no 1 KB pages.

A chained block never reaches the dispatcher, so it observes nothing
that the dispatcher delivers. Emitted code polls two things in CPU
state before each chained jump: the chain-exit word, and the guest
cycle counter against the published deadline of the next timer event.
When the word is not zero, or the counter reaches the deadline, the
block returns to the dispatcher. Every signal that must stop a chained
block therefore owns a bit in that word. Every timer event is a cycle
count that the deadline carries - see
[agent_docs/timers_clocks.md](timers_clocks.md).

## The frontend contract

The decoder fills a decoded-instruction record and assigns an
instruction kind. Each kind maps to a CerfIR translator, which adds
the IR ops of that one instruction to the block.

No translation code is specific to both one guest and one host. A
frontend belongs to one guest and to no host. It reaches the host only
through `cerfir_host_lowering.h`. A lowering belongs to one host and to
no guest. The guest-specific part of a lowering is data from
`cerfir_guest_model.h`. The slow-path entries that this data names are
host-independent C++.

Frontend and guest-model code keep a host address at the width of a
pointer. Only a lowering puts a host address into host code.

An instruction with more than one memory access uses the generic memory
ops of the IR. No guest instruction gets a lowering of its own.

To add an instruction, add these items:

- An instruction kind
- A decoder mapping
- A CerfIR translator, and its entry in the translator table

The build fails when a kind has no translator. No build-script edit is
necessary, because the CMake build of the engine globs `src/*.cpp`.

A translator reaches per-instance state only through its block
context.

When a decoder returns success, the translator either implements the
instruction or halts on it. A decoder that returns failure means the
encoding is architecturally UNDEFINED or UNPREDICTABLE, and the caller
raises a guest Undefined-Instruction exception.

## Pinned-register dispatcher

Every translated block runs with the guest CPU-state pointer pinned in
one host register. ARM additionally pins the MMU-state pointer in a
second one. Each lowering names the two registers. Lowered code
addresses state fields off the pinned register and never recomputes the
base.

**The assignment is invariant across the whole lowering and every JIT
helper.** A change to it requires an edit at every emit site.

## Pinned guest slots

A guest model can name a run of 32-bit state slots as pinned. The
AArch64 lowering keeps those slots in host registers while guest code
runs.

**Memory and the pinned registers agree at every block boundary.** A
dispatcher must enter a block through the entry stub of the lowering,
because the stub loads the pinned registers.

**A call to a C++ function sees guest state in memory.** The function
can read and write any guest slot. The block continues with the values
that the function left. A memory tail gives its slow entry the same
view.

**A TLB miss helper sees guest state in memory, but the block keeps its
pinned registers.** A miss helper can read a pinned slot. It must not
write one.

**A helper that unwinds to the dispatcher in the middle of a block
leaves memory older than the pinned registers.** A guest that delivers
exceptions through such an unwind must not pin slots.

**The lowering tracks the state of each pinned register at compile time,
across labels and condition guards.** A write to a pinned slot inside a
branch that the lowering does not track breaks that state. A byte access
to a pinned slot has no pinned form. Both are compile faults.

## Invariants that span files

None of these is visible from any single file.

- **A CERF service that resolves an ISA-specific engine service must
  gate `ShouldRegister` on `CpuArch` itself.** On a board of the other
  ISA the engine has no such service, and the lookup halts at boot.
  Nothing infers the gate, and neither the compiler nor the linker sees
  the omission.
- **A consumer links libCerfEngine as a whole archive.** The engine
  services register through static initializers. A plain static link
  drops their objects, and the first lookup of an engine service fails.
- **An engine service keeps its own copy of each host context that it
  passes while guest code runs.** A lookup through the engine or the
  bridge on each call adds loads.
- **A `cerfengine::host` function forwards to a private member of the
  CERF service that owns the body.** The member carries a forced-inline
  attribute, so the call reaches the body with no second call.
- **Every change to how a physical page maps to host memory invalidates
  the engine page map.** The map caches a host pointer for each page that
  host memory backs linearly. A new region needs no invalidation, because
  the map caches no negative result. A changed address decode needs it.
- **The MMIO bus host increments its route generation after every change
  that can make a route stale.** The engine reuses the last route that it
  found while the generation stays the same. The host publishes the new
  routes before it increments the generation.
- **A block's physical identity comes from the fetch, never a
  re-walk.** An independent later walk diverges from the fetch during
  transitional MMU states. Two such states are a TLB-cached mapping
  the fresh walk cannot see, and a partially-built page table. The
  walk then mis-keys the block, or faults it spuriously.
- **Short jumps silently truncate.** `Jcc rel8` / `JMP rel8` carry a
  signed-byte displacement. When the emit between a jump and its
  target grows past that range, the back-patch truncates and the CPU
  jumps into garbage. The fixup helper fatals at emit time instead.
  The fix is the `rel32` form of that jump.
- **On x86-64, a host pointer is 64 bits wide, and a guest value is
  32 bits wide.** The lowering keeps every guest value in a 32-bit
  register. A test or a move of a host pointer must use the 64-bit
  operand size. A 32-bit test of a pointer fails for a pointer whose
  low 32 bits are zero.
- **On x86-64, blocks run with RSP aligned to 16 bytes.** Every call
  from emitted code to a host function must keep that alignment. Code
  that a block enters by `CALL` starts 8 bytes away from that alignment.
- **On AArch64, the upper 32 bits of a register that holds a guest
  value are unspecified.** A 64-bit read of such a register first
  extends the value, or reads a register that a 32-bit write just set.
  A 32-bit write clears the upper 32 bits.
- **On AArch64, a conditional branch has a short range.** `B.cond` and
  `CBZ` reach 1 MB, and `TBZ` reaches 32 KB. When the target is out of
  range, the label fixup raises an emit fault.
- **On macOS, every write to the arena runs inside a code-write
  scope.** The arena is a `MAP_JIT` region, and a code-write scope opens
  it for writes on one thread. While the scope is open, that thread can
  write the region and cannot execute it. Every byte that a write
  changes must also reach the instruction cache before the code runs.
  The block records live in the arena too, so a change to a record is a
  write to the arena.
- **A guest floating-point operation whose exception flags matter runs
  inside the host floating-point layer.** A compiler can move ordinary
  arithmetic across the instructions that clear and read the host
  flags. A C runtime can also compute a square root outside the unit
  that sets those flags. The guest flags then depend on the host
  compiler. The layer clears the flags, runs the operation and reads the
  flags as one unit.
- **A flush never reclaims a permanent arena allocation.** The
  soft-TLB miss routines are permanent, because emitted blocks call
  them at a fixed address. If a flush reclaims those bytes, every such
  block jumps into unrelated code.
- **Emitted code reaches a coprocessor callback with `CALL`, so control
  RETURNS into the calling block.** A callback that frees the arena under
  that block returns into freed memory. An SCTLR write therefore pends its
  cache flush instead of performing it.
- **FCSE fold is identity on ASID kernels.** The cp13 fold separates
  per-process low VAs only on FCSE kernels (CE5 / ARMv5). CE6 / CE7
  leave the fold base at zero and distinguish address spaces by ASID
  instead. A VA-keyed structure that must stay process-private
  therefore has to incorporate the ASID, and must not rely on the fold.
- **The interrupt line is a LEVEL, not an edge.** Peripheral threads
  publish the current level. The engine folds that level on the JIT
  thread at the top of each iteration. A publisher that sends less
  than the full current level leaves a stuck bit, and the guest
  re-enters its ISR forever. The line carries the level across
  threads. The chain-exit bit is a ONE-SHOT kick: an assertion sets
  it, and the dispatcher consumes it at the top of each pass. The
  dispatcher consumes the bit even when the interrupt stays masked,
  and then re-tests the line. A bit that stays set while the line is
  high returns every chained block to the dispatcher across the whole
  masked-pending span. One channel owns the line and that bit.
- **A reset re-enters at a PHYSICAL address.** The reset must
  therefore turn the MMU off and clear the FCSE fold base. Otherwise
  the fetch folds that address and walks it through the page tables of
  the process that ran before the reset. Deep-sleep resume overrides
  those reset values - see [agent_docs/deep_sleep.md](deep_sleep.md).

## I/O routing

An ARM translate returns null for two different reasons: a real fault,
or a resolved PA that lies in peripheral space. The MMU records the
peripheral PA, and a separate flag shows whether that record is live.
The flag alone separates the two cases. A peripheral can occupy
physical address zero.

**Every path that reaches the abort tail must leave that record in a
defined state.** The walker clears it on entry, and a path that never
runs the walker clears it itself. A translation-free path that does
not clear the record sends its abort into the interpreter.

A peripheral access happens exactly once. Emitted code either performs
it and completes the instruction, or it performs no access and leaves
the block. The interpreter then re-executes the full instruction.

The record that carries the peripheral address holds one address. An
access with more than one address therefore cannot complete inside the
block.

A peripheral access has a third outcome. The interrupt channel owns
one gate over the interrupt line, the CPSR interrupt mask, and the
sleep state. The dispatcher raises on that same gate, so one predicate
serves both. When the gate passes, no access happens, and the channel
sets the guest PC back to this instruction. Control then leaves the
block.

The guard takes two forms. The memory slow path carries it at the
peripheral branch of a translation, and clears the record itself. A
load-store helper carries it at its own peripheral branch, and clears
the record there. The helper form also applies only before the access moves any
bytes.

The dispatcher then re-reads the line. When the line is still high,
the dispatcher raises the interrupt, and the instruction runs after
the handler. A peripheral thread can clear the line first. The
instruction then runs again with no interrupt. The back-out does not
change the interrupt line.

This path runs only when two conditions are true together. The
translation resolved the access to peripheral space. The instruction
commits no state before this point. Every other access keeps delivery
at block boundaries.

---

# MIPS engine

`MipsJit` is structured in parallel to `ArmJit`: same arena, same block
index, same frontend contract. Each engine indexes each instruction set
in its own block space. The second set is Thumb on ARM and MIPS16 on
MIPS.

The parts that differ from ARM:

- **CP0 exception model.** Synchronous exceptions follow the model of
  QEMU `target/mips` `mips_cpu_do_interrupt`. The common entry sets
  EPC, the level bits and the cause code. It picks the refill vector
  when the level bit was clear, and the general vector otherwise. A
  guest exception raised inside a helper unwinds to the dispatch loop
  through a customer-defined NTSTATUS, and resumes at the already-set
  vector PC.
- **kseg fold.** In Kernel mode, `kseg0` and `kseg1` map directly,
  cached and uncached respectively. Mapped segments walk the software
  TLB. The EntryHi ASID distinguishes address spaces, and an ASID change
  flushes the VA jump cache.
- **Blocks are keyed by processor mode.** The dispatcher reads the mode
  from Status: Kernel, Supervisor or User. A block translates its fetches
  and its memory accesses with the address rules of that mode. In
  Supervisor and User mode, a CP0 instruction and CACHE first test
  Status.CU0. After every write to Status, control returns to the
  dispatcher before another block runs. As a result, the mode of a block
  stays valid while the block runs.
- **Wide operations go through helpers**, because the lowering keeps
  every guest value in a 32-bit register on both host widths. These are
  the doubleword loads and stores, the
  unaligned merges, the 128-bit products, doubleword division, and the
  variable doubleword shifts.
- **Loads and stores call the memory helpers.** The MIPS memory model
  has no inline TLB lookup.
- **A write that can unmask an interrupt ends the block.** A write to
  CP0 Status or Cause, and RFE, return to the dispatcher, which then
  delivers a pending interrupt. A clock event that a memory helper
  dispatches can set a Cause bit, so that helper also requests a chain
  exit.
- **Unimplemented paths halt, never silent-UND.** A decoder reject
  halts the run with the opcode and the PC.
