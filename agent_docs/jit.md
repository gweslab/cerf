# JIT — ARM/Thumb → host x86 block translator

The JIT translates guest ARM and Thumb instructions to native host
x86 at first execution of each block and caches the translation.

## Boundary

- **Host C++ in the JIT covers**: translation (decode → emit), the
  dispatch loop, the MMU + cp15 state, per-SoC configuration
  strategies, exception entry, the cross-thread interrupt channel,
  and the SEH fault wrapper. That's it.
- **NOT covered by host C++**: any CE userspace or kernel behavior.
  Those are guest ARM running in the cache. If `coredll.dll` does
  something wrong, the fix is not in the JIT.

## Service set

The JIT is not one service; it's a small constellation. Each owns
one responsibility:

- **`ArmJit`** — the translation cache, the dispatcher, the compile
  pipeline. Hot-path runtime helpers called from emitted code live
  here as static methods so emit code can bake a stable
  function-pointer address.
- **`ArmCpu`** — owns `ArmCpuState` (GPRs, CPSR, banked SPSR/R13/R14
  per privileged mode). Hosts the mode-bank / CPSR-write helpers and
  the exception-entry methods (Undefined, AbortData, AbortPrefetch,
  IRQ, SWI, Reset).
- **`ArmMmu`** — owns the cp15 register file, the I-TLB and D-TLB,
  the page-table walker. `Translate{Read,Write,ReadWrite,Execute}`
  are the public surface; on a peripheral PA they return `nullptr`
  and stash the PA in an I/O-pending slot the JIT helper reads to
  route the access to `PeripheralDispatcher`.
- **`ArmDecoder`** — ARM/Thumb opcode → `DecodedInsn`. Thumb decoders
  synthesize an ARM equivalent and re-issue through the ARM decoder
  so register/operand placement has one canonical source.
- **`ArmProcessorConfig`** — per-SoC strategy. PC store offset,
  base-restored-abort model, memory-before-writeback model,
  cache-line size, MIDR/CTR, syscall presence, DSP / LDRD-STRD
  optionality. Concretes live under `cerf/socs/<chip>/`.
- **`CoprocEmitter`** — per-SoC MCR/MRC/CDP/LDC/STC emit strategy.
  Concretes live under `cerf/socs/<chip>/`.
- **`ArmCp15SctlrHandler`** — owns the per-instance trampoline that
  cp15 c1 (SCTLR) writes JMP to. SCTLR changes flip MMU on/off,
  invalidating every cached block — the handler flushes the cache
  before returning so JIT-emitted code never re-enters a freed
  block.
- **`JitRunner`** — owns the JIT main-loop thread. `Start` spawns,
  `RequestStop` signals exit, `Join` waits. One per `CerfEmulator`
  instance.

`PeripheralDispatcher` (in `cerf/peripherals/`) hosts the JIT-side
peripheral I/O helpers; the JIT emits direct calls into them.

## Per-SoC variation

SoC-specific JIT behavior — PC store offset, base-restored-abort
model, cache-line size, MIDR/CTR, coprocessor emit shape — lives in
`ArmProcessorConfig` and `CoprocEmitter` strategies. The JIT body
never branches on SoC family. A new SoC adds one concrete under
`cerf/socs/<chip>/` for each strategy base (`ArmProcessorConfig`,
`CoprocEmitter`, `MmuPolicy`, `PageTableBuilder`, …); the JIT body
is untouched.

## The `place_fn` contract

The single most important convention in the JIT. The decoder fills a
`DecodedInsn` and assigns a function pointer; the emit phase invokes
that function once per guest instruction:

```cpp
using ArmPlaceFn = uint8_t* (*)(uint8_t*       cursor,
                                DecodedInsn*   d,
                                BlockContext*  ctx);
```

Each `place_fn` writes host machine code at `cursor` and returns
the advanced cursor. Place fns live in `cerf/jit/place/` — one file
per function. Adding a new ARM instruction is "add a decoder
mapping + add a `cerf/jit/place/<name>.cpp`"; no build-script or
project-file edit (`cerf.vcxproj` globs `**\*.cpp`).

`BlockContext*` carries per-block emit state: the decoded-instruction
array, the owning `ArmJit*` back-pointer for service access, the
addresses of the per-instance JIT trampolines, and per-block caches
(e.g. the PC-relative-load address cache). Place fns reach
per-instance services through `ctx->jit`.

## Pinned-register dispatcher

Every translated block runs with two host registers pinned across
the entire block: one points to `ArmCpuState*`, the other to
`ArmMmuState*`. Place fns address CPU/MMU fields as `[<pinned-reg>
+ byte-offset]` without ever recomputing the base. The current
assignment (`ESI` and `EBX` respectively) is invariant across every
place fn and every JIT helper — changing it would require touching
every emit site. Helpers documented as `__fastcall(va, hint, jit)`
follow that convention because emit code at the call site already
has the args in the right registers.

## Compile pipeline

`ArmJit::JitCompile(guest_pc)` runs a multi-phase pipeline:

1. **Decode forward** from `guest_pc` until a kernel boundary, a
   prefetch-abort PA, or a per-block instruction cap. ARM vs Thumb
   picked from CPSR.T.
2. **Locate entrypoints + flag-eliminate**. Every R15-modifying
   insn terminates an entrypoint; in-stream branches create new
   entrypoints at their destinations. A back-to-front sweep drops
   per-insn flag packs the next consumer overwrites.
3. **Allocate + register entrypoints**. Bump-allocate one slab from
   `JitCodeArena` (entrypoint records + estimated code size), place
   the records, insert into the per-ISA `JitBlockIndex`. Outer
   entrypoints become new ranges; re-entries into an existing range
   become sub-entries linked off the outer's `sub_block` chain.
4. **Generate code**. Walk the decoded stream, emit per-entrypoint
   prologue + per-condition guard + per-instruction `place_fn`.
5. **Apply fixups**. Back-patch intra-batch forward branches whose
   destination native address wasn't known when the JMP was emitted.
6. **Flush host instruction cache** for the emitted range.

On translation-cache exhaustion: full flush + retry with a fresh
slab.

## JitBlockIndex

One RB tree per ISA (ARM, Thumb), keyed on the post-FCSE-fold guest
VA. Outer entries cover `[guest_start, guest_end]` ranges. Lookup
primitives the JIT uses: find-exact, find-containing,
find-next-after, range-intersects. Sub-entries (linked off the
outer's `sub_block` chain) handle the case of re-entering the same
outer block at a non-start instruction without fragmenting the tree.

**Block physical identity comes from the fetch, never a re-walk.**
When a block is keyed or validated by physical address, that PA must
be captured from the same translation that fetched the block's bytes
— an independent later page-table walk diverges from the fetch during
transitional MMU states (a TLB-cached mapping the fresh walk can't
see, or a partially-set-up TTBR0) and will mis-key or spuriously
fault the block.

## JitCodeArena

One large `VirtualAlloc PAGE_EXECUTE_READWRITE` region per `ArmJit`
instance, bump-allocated. Allocation failure means the region is
full — caller flushes everything and retries. `Flush` drops every
block but keeps the region committed; the unused tail consumes no
physical RAM under Windows overcommit.

## Trampoline pattern

For cross-block control transfers (cp15 cache-op-induced flush,
R15-modified resolve, branch resolve, BL push, BX-LR pop,
data-abort raise, interrupt poll, …) the JIT emits a JMP/CALL to a
per-instance trampoline rather than inlining the resolve. Each
trampoline is a small naked-machine-code body in writable host
memory, owned by `ArmJit`. Self-modifying trampolines (notably the
interrupt-poll one) let peripheral threads change JIT-thread
behavior without a lock on the hot path.

## Shadow stack

`BL` (and `BL`-shaped patterns the decoder recognizes) push a
`(guest_return_addr, cached_native_dest)` pair onto a per-instance
shadow stack. `BX LR` / `MOV PC, LR` pop and compare; on a
guest-return-address match the JIT JMPs straight to the cached
native destination, skipping the R15-modified-helper round trip.
Cleared on every JIT cache flush — the cached pointers became
stale the moment the arena was reused.

## FCSE fold

Guest VAs below 32 MB are private to the current process (ARM
Fast-Context-Switch Extension — the OS plants the active process's
fold base in cp13). The block-index key, the TLB key, and the
shadow-stack key all use the post-fold VA; `DecodedInsn::guest_address`
keeps the raw VA for diagnostics and for instruction-stream
re-entry.

**FCSE fold is identity on ASID kernels.** cp13 FCSE `process_id`
separates per-process low VAs only on FCSE kernels (CE5 / ARMv5).
CE6 / CE7 set `process_id = 0` and distinguish address spaces by ASID
(CONTEXTIDR) instead, so the fold is a no-op there. Any VA-keyed
structure that must stay process-private therefore has to incorporate
the ASID rather than rely on the fold.

## I/O routing

`ArmMmu::Translate*` returns `nullptr` for two reasons: (1) a real
fault (TLB miss + page-table fault), and (2) the resolved PA lies
in peripheral I/O space. The JIT helper distinguishes by reading
the MMU's I/O-pending slot — non-zero means "PA is here, route to
`PeripheralDispatcher`," zero means "raise the abort." The slot is
per-`ArmMmu` instance.

## Interrupt delivery (cross-thread)

Peripheral threads call `ArmJit::SetInterruptPending` (or
`ClearInterruptPending`) under `InterruptLock`. The lock guards
both the pending bit and the byte of the interrupt-poll trampoline
that the JIT thread CALLs at every guest-block exit. A pending IRQ
patches the byte to NOP (fall through to delivery); no pending
patches it to RETN (return to block immediately). `SetEvent` wakes
the JIT thread if it's parked in an idle-loop `WaitForSingleObject`.
Idle-wake is fire-and-forget outside the lock — wake-up never hurts;
missing one (because the peripheral asserted just as the JIT thread
was about to park) is self-correcting on the next poll.

## Reset

- **Cold power-on**: the boot path resolves the entry VA, writes
  the bootloader-handoff SP via `ArmCpu::SetInitialStackPointer`,
  then calls `RaiseResetException(initial_pc)`. The initial PC is
  cached for subsequent soft resets.
- **Soft reset** (watchdog expiry, OAL request, …): peripheral
  calls `ArmJit::SetResetPending`; on the next IRQ-delivery
  dispatch the JIT routes through `ArmCpu::RaiseResetException()`
  (no-arg overload, uses the cached entry VA).

## SEH fault filter

`ArmJit::Run` wraps `Dispatch` in `__try`/`__except`. The filter
dumps the host EIP context (host x86 registers + a window of
JIT-emitted bytes around the fault), the guest ARM register file,
and the host symbol resolved via `dbghelp`, then `CerfFatalExit`s.
The filter only runs on actual hardware exceptions — zero hot-path
cost on the dispatch path.

## `x86_emit.h`

Header-only x86 encoding helpers. Style: free functions taking
`uint8_t*& cursor`, advancing the cursor past emitted bytes. The
encoding source of truth is Intel SDM Vol. 2.

**`rel8` vs `rel32` trap.** Short conditional jumps (`Jcc rel8` /
`JMP rel8`) carry a signed-byte displacement (±127). When the emit
between the jump and its target grows past that range — usually
because the surrounding instruction's code body grew — the
back-patch silently truncates and the CPU jumps to garbage. The
`FixupLabel` helper catches the overflow at emit time with a fatal
log naming the jump opcode and the actual displacement; the fix is
to switch the affected jump to its `*32` cousin (`EmitJzLabel32`,
`EmitJnzLabel32`, `EmitJmpLabel32`, `FixupLabel32`).
