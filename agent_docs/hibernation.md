# Hibernation - full machine-state save / restore

CERF can snapshot a running guest to a `.img` file and later resume it bit-for-bit
("hibernation" / "state saver"). This page is the **contract every peripheral
author must obey**, so a restore returns a live, correct machine instead of
a half-reset one. If you create or modify ANY peripheral, SoC block, board device,
codec, or worker thread, the § "Peripheral contract" rules below are mandatory.
A skipped rule does not produce a smaller feature. It produces a broken restore
(dead display, frozen scheduler, missed interrupts) that appears hours later on a
different device.

Host-side implementation: `cerf/state/` (`hibernation.{h,cpp}`,
`state_stream.h`, `state_image_format.h`, `state_boot_gate.cpp`,
`emulation_freeze.h`, `shutdown_dialog.cpp`). The JIT pause lives in
`cerf/jit/jit_runner.{h,cpp}`.

## What it is

Three outcomes from a saved `.img`:

- **Full restore** - resume the exact desktop (every register, all RAM, all
  peripheral state) as if the machine never stopped.
- **Warm boot** - keep RAM + flash, re-init CPU / cp15 / peripherals cold. The OS
  reboots, but the filesystem-in-RAM and any flash writes survive.
- **Cold boot** - ignore the image, boot from scratch.

**Why it exists:** real vintage HPC devices (Jornada 720, …) are battery-backed and
keep DRAM alive across suspend. Only a battery pull wipes it. The running OS
and its RAM-backed object store (the CE in-memory filesystem) therefore persist
across power cycles. CERF instead wipes all guest RAM on close. Every exit is
effectively a cold boot, and all guest state from since boot is lost. Hibernation
preserves the full running machine across an exit.

**Triggers:** the Actions-menu Save/Load state, a Shutdown dialog on window close
(save-on-exit), and a boot-time prompt when a default `state.img` exists in the
device directory.

## The `.img` format

The image starts with a magic and an identity header. Length-framed sections
follow. Each peripheral has its own frame inside the Periph section, with its
`MmioBase` as the frame id. Every field carries a tag with its name, kind and
size.

Hibernation compares the identity **before** CERF mutates any live state.

## Compatibility

The image describes its own layout. The reader compares each field name, kind
and size, each frame id and each frame length with what this build expects. A
difference refuses the image. A build that serializes a peripheral the same way
loads an image from another build. A build that changes a layout refuses only an
image that carries the old layout.

**The stream takes scalars, enums and arrays of them only.** A struct written as
one blob can gain a field inside its padding, and its `sizeof` stays the same.
A size tag cannot see that change. Write a struct field by field, so an added
field adds a tag.

The field list of a struct is one visitor that save and restore share. A
`static_assert` on `StateVisitCoversAllBytes` makes the build fail when the
visitor does not name or skip every member exactly once. A struct with padding
carries its padding as a named member.

**Every field has a name, and the name is the identity of the field.** The same
name on the save side and the restore side is one field. A rename is a layout
change. When a field changes its meaning, its units or its set of values, give
it a new name.

The restore is transactional. Before it applies an image, CERF writes the live
machine to `rollback.img` in the device directory. When the reader refuses the
image part way through, CERF restores the rollback image and shows the reason.
The machine then equals a save and restore of the live machine. Host coupling
that every restore resets stays reset, for example an open shared-folder handle
or an in-flight audio stream. A failed boot-time restore leaves the unmodified cold-boot
machine. A rollback that fails is a CERF bug, and CERF halts.

The magic moves only when the frame or tag encoding in `state_stream` changes.

A `RestoreState` never calls `CerfFatalExit` or `Fatal::Die` on a value it read
from the image. It calls `r.Reject`, which refuses the image.

A buffer whose size this build fixes is read at that size, with no saved count.
The byte-block tag then refuses an image that saved another size.

A frame with no owner in this build refuses the image. The one exception is a
part that the machine does not need, for example a host widget. The caller
skips that frame with `SkipFrame`.

## Sections - what each captures

- **Cpu** - the CPU state of the engine, field by field.
- **Mmu** - the persistent MMU state of the engine. The TLBs and SMC bitmaps are
  derived state. Restore flushes them and never serializes them.
- **Ram** - the volatile memory regions.
- **Flash** - the read-only memory regions. Flash writes since boot are machine
  state. Restore applies this section on a warm boot too, because flash survives
  a reboot on real hardware.
- **Periph** - every registered peripheral.
- **Presentation** - the guest-surface dimensions, so a custom resolution
  restores its window size.
- **Widget** - the host-widget state that drives guest-visible hardware (for
  example the charge level / AC of the battery widget, which a board service
  feeds into GPIO/MCU lines). Only a full restore applies it. On a warm boot the board service
  re-asserts it when it re-drives at startup.
- **Reset** - the reset cause and the registered boot-time guest-RAM write
  replays.

CERF **flushes** the JIT translation cache and never saves it. The `Run` of each
engine re-reads the live interrupt line on every iteration. The `PostRestore` of
the INTC re-drives that line from the restored state. An INTC without that
re-drive silently drops a restored-pending IRQ.

## The two-thread freeze model - read before touching ANY peripheral

A safe snapshot requires a quiescent guest. Two things execute guest-visible
state, and a pause of one does NOT pause the other:

1. **The JIT (guest CPU) thread.** `JitRunner::Pause()` parks it between translated
   blocks. `Resume()` releases it. `Pause()` is **host-thread only**. A call from
   the JIT thread self-deadlocks. Hibernation runs `Pause() → work → Resume()`.

2. **Peripheral worker threads.** A peripheral that owns a `std::thread` continues
   to mutate guest-visible state, whatever the JIT pause does. **`EmulationFreeze`**
   (`cerf/state/emulation_freeze.h`) freezes them:
   - A worker holds `WorkerSection()` (a `shared_lock`) **around the part of each
     iteration that reads or writes guest state**.
   - Hibernation holds `SnapshotSection()` (a `unique_lock`) across the whole
     save or restore.
   - **Lock-order invariant (a violation deadlocks):** take the freeze lock
     BEFORE any peripheral mutex. A worker **never** holds `WorkerSection`
     across a cv wait / sleep / thread join. Acquire it, do the state touch,
     release it, then wait.

Every peripheral that owns a worker thread wraps its state touch in a worker
section. A peripheral whose state advances only on the JIT thread - every timer
on the guest cycle clock is one - has no worker and needs no `WorkerSection`.

## The peripheral contract - MANDATORY when you create or modify a peripheral

A `Peripheral` (or any object that holds mutable guest-visible state) gets a
maximum of three methods. **Every peripheral with mutable state MUST implement the
first two.**

### 1. `SaveState(StateWriter&)` / `RestoreState(StateReader&)`

Serialize **every mutable register, latch, counter and FIFO**, not only an
obvious `storage_[]` array. Examples:

- timer counters and DMA transfer registers
- the RTC base and the LCD framebuffer configuration
- the latched parameters of a blit engine
- FIFO contents and mode or command FSM latches

Save and Restore must be **exact mirrors** (same fields, same names, same
order). Length-prefix data whose size changes at run time, for example a FIFO.
Put a part that another build can lack, for example an optional card, in its own
`BeginFrame` / `EndFrame`. For `std::atomic<uintN>`, use
`.load(std::memory_order_acquire)` / `.store(v, std::memory_order_release)`.

### 2. `PostRestore()`

It runs in a **second pass, after the `RestoreState` of every peripheral is
complete** (`Hibernation::RestorePeripherals`). It is therefore order-independent,
because all registers are already in place. Use it to re-assert **computed** state
that a single `RestoreState` cannot establish. The interrupt line
`source → INTC → JIT` is the most important case:

- An **INTC** re-notifies the JIT of its restored pending/mask state
  (`SetInterruptPending` / re-derive `HasPendingUnmasked`). A restored INTC that
  only reloads its registers never re-arms the JIT → missed or stale IRQ → hang.
- A **level-driving source** (GPIO edge/level lines, OST match level, an SA-1111
  cascade) re-drives its INTC source level. See `sa11xx_intc` (`NotifyLocked`),
  `os_timer` (`PushMatchLevel` from `PostRestore`), `sa11xx_gpio`
  (`PublishEdgeSourcesLocked`), `sa1111_intc` (`DriveCascadeOutput`).

`PostRestore` is a no-op default in `peripheral_base.h`. Override it only when you
own a computed line. **Fix the whole bug class, not one instance.** If one INTC
needs `PostRestore`, audit every INTC.

### 3. Worker-thread wrapping

If your peripheral starts a worker thread that touches guest state, wrap the
state touch in `emu_.Get<EmulationFreeze>().WorkerSection()`, per § The two-thread
freeze model.

## Patterns by peripheral shape

- **Unified peripheral** (`class Foo : public Peripheral` that holds its own regs)
  - SaveState/RestoreState directly on the class.
- **Split peripheral** (a stateless MMIO `Peripheral` that delegates to a
  state-owner registered `_AS` a base, for example the S3C2410 INTC) - the
  **state-owner** implements SaveState/RestoreState/PostRestore. The MMIO override
  delegates through `static_cast<Owner&>(emu_.Get<Base>())`. **Read BOTH `.h` and
  `.cpp`** before you call a peripheral a gap. Save/Restore is often inline in the
  header.
- **Codec / PMIC parts are Services, NOT Peripherals** → they are not in the
  `RegisteredPeripherals()` walk. Add virtual `SaveState/RestoreState` to the codec
  base (`Ac97Codec`, `Sa11xxMcpCodec`). Override it in the concrete and serialize
  its `reg_`. Then **forward from the SaveState/RestoreState of the owning
  peripheral** with `if (auto* c = emu_.TryGet<Base>()) c->SaveState(w);`
  (symmetric in Save+Restore).
- **Non-`Peripheral` stateful objects** (PCMCIA `PcmciaSlot` / `PcmciaCard`,
  sub-devices like a companion-ASIC `Ps2Mouse`) are not auto-enumerated → they need
  an explicit serialization walk + card-presence recreation
  (`PcmciaCardCatalog::TryCreate(id, binding)`).
- **Rebase timers** - a timer anchored to a baseline **never raw-serializes
  that baseline or a `std::chrono::time_point`.** It saves the live counter,
  re-anchors at the restored guest time, re-arms its events and re-drives its
  level from `PostRestore` - see
  [agent_docs/timers_clocks.md](timers_clocks.md) § Hibernation and deep sleep.
  A host-clock source re-anchors to `Clock::now()`.
- **In-flight host coupling** resets on restore, because no host sink / pen /
  socket exists after a restore. In RestoreState or PostRestore, clear audio-DMA
  `in_flight`/`tx_running`, touch `pen_down`/`pen_timer_enabled`, and the
  equivalent flags. See `sa11xx_dma`, `sa1111_sac`, `odo_arm720_touch_sound`.

## What NOT to serialize (host-side members)

Skip anything that is host machinery, not guest state. CERF reconstructs it and
never restores it: raw host pointers, `std::thread`, `HANDLE`, audio sinks,
`std::function`, pointers into the own buffer of the object,
`std::string`/`std::vector` TX-line accumulators. A **file-backed `DiskImage`**
(host `HANDLE`) is NOT serialized. It persists on host disk across the restart.
Only its in-flight transfer state (`AtaDrive`) is serialized.

## Verifying a peripheral's serialization

A peripheral that compiles is not a peripheral that serializes. For completeness,
read every `public Peripheral` (both `.h` and `.cpp`) and verify that it has
SaveState/RestoreState. Then do a **save → restore round-trip on the actual
device** and exercise it. A single clean round-trip on one OS does not prove
restore correct. Per-device runtime testing does.

## Common failure shapes

- A peripheral resets on restore (its registers reload but a `PostRestore`-computed
  line / cleared in-flight flag is missing) → dead display or frozen scheduler.
- A worker thread mutates state mid-snapshot (missing `WorkerSection`) → torn,
  inconsistent image.
- A rebase timer raw-saved its baseline → the clock jumps or stalls on restore.
- An INTC reloaded registers but never re-notified the JIT (missing `PostRestore`)
  → a pending IRQ is lost and the guest hangs.
