# Deep Sleep - guest suspend / resume

CERF models guest deep sleep / suspend. When the running guest powers down its
CPU (a SoC power-down register write, or a CPU power-mode instruction), CERF
halts the virtual CPU and shows a no-timeout "Shut down CERF?" recovery dialog.
On Cancel it wakes the guest, so the guest resumes exactly where it slept - zero
data loss. This is the GUEST's own suspend/resume on faithful virtual hardware.
CERF only halts the CPU and drives the wake.

**This is not hibernation.** See § "Suspend/resume is not hibernation" - a
conflation of the two is the most common mistake in this subsystem.

Host implementation: `cerf/host/guest_deep_sleep.{h,cpp}`,
`cerf/state/shutdown_dialog.{h,cpp}`. CPU halt/wake: `cerf/jit/arm/arm_jit.cpp`
(`EnterDeepSleep`, `SetResetPending`, delivery), `cerf/jit/jit_runner.cpp` (the
park), `cerf/jit/arm/arm_cpu.cpp` (`RaiseResetException`). Reset cause + reset
line: `cerf/socs/guest_cpu_reset.{h,cpp}`.

## The halt model

`ArmCpuState::deep_sleep` is the halt flag. `ArmJit::EnterDeepSleep()` sets it
on the JIT thread; when `ArmJit::Run()` returns with it set,
`JitRunner::RunLoop` parks the JIT thread - the same park a reset uses. A
delivered reset clears `deep_sleep` and releases the park. No guest
instructions run while the thread is parked, so no peripheral IRQ reaches the
sleeping CPU.

`GuestDeepSleep::Enter()` (JIT thread) banners the sleep, halts the CPU, and posts
`Recover()` to the UI thread. `Recover()` shows `ShutdownDialog::Show(...)`: Cancel
wakes (`DeliverWake`), OK exits (with an optional save). The recovery dialog is
**no-timeout** by design - a countdown can auto-exit and discard live guest RAM
while the user is away.

## Two wake shapes - read the SoC before picking one

Sleep-exit is silicon behavior, and it takes one of two forms. Which one a SoC
implements is a fact to establish from its manual and its guest's own resume code,
never assumed:

- **Reset-on-wake.** The power-up applies an internal CPU reset. The core
  re-enters at the reset/boot vector, reads the reset-cause register to
  distinguish sleep-exit from a cold boot, and runs the kernel/bootloader resume
  path from there. SA-1110 and PXA255 are this shape. It is the `DeepSleepWaker` /
  `SetResetPending` path below.
- **Clock-stop, resume in place.** The chip stops the CPU clock. The core holds
  its entire state and, when the clock restarts, continues at the instruction
  after the one it stopped on. No reset, no reset cause, no resume vector. The
  PR31x00 is this shape - TMPR3911 §12.2.4 (p.12-8): *"the CPU will remain
  suspended at its last state ... Then the CPU will resume the instruction
  execution from where it stopped."* CERF models it with `DeepSleepClockStop` +
  `GuestEngine::ExitDeepSleep()`: `DeliverWake()` applies what the silicon asserts
  on the power-up edge and un-halts the CPU at its halted PC.

**The SoC manual settles which shape a SoC has. The guest binary corroborates it.** Read
the power-down section first. It says either that the part stops the clock and holds state
(TMPR3911 §12.2.4), or that the power-down instruction *"enters reset status"* and recovery
*"begins the Cold reset exception sequence to access the reset vectors in the ROM space"*
(VR4102 UM §7.1.4 / VR4121 UM §8.1.4, of the HIBERNATE instruction). Then corroborate in the
guest: a reset-on-wake guest saves its whole CPU/CP0/peripheral context to RAM before the
power-down store and restores it from the reset entry, and it ends in a jump to the saved
return address - so the suspend call *appears* to return to its caller. A clock-stop guest
continues.

**Live code after the power-down store does NOT prove the core was never reset.** Whether
the rails actually drop is a BOARD decision, so an OEM writes a routine that survives both
outcomes, and both VR41xx ROMs carry real code after their power-down instruction and are
still reset-on-wake. A model of a reset-on-wake SoC as clock-stop resumes the guest in
place: none of the context it saved before the power-down store is restored, so it re-enters
sleep immediately and loops. Beware equally of a retention sentence that is conditional on
the core supply: a manual can say registers are retained in the low-power mode and, in the
same breath, that the mode exists so the core rails CAN be cut - and a battery handheld cuts
them. When the manual and a plausible reading of the guest disagree, the manual's power-down
section wins.

## Reset-on-wake

Where the wake IS a reset, CERF delivers it through the reset path:
`GuestDeepSleep::DeliverWake()` latches the wake cause and calls
`SetResetPending()`. The guest's OWN kernel/bootloader resume code - which runs at
the reset/boot entry - is what restores the live session.

Because the wake re-enters through reset, two things must hold:

- **A true reset cause must be latched.** Cause-checking boot paths read the
  reset-cause register. A causeless reset reads as an ordinary cold boot (or, on
  some kernels, as a sleep-exit that resumes from a stale save block) and hangs.
  The cause is latched through the SoC's reset-cause register via the sleep
  `DeepSleepWaker` (and, for CERF-initiated resets generally, `ResetCauseLatch`).
- **Reset-line silicon must reset on the wake.** A peripheral the board's reset
  line clears registers a `GuestCpuReset::RegisterResetListener` so it
  re-initializes at wake delivery (JIT thread). A skip of this leaves stale state
  that breaks the resume - for example a clock-control register that still holds
  its power-off value is read back and re-enters sleep, or a stale input-device
  FIFO desyncs the driver's re-init handshake.

On wake the deep-sleep decider banners `GuestPowerNotifier::NotifyResume(ResumeSource)`
(`User` = dialog Cancel, `Hardware` = a startup-factor wake). A reboot banners `NotifyReboot()`.

## Per-SoC / per-board wiring contract

Do these steps to implement deep sleep on a new SoC or board. A SoC takes one wake
shape or the other, never both. A step that names a shape applies to that shape only.
Every other step applies to every SoC.

1. **Detect the power-down write** in the SoC peripheral that owns it (for example a
   power-manager force-sleep bit, a CP power-mode write, or a simultaneous
   power-rail-enable clear). Then call `emu_.Get<GuestDeepSleep>().Enter()`.
2. **On a reset-on-wake SoC, latch the wake cause.** The peripheral that owns the
   reset-cause register implements `DeepSleepWaker::LatchSleepWakeCause()` (set the
   sleep/SMR cause bit) and registers via `GuestDeepSleep::RegisterWaker`.
3. **On a reset-on-wake SoC, reset reset-line silicon on wake** with
   `GuestCpuReset::RegisterResetListener` for each register or device that the
   board's reset line clears.
4. **On a reset-on-wake SoC whose guest resumes at a saved vector** rather than the
   cold entry, implement `SleepResumeVectorProvider` (board-scoped) and register it with
   `GuestDeepSleep::RegisterResumeVectorProvider`. Its `ApplyPendingResume()`
   arms the next reset delivery through its own CPU service: an ARM board calls
   `ArmCpu::SetPendingResumeVector(pc)`. When the resume entry expects the MMU
   still live, the provider also calls `ArmCpu::SetPendingResumeMmu(control, ttbr0, dacr)`.
   If you arm nothing, the reset stays at the cold entry.
5. **On a clock-stop SoC**, there is no reset, no cause to latch and no resume
   vector. The peripheral that owns the power register implements
   `DeepSleepClockStop::OnPowerUp()` and registers via
   `GuestDeepSleep::RegisterClockStopWaker`. `OnPowerUp()` applies exactly what the
   silicon asserts on the power-up edge (on the PR31x00, POWER_CTL PWRCS + VCCON,
   which §12.3.1 says hardware sets when ONBUTN is asserted while PWROK is high).
   **Silicon that loses power in the Suspend State still re-initializes.** No reset
   line fires on this path, so a `GuestCpuReset` reset listener does NOT run.
   Re-initialize a device on a power rail that the suspend cuts from the power-up
   edge instead (TMPR3911 §12.2.3: in the Suspend State "VSTANDBY and VCCDRAM are
   powered but VCC3 is not powered"). If you miss it, the resumed guest's driver
   re-handshakes against a device that still holds its pre-sleep state.
6. **Credit the park to a counter that the guest cycle clock drives and that the
   datasheet exempts from sleep.** Read `GuestDeepSleep::SleptNs()`. It gives the
   total time in the park since boot. This total includes the park in progress, and
   it never decreases. Keep the previous total. Credit the difference, on the JIT thread.
   Register the counter with `GuestDeepSleep::RegisterParkClock`, so that it also
   advances during the park. Do not access `GuestCycleClock` from a host thread.
7. **On a reset-on-wake SoC, guard the reset listener of a unit that the
   datasheet exempts from sleep.** When
   `GuestCpuReset::DeliveredResetWasResume()` is true, return early from that
   listener. The wake arrives as a reset delivery, and every reset listener
   runs before the resumed guest runs one instruction.
8. **Register every wake source that the datasheet names for sleep.** Use
   `GuestDeepSleep::RegisterParkWakeSource`. When its wake-up event occurs and
   its enable is set, return true from the source. Assert only the status bits that
   the datasheet sets at that wake-up event. If the datasheet clears a wake status
   bit when sleep begins, clear it in a `GuestDeepSleep::RegisterSleepEntryListener`
   callback. Otherwise a status bit from before the sleep ends the park at once.
   If a counter drives the wake source, also register its due time with
   `GuestDeepSleep::RegisterParkWakeDue`. The due time must be the exact
   `SleptNs()` total at which the wake-up event occurs. The park credit stops at
   the earliest due time. If the park reaches the due time and no wake source
   returns true, CERF halts. A wake-up event can already be present when sleep
   begins, for example a held level input. Latch that event in the
   sleep-entry callback. Then register the current `SleptNs()` total as its
   due time.
9. **Make a user wake operate the input that a user operates.** A dialog Cancel
   stands for a user who wakes the device. Some firmware reads the input that caused
   a wake, and puts the device back to sleep when no user input caused it. For such
   a board, register `GuestDeepSleep::RegisterUserWakeInput`. Its callback drives
   that input, for example the power button pin. The callback runs only for a user
   wake. It runs while the SoC is still asleep, so the SoC records the input as the
   wake-up event.

Suspend/resume serializes nothing - RAM stays live the whole time. The CPU is
only parked.

## Resume mechanism: SoC baseline, OEM specifics

The SoC sets the baseline and the OEM builds the mechanism on top - the boundary
is blurry, so treat both layers as in scope:

- **SoC baseline (fixed by the chip):** sleep-exit is an internal reset that
  latches a sleep-mode reset cause (for example RCSR.SMR). That much is pure SoC and is
  what § "Reset-on-wake" models - the cause latch belongs to the SoC's
  reset-cause peripheral regardless of OEM.
- **OEM mechanism (built on top):** where the CPU/cp15 save block lives, whether a
  scratch register holds the resume vector, what the kernel StartUp examines, and
  what (if anything) the bootloader restores before handoff. These vary
  board-to-board on one SoC, and an OEM can add quirks on top of the baseline.

The `SleepResumeVectorProvider` seam exists for that OEM layer. To pick the shape,
read what the guest's own resume code does (decompile the boot / StartUp path):

- **In-kernel resume.** The kernel's StartUp examines the reset-cause register and
  branches to its own resume routine. CERF needs only to latch the cause (and, on
  some power managers, also set the status bit the kernel additionally gates on).
  No resume-vector provider is needed - the kernel finds its own saved block.
- **Kernel-saved resume vector.** Some kernels store the resume entry in a
  software-defined scratch register and re-enter there, and they skip early boot
  code that clobbers the saved block. The board's provider returns that value as
  the resume PC.
- **CERF stands in for the bootloader.** When the bootloader CERF skips is the
  thing that reads the wake cause, restores cp15, and jumps to a saved resume
  address, the board's provider replays that: read the resume address + cp15 block
  the kernel left in RAM, then arm both via `ArmCpu::SetPendingResumeVector` and
  `ArmCpu::SetPendingResumeMmu`.
  When CERF skips a bootloader, it silently drops any sleep handling that the
  bootloader does and the kernel relies on - model that role, and do not assume
  that the kernel is self-contained (see `agent_docs/boot_loaders.md`).

A scratch / "saved-state" register that one OEM uses as a resume vector is, on
another OEM (even the same SoC), a free-form software scratch or a checksum - it
is not a universal resume vector. Read the guest. Do not assume.

## Suspend/resume is not hibernation

Two different mechanisms. A conflation of them causes real bugs:

- **Suspend/resume (this page)** is GUEST-driven: the guest powered itself down at
  runtime, RAM is live, and the guest's own resume code runs on wake. CERF halts
  the CPU and drives the wake. No machine state is serialized.
- **Hibernation** (`agent_docs/hibernation.md`, `cerf/state/hibernation.cpp`) is
  HOST-driven: CERF serializes the whole machine to a `.img` file and restores it
  later. The per-peripheral `SaveState` / `RestoreState` / `PostRestore` contract
  in `hibernation.md` belongs to hibernation. It does not apply to suspend/resume,
  which serializes nothing.

The two meet at exactly one point: a machine hibernated WHILE asleep restores with
`deep_sleep` set, so `GuestDeepSleep::OnFullRestore()` auto-wakes it (delivers the
wake, no dialog). Consequences:

- **Never re-post the recovery dialog on a hibernation restore.** A restore of a
  saved-asleep machine must auto-wake. A "Shut down CERF?" prompt on restore is a
  bug (the user reopens a restored machine and is asked to shut it down).
- **A restore-into-deep-sleep IS the suspend/resume path**, and it runs the same
  `DeliverWake` - not a separate hibernation defect to chase.

- `cerf/host/guest_deep_sleep.{h,cpp}`, `cerf/socs/guest_cpu_reset.{h,cpp}`,
`cerf/state/shutdown_dialog.{h,cpp}`; CPU halt/wake under `cerf/jit/`.
