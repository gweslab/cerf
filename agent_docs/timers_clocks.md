# Timers and clocks

Every clock a guest can read derives from one time base. That base is the
number of guest instruction cycles the JIT has executed, at the datasheet CPU
rate of the SoC.

## Guest time

- **Guest time is a cycle count.** The JIT counts the cycles of every
  translated instruction. That count, at the CPU rate, is guest time.
- **The CPU rate is the datasheet product, never a rounded print.** A clock
  table gives a multiplier of the crystal. The rate is the crystal times the
  multiplier. SA-1110 Dev Man § 8.2 Table 8-1 gives CCF 01010 as 3,686,400 x 56
  = 206,438,400 Hz, printed "206.4". A PLL-programmed SoC takes the rate the
  guest programs, from the register's own formula.
- **A timer match is an event at a cycle count.** The JIT thread delivers the
  match when the cycle count reaches that event. A guest tick never comes
  from a host thread, and never from a host deadline.
- **The emulator runs at or behind wall, never ahead.** When the guest is
  behind wall by more than a bounded window, the emulator forgives the excess
  and never replays it. That window is the max-fallback of the Dolphin
  `CoreTiming` model. A slow host therefore slows the whole guest uniformly.
  A host-referenced observer sees the replay of at most one window when a
  busy guest becomes idle, and the guest cannot see it.

## What runs on guest time

- **Every state that the guest can see advance with time runs on guest
  time.** A timer is one case. The same rule covers a frame or scan-line
  status bit and a line counter. It also covers a transfer that completes
  after a delay, a sample rate, a baud rate and a conversion time. The rule
  holds for a part on every board and every CPU architecture. A shared part
  never selects its time base by architecture.
- **While guest time runs, a host clock, a host thread and a list of host
  deadlines are never the time base of a guest-visible state.**
- **When the guest reads a polled state, the part computes that state from
  the cycle count.** A status bit, a line counter or a count register needs
  no event and no thread.
- **A part arms an event at a cycle count only where the silicon raises an
  interrupt at that moment.** The interrupt line must rise at the cycle of the
  edge, not at the next register read.
- **Every period comes from the registers that the guest programs.** When the
  guest changes the period or the CPU rate changes, a part recomputes the
  period.

## Idle

- **A wait-for-interrupt completes only on an interrupt.** ARM DDI 0406C
  B1.8.14: a wake-up event is a physical IRQ regardless of CPSR.I. The idle
  wait advances guest time to the next armed event, paced to wall, and never
  ahead of wall. There is no timeout. A timeout is a spurious wake, and the
  guest's idle arithmetic credits it as slept time.
- **Idle exit on SA-11xx and PXA2xx follows ICCR.DIM** (SA-1110 § 9.5.2.2,
  PXA255 printed 4-21, PXA27x § 25.5.6). With DIM clear, any enabled
  interrupt ends idle, masked or not. With DIM set, only an unmasked one
  ends it. The wake completes the wait, and execution continues at the next
  instruction.
  An exception follows only through the ordinary interrupt gate.
- **Every idle shape reaches the same wait.** The SA-1110 sequence is
  `c15,c2,2`, an uncached load, then `c15,c8,2` (§ 9.5.2.1). The `c2,2`
  write only disables clock switching (§ 8.2.1). The wait is `c8,2` alone.
  XScale idles through a PWRMODE write. ARM920T idles through cp15
  `c7,c0,4`. The S3C2410 idles through a clock-control bit. An idle that
  does not reach the wait spins, and the guest's idle credit arithmetic then
  runs on nothing.

## Why the wall clock was abandoned

A timer that expired on a host clock set its status bit late by a host
thread's latency. Every CE kernel then needed its own rule for what its
handler did with the late tick. A cycle-count match cannot be late relative
to the guest's own instructions, so the mechanism needs nothing from any
kernel.

**A timer left on a host clock while the CPU is paced by cycles loses
ticks.** Its expiries continue while the guest sleeps in the throttle or
runs a host-side device operation. The next expiry lands on an
interrupt-controller pending bit that is already set, and it is gone. The
guest's clock then falls behind wall.

## What a timer is in Windows CE

The OAL drives one hardware timer channel as the system tick, and its ISR
credits the millisecond counter that `GetTickCount` reads. Everything else
about that channel is per-SoC and per-kernel. The guest's arithmetic around
that timer is what makes it dangerous.

- **The catch-up loop.** Many SA-11xx and PXA kernels re-arm with
  `OSMR0 += period`. The kernel repeats that add while `OSMR0 - OSCR` is
  under a small margin, and some kernels also while that distance is more
  than one period. The loop therefore walks one period per pass until the
  match is ahead of the counter again. **Whether the millisecond counter
  is credited inside that loop or once after it is a per-kernel choice, and
  it decides what lateness costs.**
  A kernel that credits inside the loop credits every period the loop walks.
  A kernel that credits once after it credits one period however many the
  loop walked.
- **The tick death.** The subtraction is unsigned. An entry that is late by
  nearly one period or more can land in a narrow residue band. In that band
  the distance is less than the exit margin. In a kernel with both tests, the
  next pass leaves the match more than one period ahead. The loop then walks
  until the distance wraps through 2^32. Each pass also moves the counter by
  the time of that pass. The lap therefore takes a little more than
  2^32 / period passes, roughly 1.165 million at a 3686-tick period.

  A kernel that credits inside the loop moves its clock by that many periods,
  about 19.4 minutes at 1 ms each. A store that lands at or behind the counter
  laps 2^32 ticks (1165 s at 3.6864 MHz). The channel is then dead until the
  guest rewrites it.
- **Late entries.** On the cycle clock CERF never makes an entry late. A guest
  that masks the tick while it waits on the counter makes the entry late
  itself, by the whole wait.
- **Per-pass and per-entry credit.** A kernel credits either once per loop
  pass or once per entry, in units of its own tick period, and some re-check
  the distance after the re-arm and credit again.
- **OEMIdle banking.** A banking kernel reads the phase since the last tick
  at idle entry. It adds an accumulator, credits the whole periods, and arms
  one long match at the scheduler deadline. On wake it credits the slept
  periods from the changed counter, or from the counter-derived quotient
  when the tick never came. Then it re-bases the match one period out. Every
  such re-base to the counter discards the phase between the last match and
  that counter. A kernel that advances the match by whole periods instead
  keeps that phase.
- **The bank-and-exit double.** An entry banks a full period at the
  scheduler's 1 ms deadline and exits without arming. The still-armed tick
  then credits the same period again.
- **A guest clock that does not keep time is a CERF defect until the
  arithmetic says otherwise.** The device kept time on silicon. An attribution
  to the guest's own tick arithmetic holds only when that arithmetic is
  computed from the reload count, the prescaler and the programmed clock. The
  result must also land on the measured ratio. A named mechanism that does not
  produce the measured magnitude is an open defect, not an explanation.
- **The same shapes on other silicon.** The i.MX EPIT is a compare-register
  down-counter. Its tick handler re-reads the counter, clamps, and stores the
  compare a few instructions later. A host stretch of that window past the
  margin lands the compare behind the counter, and the channel laps. That is
  the SA-11xx death on a different IP. The S3C2410 PWM timer is an
  auto-reload down-counter with one interrupt per reload and no loop. It
  loses ticks instead of dying. MIPS CP0 Count / Compare is the OSCR / OSMR
  shape in a coprocessor register.

No kernel identity shapes the time path. It carries no per-ROM, no per-kernel
and no per-board branch. One implementation serves every ROM. A correction that
the guest's own register surface selects is the one permitted exception.

## When a kernel needs its own branch

One shared clock drives every board. One shared timer model sits on that clock.
A kernel whose own idle arithmetic cannot keep time on that model receives a
correction inside the shared model. A fact that the guest establishes at the
register surface at run time selects the correction. The ROM never selects it.
The board never selects it, and the kernel name never selects it.

**A correction answers a kernel, never a chip and never a board.** Two kernels on
one board differ in the one behavior that a correction targets. One handheld
kernel banks the elapsed phase at idle entry. Its sibling on the same board drops
that phase. A board condition cannot express that difference. One implementation
therefore serves every kernel of the shared model.

**The re-phase absorb.** A kernel arms the tick channel at the
counter plus whole periods. That write re-bases the grid of the kernel to the
counter. It discards the phase since the last match. Unless one of the skips below
applies, the timer advances the counter by that phase. The next match then lands
where the kernel's arithmetic expects a whole period.

**The absorb moves the counter, never the tick delivery.** The tick handler compares
the next match against the counter with zero margin at its loop exit. A match
delivered one tick early makes that loop walk the full 32-bit wrap. The
free-running counter can advance by the phase that a kernel discarded. The
counter value at the next match is then still the exact value the kernel armed,
and the arithmetic of the handler does not change. The timer also delivers the match of
every other channel whose compare lies inside the advance, because the counter
passed that compare.

The absorb skips itself on a write to any channel but the tick channel. It skips
itself before the first match of that channel, and while the last match waits for
service. It also skips itself when any of these holds:

- The write advances the compare by a whole number of tick periods. The kernel
  preserved its grid.
- The kernel read the counter and the compare register with the status bit
  clear. It had the phase and banked it itself. The pair counts in either
  order: the counter before the compare, or the compare with the counter as
  the next timer read. A kernel that wakes on another interrupt before its tick
  uses this pair to measure the phase. Its exit re-base then discards nothing.
  Interrupts can be masked or unmasked at that read.
- The phase is zero, or the advance reaches the compare that the kernel just
  armed.

The tick period comes from the handler stores of the kernel itself. Two consecutive
equal steps confirm it, because a catch-up loop store is a multiple of the
period.

**The omitted-exit re-arm.** A bank-and-exit kernel reads
the counter and then the compare register, with interrupts masked and the status
bit clear. It banks a whole period against its deadline. Then it returns and
does not arm the channel. The tick that its own handler armed credits that
period a second time.

When the next tick-channel event is that match, and no guest write falls between
them, the timer does not deliver. It moves the compare to the bank point plus one
period. It does this only after it learns the period, and only while the kernel
keeps the tick channel enabled.

The kernel can also bank a second time before that match arrives. The timer then
moves the compare to the first bank point plus one period. The read that observed
the second bank returns that value. The kernel measures its own phase against the
grid that the first bank established.

This correction moves the compare register, not the counter. On the match path the
kernel abandoned that compare. On the read path the kernel receives the replaced
value and measures its phase against the re-anchored grid.

Another kernel emits that same register signature at every tick. Its tick
handler acknowledges the status bit, then advances the compare, then reads the
counter and the compare for its own loop-exit test. That read is masked, the
status bit is clear, and no write follows it. Both kernels run in the same
processor mode, and their instruction distances overlap.

**The kind of the last compare write separates them.** The read of the handler
follows a write that advanced the compare by whole tick periods. Such a write
preserves the grid of the kernel. A bank follows a write that landed the compare
on the counter, which re-phases that grid. A pair is therefore a bank in two
cases:

- No compare write follows the service of the last match.
- The last compare write re-phases the grid.

The two cases answer different kernels. A kernel that services the match before
it advances the compare always writes between the match and the read. The kind
of that write then decides. A kernel that advances the compare before it
services the match writes nothing there. The absence then decides.

**The walk-away step.** It serves a kernel whose catch-up loop also repeats
while the match is more than one period ahead. A late entry can end a pass with
the match ahead of the counter by less than the exit margin. The loop then adds
one more period, and the match is more than a period ahead. Each later pass
moves it further, so the loop runs until the 32-bit wrap.

The step acts on a tick-channel compare write that is not the first since the
kernel cleared the status bit. The write advances the compare by one tick period,
and the compare that it replaces is more than one period ahead of the counter.
The timer then advances the counter to the replaced compare, and the next check of
the kernel finds the match one period ahead. The loop ends there.

No tick-channel match fires, because the compare already moved past the point
that the counter reaches. The timer delivers the match of every other channel whose
compare lies inside the advance. A kernel that credits one period for each pass
then credits exactly the grid points that the counter passed. A kernel that
credits once per entry credits one period, as for any late entry. Before two
equal steps confirm the tick period, the step takes it from the first store of
the handler.
The late entry after a wake comes before that confirmation.

**A measurement over every kernel settles a correction.** Before a correction
lands, that measurement covers every kernel on the shared model. It records the
register behavior that selects the correction. A correction that is inert on
every kernel that does not need it is finished. A predicate that fires on a
kernel that does not need it is not finished.

**The tick-period rounding is the kernel's own floor, not a defect.** A kernel
credits one millisecond per 3686 ticks of a 3,686,400 Hz counter. That period is
0.99989 ms, so the kernel's clock runs 0.109 per mille fast against its own
crystal. The floor is the same on silicon and on the emulator. A period that
divides the counter rate exactly has no floor: 3250 ticks at 3,250,000 Hz, or
92160 ticks at 3,686,400 Hz. The kernel's own floor is the reference for every
timer change measured on it.

## How a timer change is judged

- The guest's own tick counter against guest time is the criterion, measured
  under a starved host and then an idle host, with the guest under load. Any
  ratio other than one is a defect until the guest's own tick arithmetic is
  computed and lands on it.
- A host-referenced measurement reads the throttle's replay, so it is never
  the verdict. The guest's counter is.
- Nothing fast-forwards. No recovery loop iterates. No channel laps. Nothing
  fatals. Hibernation round trip and deep-sleep resume keep working on the
  same binary.

## Hibernation and deep sleep

A timer on the clock saves its live count. The timer re-anchors this count at
the restored guest time.

The deep-sleep park stops guest time. A timer therefore stops for the length of
the park. On silicon, the same timer also stops in sleep.

A datasheet can state that the counter of a timer is unaffected by the
transition into and out of sleep. That timer does not stop. That timer counts
the full length of the park. That length comes from the wall clock.

A chip in sleep can keep an oscillator in operation. The same chip can remove
power from the counter that this oscillator feeds.
