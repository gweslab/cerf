# LEDs and LED buttons

An LED is a host widget in the status bar.

## The shape

The peripheral or board service that owns the LED registers also implements
`HostWidget`. It registers itself with `HostWidgetRegistry` in `OnReady`, and
`Group()` returns `WidgetGroup::Indicator`.

- **Draw anti-aliased.** `HostGdiPlus::FillCircleAA(dc, cx, cy, r, fill, rim)`
  draws the dot. The fill carries lit or dark. The rim carries a second bit,
  usually blink mode.
- **Repaint through `PollDirty`.** An LED carries no data path, so `MarkRx`
  and `MarkTx` never fire for it. Keep the drawn appearance in members that
  only the UI thread touches.
- **Compute the blink phase in `PollDirty`.** Count its own ticks, or read
  `GetTickCount()`.
- **Read the state under the lock.** Then draw from that copy, outside the
  lock. The guest writes the registers on the JIT thread, and the UI thread
  reads them.
- **Serialize the registers only.** The blink tick and the last-drawn members
  belong to the UI thread.

## Variants

- **On-chip LED unit.** `cerf/socs/vr41xx/vr41xx_led_impl.h` - the VR41xx unit
  blinks in hardware, so the registers hold the on-time and the off-time.
  `PollDirty` converts those units into its own ticks.
- **LED behind a companion MCU.** `cerf/boards/jornada720/jornada720_led.h` -
  the LED has no MMIO of its own. The class is a plain `Service`, and the MCU
  command handler calls `SetState()` from the JIT thread.
- **One block that drives more than an LED.**
  `cerf/boards/smdk2410_devemu/devemu_nled.cpp` - two channels, where the
  second one is a vibrator. One widget draws both: the dot for the LED, and
  chevrons beside it for the vibrator.
- **A row of LEDs.**
  `cerf/boards/odo_arm720/odo_arm720_hkeep_fpga.cpp` - one widget holds eight
  discrete debug LEDs, as a 4x2 grid of `Rectangle` cells. The tooltip carries
  the four-character alpha display of the same block. Combine the LEDs of one
  block into one widget.

## Pressable LED buttons

Some boards put a button in the LED. The LED and its button are one widget.

- `OnPrimaryAction()` presses the button.
- `BuildMenu()` offers the same press as a named item.
- **The press drives the pin that the board wires.** The Jornada 720 button is
  GPIO 13. `OnReady` drives that input to its idle level, and the press drives
  the edge. The guest driver turns that edge into an interrupt.
