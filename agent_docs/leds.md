# LEDs and LED buttons

An LED is a lamp of the device. libCerfCore describes each LED as a machine
object.

## The shape

The peripheral or board service that owns the LED registers also implements
`MachineLamp`.

- **Describe the lamp, never draw it.** The dark color, the rim and the size
  belong to the frontend.
- **Read the state under the lock.** Then build the `LampState` from that copy,
  outside the lock. The guest writes the registers on the JIT thread, and the
  frontend reads the lamp on its own thread.
- **Serialize the registers only.** The visible blink phase is not guest state.

## Variants

- **On-chip LED unit.** `libCerfCore/src/socs/vr41xx/vr41xx_led_impl.h` - the
  VR41xx unit blinks in hardware.
- **LED behind a companion MCU.** `libCerfCore/src/boards/hp_jornada_700/hp_jornada_700_led.h` -
  the LED has no MMIO of its own. The class is a plain `Service`, and the MCU
  command handler calls `SetState()` from the JIT thread.
- **One block that drives more than an LED.**
  `libCerfCore/src/boards/samsung_smdk2410/samsung_smdk2410_nled.cpp` - two
  channels, where the second one is a vibrator. The vibrator is a
  `MachineVibrator` child of the lamp.
- **A row of LEDs.** `libCerfCore/src/boards/odo/odo_hkeep_fpga.cpp` - eight
  discrete debug LEDs are `MachineLamp` children of the four-character
  `MachineCharacterDisplay` of the same block.

## Pressable LED buttons

Some boards put a button in the LED. The button is a `MachineButton` child of
the lamp.

- **The press drives the pin that the board wires.** The Jornada 720 button is
  GPIO 13. `OnReady` drives that input to its idle level, and the press drives
  the edge. The guest driver turns that edge into an interrupt.
