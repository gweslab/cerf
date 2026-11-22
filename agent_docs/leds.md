# LEDs and LED buttons

An LED is a lamp of the device. libCerfCore describes each LED as a machine
object. The HUD of the board shows it.

## The shape

The peripheral or board service that owns the LED registers also implements
`MachineLamp`.

- **Describe the lamp, never draw it.** The dark color, the look and the size
  belong to the frontend.
- **Read the state under the lock.** Then build the `LampState` from that copy,
  outside the lock. The guest writes the registers on the JIT thread, and the
  frontend reads the lamp on its own thread.
- **Serialize the registers only.** The visible blink phase is not guest state.
- **An on-chip LED unit gives a fallback color.** The chip does not know which
  LED the maker fitted. A board whose LED color is known gives it in the `led_color`
  field of its row in `libCerfCore/db/boards/`.

## Variants

- **On-chip LED unit.** `libCerfCore/src/socs/vr41xx/vr41xx_led_impl.h` - the
  VR41xx unit blinks in hardware.
- **LED behind a companion MCU.** `libCerfCore/src/boards/hp_jornada_700/hp_jornada_700_led.h` -
  the LED has no MMIO of its own.
- **One block that drives more than an LED.**
  `libCerfCore/src/boards/samsung_smdk2410/samsung_smdk2410_nled.cpp` - two
  channels, where the second one is a vibrator. The vibrator is a
  `MachineVibrator` child of the lamp.
- **A row of LEDs.** `libCerfCore/src/boards/odo/odo_hkeep_fpga.cpp` - eight
  discrete debug LEDs are `MachineLamp` children of the four-character
  `MachineCharacterDisplay` of the same block.
- **One package with two elements.** A `MachineLamp` child of a lamp is a second
  element of the same LED, never a lamp of its own.

## Pressable LED buttons

Some boards put a button in the LED.

- **A button on a pin of its own is a `MachineButton` child of the lamp.** The
  press drives the pin that the board wires, and the release drives it back.
  `OnReady` drives the pin to its idle level. The pin stays at its pressed level
  for as long as the person holds the button.
  A restore drives the pin back to its idle level, because no host holds the
  button after a restore.
- **A button on the keyboard matrix is a key of the stock keyboard.** The HUD
  presses that key, and no `MachineButton` drives the same cell.

## On the HUD

- **Every board with a lamp shows the lamp on its HUD.** A board with no HUD
  preset gets a preset that holds the lamp alone.
- **The status bar shows no lamp and no character display.**
- **The vibrator is not a lamp, and the HUD does not show it.**
