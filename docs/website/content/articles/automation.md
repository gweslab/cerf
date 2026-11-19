# Automation API

Bet you always wanted to automate your Windows CE experience? **That's now possible.** We bundle the Python automation API since CE Runtime Foundation 10.

!!! question "**Desktop** platform is required."

Automation lets you do bare minimum what you need and might evolve later:

- Launch, connect, halt, reset emulator from Python script
- Tap, click, move mouse, press buttons, type text
- Control PC Cards and other machine objects (the ones you usually see in status bar)
- Control save states, take and read screenshots

## Prerequisites

- Python 3
- The `tools/cerf_automation` package inside your emulator's installation directory

## Start the emulator with automation

Starting the emulator:

```python
with Cerf.spawn("jornada720") as cerf:
    ...
```

!!! warning "The emulator closes when the `with` block ends."

More complex scenario for instance management (might be more useful for LLMs using CERF). Start the emulator yourself with the fixed endpoint name you pick:

```
cerf.exe --device=jornada720 --automation=my_test
```

Connect to your endpoint:

```python
from cerf_automation import Cerf

cerf = Cerf.connect(endpoint="my_test", wait=60)
```

!!! info "Automation can be turned on only when the emulator boots. If you want to connect your running instance - you should save its state and restart with automation (`--automation=NAME --boot=resume`)."

## First script

```python
import time
from cerf_automation import Cerf

with Cerf.spawn("jornada720") as cerf:
    time.sleep(30)
    cerf.tap(320, 120)
    time.sleep(2)
    cerf.type_text("hello")
    cerf.press_key("VK_RETURN")
    time.sleep(2)
    cerf.frame().save_png("screen.png")
```

Here is what this script does:

1. Waits 30 seconds for device to boot
2. Taps the screen
3. Prints "hello"
4. Presses Enter
5. Saves a screenshot

!!! example
    - Receive screen size from  `cerf.screen.size()` if you need.
    - See more examples in `tools/cerf_automation/examples`

## Common tasks

### Mouse/stylus

- `cerf.tap(x, y)` - tap or LMB 
- `cerf.tap(x, y, button="right")` - RMB
- `cerf.drag([(10, 10), (100, 100)])` - drags through points
- `cerf.pointer.wheel(x=100, y=100, delta=120)` - turn the mouse wheel

### Keyboard/keypad

- `cerf.press_key("VK_RETURN")` - press Enter. Use Win32 VKs.
- `cerf.type_text("Hello, world!")` - uses keyboard and types a text for you
- `cerf.keyboard.ctrl_alt_del()` - ctrl+alt+del

### Generate CF card

```python
cerf.socket.insert(path=["cf_slot"], type="cf", command="generate_fat32",
                   answers={"compact_flash_documents": [r"C:\files\readme.txt"],
                            "compact_flash_size_mb": 32,
                            "compact_flash_output_image": r"C:\cards\test.img"})
```

This does the following:
1. Emulator writes your files into FAT32 image
2. Puts it into your Card slot

- If you want FAT16 - use `generate_fat16` instead.
- `cerf.objects.list()` - list available slots
- `cerf.socket.eject(path=["cf_slot"])` - eject the `cf_slot`

### Automatic touch clibration

```python
cerf.calibration.run(calibrate=True)
# Returns `finished` or `failed`.
```

### Multi-instance

Give each emulator its own name:

```python
a = Cerf.spawn("jornada720", name="test_a")
b = Cerf.spawn("jornada820", name="test_b")
```

### Reset, save, load and close

- `cerf.shutdown.run(action="soft_reset")` - reset a device, or `hard_reset` for a cold reset
- `cerf.state.save(path=r"C:\states\test.img")` - save the state, or `cerf.state.load(path=...)` to load one.
- `cerf.shutdown.run(action="exit")` kill the emulator, or `save_state_exit` - die and save the state at regular path.

### Screenshots and pixels

- `cerf.frame()` - geth the screen
- `frame.save_png("shot.png")` - save the screen(shot)
- `frame.pixel(x, y)` - get pixel color as (red, green, blue).

## All commands

List your instance's command by running the following commands in your `tools` folder:

```
python -m cerf_automation --endpoint my_test describe
python -m cerf_automation --endpoint my_test call keyboard.ctrl_alt_del
python -m cerf_automation --endpoint my_test watch guest.suspend
```

## Other languages

!!! info "The emulator speaks JSON-PRC 2.0. You can write clients in more languages if you want some."
