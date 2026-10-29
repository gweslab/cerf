--8<-- "ai-summary.md"

# Running your own ROM

CERF emulates a *whole device* - the SoC, the board, the memory map and every peripheral the ROM's
drivers touch. A ROM boots when **that board is implemented in CERF**. The same chip on another
board has different RAM and flash addresses, a different display controller and different wiring,
so a matching SoC is not enough.

In practice: a dump boots if its board is on the [supported list](/devices.md). A ROM found on the
internet for some other device will not.

## Adding a device ROM through the device list

1. Click **New** on the toolbar.
2. Pick **New device** - the option that says *"Create a device from your local ROM"*.
3. Follow the wizard: choose the board, name the device, and point it at your ROM file.

That is it. The device shows up ready to boot.

## Adding a device ROM by hand

1. Create a folder under `devices/` (next to `cerf.exe`), e.g. `devices/mydump/`.
2. Put the ROM image in it, e.g. `mykernel.nb0`.
3. Add a `cerf-user.json` naming the board and the ROM:

    ```json
    {
      "board": { "id": "jornada_720" },
      "rom":   { "primary": "mykernel.nb0" }
    }
    ```

4. Run `cerf.exe --device=mydump`.

The board id is your device's - `cerf.exe --help` lists them all. Those two keys are the minimum.
[The configuration files](cerf-json.md) covers everything else the file can carry. Both fields
can also be given on the command line instead:

```
cerf.exe --device=mydump --board-id=jornada_720 --rom-primary=mykernel.nb0
```

## What if CERF does not support the device I want to run a dump of?

[Contribute to CE Runtime Foundation](https://github.com/gweslab/cerf) - implement it yourself.
