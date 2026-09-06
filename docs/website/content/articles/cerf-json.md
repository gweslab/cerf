# cerf.json - the configuration files

JSON files in the CERF directory describe a device instance. Everything in them lands in one place:
the configuration that CERF builds for that instance at startup.

There are **three layers**, read in this order:

| # | File | Where | Written by |
| --- | --- | --- | --- |
| 1 | `cerf.json` | next to `cerf.exe` | ships with CERF. The launcher and CERF both edit it |
| 2 | `cerf.json` | `devices/<name>/` | ships with the ROM bundle. The remote repository owns it |
| 3 | `cerf-user.json` | `devices/<name>/` | the launcher, on your behalf - optional |

CERF applies each layer on top of the previous one, key by key. CERF applies the command line last,
so a flag always wins over a file. Every field is optional, and CERF runs when none of them are
present.

CERF ignores unknown keys. If a file is unreadable or malformed, CERF names the file and the key,
then exits.

## Layer 1 - the global `cerf.json`

One file next to `cerf.exe`, shared by every device instance on the installation. CERF folds its
values into each device's configuration before it reads that device's own file.

```json
{
  "device": "cerfos",
  "video_driver_names_for_guest_additions": [
    "ddi.dll",
    "s3c2410disp.dll"
  ],
  "bundle_repositories": [
    { "url": "https://cerf-bundles.dz3n.net/cerf-bundles", "enabled": true }
  ],
  "last_save_state_mode": false,
  "discord_rich_presence": false,
  "host_key": [162, 164]
}
```

| Key | Type | Meaning |
| --- | --- | --- |
| `device` | string | The device directory to boot when the command line has no `--device=`. |
| `video_driver_names_for_guest_additions` | array of strings | The ROM display-driver module names that [Guest Additions](features.md#guest-additions) can replace with the CERF driver. |
| `bundle_repositories` | array of `{ url, enabled }` | The [ROM bundle repositories](bundle-repositories.md) that the launcher installs and updates from. Launcher only - `cerf.exe` does not read it. |
| `last_save_state_mode` | boolean | The default state of **Save the state** in the shutdown dialog. |
| `update_channel` | string | Which CERF builds the launcher offers you: `disabled`, `stable`, or `unstable`. Launcher only - `cerf.exe` does not read it. |
| `discord_rich_presence` | boolean | Publish the device that you run to Discord. Read by both the launcher and `cerf.exe`. |
| `host_key` | integer, or array of integers | The host key: one virtual-key code, or up to eight of them that you press together. Absent, the host key is Right Ctrl (`163`). |

!!! tip "Adding your own display driver name"

    `video_driver_names_for_guest_additions` lists the ROM modules that Guest Additions can replace.
    It carries the driver names that CERF knows. If your own dump has a display driver under another
    name, Guest Additions finds nothing to replace and stays off. Add that module name to the list.

`last_save_state_mode` is the one key that CERF writes back. When you tick **Remember choice** in
the shutdown dialog, CERF stores your answer here. When you upgrade CERF, the installer merges the
new file into your existing one. It keeps every value that you already have, so your own edits
survive.

## Layer 2 - the device `cerf.json`

This file lives inside the device directory next to the ROM. It is what makes a directory of files
a bootable device.

```json
{
  "meta": {
    "device_name": "HP Jornada 720",
    "os": { "name": "Handheld PC 2000", "ver_major": 3, "ver_minor": 0 },
    "device_year": 2000
  },
  "board": { "id": "jornada_720" },
  "rom": {
    "primary": "jornada720.bin",
    "eeprom": "jorn720_eeprom.bin"
  }
}
```

Two keys carry the whole boot. `board.id` selects the board that CERF emulates. `rom.primary` names
the file that boots. Everything else is optional.

### `board`

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | The board that CERF emulates. `cerf.exe --help` lists every id. |
| `configurable_screen_width` | integer | The screen width on a board whose resolution is not fixed, and for the Guest Additions display. |
| `configurable_screen_height` | integer | As above, the height. |
| `configurable_screen_dpi` | integer | The display DPI that CERF reports to the guest. Guest Additions only. |
| `configurable_screen_bpp` | integer | The display colour depth in bits per pixel. Absent, CERF picks the depth. |

### `rom`

| Key | Type | Meaning |
| --- | --- | --- |
| `primary` | string | The file that boots. A filename inside the device directory, or an absolute path. |
| `extensions` | array of strings | Extra ROM partitions that CERF loads after the primary one. |
| `recovery` | string | An alternative image. CERF boots it only with `--recovery`. |
| `eeprom` | string | A serial configuration EEPROM image, for a board that has one. |

The `rom` block is where the boards stop looking alike. Most devices need one line - `primary`.
Some need more, because the hardware has more. The Jornada 720 has a configuration EEPROM on its
SSP bus, and its EEPROM peripheral loads `rom.eeprom` to serve it. The Zune 30 ships a recovery
image next to its main one. **What a device can declare here follows from what its board
implementation reads.**

### The rest

| Key | Type | Meaning |
| --- | --- | --- |
| `network.enabled` | boolean | The network backend. The same as `--disable-network` inverted. |
| `network.mac` | string | The guest MAC, `XX:XX:XX:XX:XX:XX`. |
| `network.mtu` | integer | 64 to 9000. |
| `network.forward_tcp`, `network.forward_udp` | string | Host-to-guest port forwards. |
| `guest_additions` | boolean, or `{ enabled, override_color_scheme }` | Boot with Guest Additions, and the color scheme that the guest driver applies. |
| `full_screen` | boolean | Enter borderless full screen at startup. |
| `adopt_guest_additions_resolution_for_host_screen` | boolean | Size the Guest Additions display to the host monitor instead of the configured resolution. |
| `share_folder` | string | A host folder that CERF mounts into the guest. Guest Additions only. |
| `additional_packages.compact_flash_cards` | array of `{ file, name, insert_on_launch }` | CF card images that ship with the ROM. Each one appears in the card insert menu. When `insert_on_launch` is `true`, CERF inserts that card automatically at boot. |
| `meta` | object | Who the device is: `name`, `device_name`, `device_year`, and `os` (`name`, `ver_major`, `ver_minor`). |

`meta` is descriptive, not operational. CERF displays it, and the launcher lists it. CERF takes
nothing about the boot from it: the board comes from `board.id`, and CERF reads everything else out
of the ROM. The launcher understands a few more `meta` fields than `cerf.exe` does (a description,
notes, the OS language and build, and the origin of the dump). This text is for the catalog and
changes nothing at runtime.

## Layer 3 - `cerf-user.json`

This file has the same format and the same keys, in the same device directory. CERF applies it
after `cerf.json`, so anything in it wins. The file is optional, and a device that you never
configured does not have one.

The launcher keeps a device from a bundle repository up to date. When the catalog metadata changes,
the launcher **rewrites that device's `cerf.json` wholesale**, and anything that you put in that
file is lost. The launcher therefore writes your choices here instead:

```json
{
  "launcher": {
    "repository_url": "https://cerf-bundles.dz3n.net/cerf-bundles",
    "name_on_repository": "devemu_ce5"
  },
  "meta": { "name": "My CE 5 box" },
  "guest_additions": { "enabled": true },
  "board": { "configurable_screen_width": 800, "configurable_screen_height": 600 },
  "network": { "enabled": false },
  "full_screen": false
}
```

- **`launcher`** - the repository that this device directory came from, and its name there. This
  block is the update link: the launcher uses it to know that a newer bundle applies to this
  directory. A device that you created from your own dump has no such block.
- **`meta.name`** - your display-name override, from **Rename** in the launcher.
- **The launch options** - every switch in the launcher's *Configuration* panel: Guest Additions
  and its color scheme, the resolution and DPI override, full screen, and the network toggle. The
  launcher stores only the ones that you changed away from the device's own default.

A ROM upgrade replaces the ROM and rewrites `cerf.json`. It does not touch `cerf-user.json`, so
your configuration is still there afterwards.

!!! note "Configuration here, ROM in layer 2"

    `cerf-user.json` goes through the same loader as `cerf.json`, so any key from layer 2 is legal
    in it. This includes `rom.primary`. But a ROM pointer here outlives the bundle that it belongs
    to. After an upgrade replaces the ROM file, the pointer still names the old file, and it wins.
    The device then does not boot. Keep this file for your own configuration, and let layer 2
    describe the ROM.

## Order of application

```
global cerf.json  ->  devices/<name>/cerf.json  ->  devices/<name>/cerf-user.json  ->  command line
```

Later wins.

A hand-written device needs neither layer 1 nor layer 3.
[Running your own ROM](own-rom.md) shows the two-key `cerf.json` that boots a dump.
