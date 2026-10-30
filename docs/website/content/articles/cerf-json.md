# cerf.json - the configuration files

There are **three layers** of JSON configuration files:

| # | File | Where | Meaning |
| --- | --- | --- | --- |
| 1 | `cerf.json` | next to `cerf.exe` | packed in the release |
| 2 | `cerf.json` | `devices/<name>/` | a configuration of your device |
| 3 | `cerf-user.json` | `devices/<name>/` | same, but stores only overrides by user |

CERF applies each layer on top of the previous one, key by key. CERF applies the command line last,
so a flag always wins over a file.

```
global cerf.json  ->  devices/<name>/cerf.json  ->  devices/<name>/cerf-user.json  ->  command line
```

Later wins. Below is an unfinished description of schema. Some values are absent from here.

## Layer 1 - the global `cerf.json`

| Key | Type | Meaning/values |
| --- | --- | --- |
| `device` | string | The device directory to boot when the command line has no `--device=` |
| `bundle_repositories` | array of `{ url, enabled }` | The [ROM bundle repositories](bundle-repositories.md) |
| `last_save_state_mode` | boolean | **Save the state** checkmark state in shutdown window |
| `update_channel` | string | `disabled`, `stable`, or `unstable`. |
| `discord_rich_presence` | boolean | - |
| `tutorial_finished` | boolean | - |
| `host_key` | integer, or array of integers | One VK or max 8 VKs. Absent: Right Ctrl (`163`). |
| `default_scale` | integer | Integer scaling at start. `0` (Dynamic), `1` (Original view), `2`, `3`, or `5`. Absent: `0`. |
| `host_branch` | string | `win32-x86`, `linux-amd64`, `macos-arm64`, `android-arm64`, `android-amd64`. Reserved: `windows-amd64`, `windows-arm64`, `linux-arm64`. Absent: `win32-x86`. |

## Layer 2 - the device `cerf.json`

### `board`

| Key | Type | Meaning/values |
| --- | --- | --- |
| `id` | string | the board ID cerf emulates from `db.json` |
| `configurable_screen_width` | integer | device models a panel with dynamic resolution - width |
| `configurable_screen_height` | integer | as above |
| `configurable_screen_dpi` | integer | as above |
| `configurable_screen_bpp` | integer | as above |

### `rom`

Devices define their own keys since sources may vary accross devices. Here are some generic but not all:

| Key | Type | Meaning/values |
| --- | --- | --- |
| `primary` | string | a generic ROM path if a device support it. Most of devices share this key |
| `recovery` | string | alternative to `primary` but boots with `--recovery` (FIXME: wait, i thought i removed it) |
| `eeprom` | string | Used for devices which have one EEPROM dump |
| `lumia800_user_area_erase` | string | Lumia 800 specific firmware package file |

### `storage`

Identical conception as above but for writable persistant user storage.

| Key | Type | Meaning |
| --- | --- | --- |
| `nand` | string | A NAND flash image, relative to the device directory. Absent, `nand.img`. |
| `hdd` | string | A hard disk image, relative to the device directory. Absent, `hdd.img`. |
| `emmc` | string | An eMMC image, relative to the device directory. Absent, `emmc.img`. |

### Network

| Key | Type | Meaning |
| --- | --- | --- |
| `network.enabled` | boolean | The same as `--disable-network` inverted. |
| `network.mac` | string | The guest MAC, `XX:XX:XX:XX:XX:XX`. (FIXME: there can be one MAC per a network device and CERF lets you to use several at once. Do we increment the MAC or something? I forgot) |
| `network.mtu` | integer | 64 to 1500. |
| `network.forward_tcp`, `network.forward_udp` | string | Host-to-guest port forwards. I don't know if it still works, nobody tested it since CERF v1 |

# Guest Additions

| Key | Type | Meaning |
| --- | --- | --- |
| `guest_additions.enabled` | boolean | The same as `--guest-additions`. |
| `guest_additions.override_color_scheme` | string | The same as `--ga-color-scheme`. |
| `guest_additions.override_font_size` | integer | same as `--ga-font-size`. |
| `guest_additions.override_cleartype` | boolean | - |
| `guest_additions.allow_untrusted_apps` | boolean | - |
| `guest_additions.share_folder` | string | The same as `--ga-share-folder`. |
| `guest_additions.shared_folder_mount_point` | string | - |
| `guest_additions.autorun` | array of strings | Guest paths. When the shell is up, the guest driver starts each path, in order. `--ga-autorun=PATH` replaces the array. (FIXME: should we add this to UI?) |

# Rest

| Key | Type | Meaning |
| --- | --- | --- |
| `full_screen` | boolean | - |
| `double_tap_helper` | boolean | A double tap at single coordinate helper for Android |
| `throttle_multiplier` | number | - |
| `cpu_rate_multiplier` | number | - |
| `hud` | string | `none`, or a HUD id from `huds.json`. Absent: the HUD of the board. |
| `additional_packages.compact_flash_cards` | array of `{ file, name, insert_on_launch }` | CF cards from a ROM bundle that are displayed in UI and might be auto-attached at launch |
| `meta` | object | Who the device is: `name`, `device_name`, and `os` (`name`, `ver_major`, `ver_minor`). Pure metadata. |

## Layer 3 - `cerf-user.json`

Identical to `cerf.json`. Conception is that `cerf.json` is a ROM bundle's one that changes only on ROM bundle updates, and `cerf-user.json` is where you dump all your personal overrides. Second is applied over first. Your data is never lost on ROM bundle updates.
