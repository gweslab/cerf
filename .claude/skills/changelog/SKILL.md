---
name: changelog
description: Add a changelog line for a change that was just made, add a patch line to a released version, or bump the CERF version (only user triggered, no agent self-invocation).
---

# changelog - record a change in the changelog

The user invoked `/changelog`. Pick the mode from the request:

- a change in the development tree: § Change line
- a patch of a released version: § Patch line
- a new version number: § Bump

Only the user triggers this skill. The user types `/changelog`, or runs `/hotfix`, which runs this skill as one of its steps. An agent never invokes it on its own initiative. A finished change does not give you permission to write the changelog.

`docs/changelog.yml` is the source of the changelog. The top entry is the version in development. Each entry below it is a released version. When the user asks for a commit, the changeset is the changelog edit, together with `cerf-qt/version.h` after a bump.

## Bump

Run `python tools/bump_version.py <part>` with the part that the user names: `patch`, `minor` or `major`. The script changes `cerf-qt/version.h`. For `minor` and `major`, it also adds the placeholder entry of the new version. A patch bump adds no line, and § Patch line tells where the line of a patch goes.

## Change line

1. Open `docs/changelog.yml` and use the top entry. Do not add a version entry. Do not change older entries.
2. Pick the group and the subcategory from § Categories. If the top entry already has that `group:` / `subcat:` key, add your line to its `|` block. If not, add the key with a `|` literal block, in any order. If the top entry still has the placeholder from § Bump, delete the placeholder.
3. Write one raw line as a plain string with no escapes. Colons, `<`, `&` and quotes are correct as they are. `**text**` shows as bold. Delete a prefix that only repeats the group (`Guest Additions:`, `Launcher:`). Keep a board name that tells which device the line is about (`NEC MP700:`, `Zune 30:`).

## Patch line

A patch is a new release of a version that is already released. A patch never gets an entry of its own, so never add a `v<major>.<minor>.<patch>` entry. Its line goes into the entry of the version that it patches, `v<major>.<minor>`. That entry is usually not the top entry.

1. Find the entry of the patched version. Do not change its `date`, which stays the release date of `<major>.<minor>`.
2. Add one line to the `patches:` / `fixed:` block of that entry, as `Patch N: <change>`. If the entry has no such block, add it. When one patch has several changes, they share its line and `; ` separates them.
3. Use the patch number of the new release as `N`. It is the `CERF_VERSION_PATCH` of `cerf-qt/version.h` on the branch `release-<major>.<minor>`, after `python tools/bump_version.py patch`. If that branch does not exist yet, `N` is 1 more than the patch number of the release commit of `<major>.<minor>`. The last `Patch` line of the entry has `N - 1`, or the entry has no `Patch` line and `N` is 1. If the numbers do not agree, tell the user before you write the line.
4. Use the text that the user gives for the line. If the user gave no text, write the line yourself. Then tell the user in bold that you wrote the text, so that the user can replace it.

## Categories

Each line goes under one component group and one subcategory. Write only their keys, because `tools/changelog.py` adds the order and the emoji.

Component groups:

- `important`: a message for users about the whole release, not about one component, for example a required action or a known limitation. It usually has only the `important` subcategory. It shows first in the entry. Add a line only when the user asks for it.
- `devices`: a board or a device. This includes support for a new board, a fix on one board (touch, sound, screen), on-board silicon (SoC RTC, suspend, battery, reset), PC cards and PCMCIA (NE2000, CompactFlash, modem), and sleeves.
- `emulator`: the CERF core (`cerf.exe`). This includes the JIT, MMU and CPU, VFP and NEON, host UI and UX, hibernation and save states, the serial stack, host OS compatibility, board detection, crashes and general fixes.
- `launcher`: the launcher tool.
- `cerfman`: the Devices Manager. This includes the device list, downloads, device properties, settings, the installer and the self-update.
- `ce_apps`: the CE binaries that CERF builds and the tools that it ships (xplorer, romdump, `tools\fileserver.py`, bundled CE apps).
- `guest_additions`: the Guest Additions. This includes the display driver, ROM injection, mouse and keyboard, shared folders, the task manager, DPI and resolution.
- `website`: the cerf.cx site.
- `patches`: the patches of a released version, in the `fixed` subcategory only. § Patch line gives the format.

Subcategories:

- `important`: a line that users must see, for example a required action. It shows first in its group. Add a line only when the user asks for it.
- `new`: an addition, for example support for a board, a new feature or app, or a redesign.
- `fixed`: a bug fix, or an improvement of existing behavior.
- `deleted`: a removal.

## Writing the line

- Write a changelog line, not a story. Tell what changed in the product, in the fewest words that are still clear.
- Write one line for each change that users can see. Do not add lines to fill space. One short line is better.
- Write nothing from the conversation: no session history, no mention of a model or an agent, no "as you asked".

This example top entry has an important message, a device fix and a Guest Additions feature:

```yaml
- version: v6.6
  date: TBA
  important:
    important: |
      Save states from v6.5 do not load in this version
  devices:
    fixed: |
      Fixed Device Emulator crash booting Windows Mobile 5.2 ROMs
  guest_additions:
    new: |
      Clipboard sharing with the host
```

This example released entry has two patches:

```yaml
- version: v8.1
  date: 10 Nov 2026
  devices:
    new: |
      NEC MobilePro 790 support
  patches:
    fixed: |
      Patch 1: Guest Additions are working again on Mobilon family
      Patch 2: Fixed broken glow effects (especially on Android)
```
