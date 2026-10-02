---
name: changelog-append
description: Add a changelog entry for a change that was just made (only user triggered, no agent self-invocation).
---

# changelog-append - record one change in the changelog

The user invoked `/changelog-append`. Add one concise entry for the change just made, then regenerate the README.

**User-invoked only.** Only the user triggers this skill by typing `/changelog-append`. An agent never invokes it on its own initiative - finishing a change is not a license to write the changelog.

## Categories

Each change goes under one **component group** and one **subcategory**. Order and emoji are applied by `tools/changelog.py`; the YAML only names the keys.

Component groups:

- **`devices`** - a board/device: new board support, per-board fixes (touch, sound, screen), on-board silicon (SoC RTC, suspend, battery, reset), PC cards / PCMCIA (NE2000, CompactFlash, modem), sleeves.
- **`emulator`** - the CERF core (`cerf.exe`): JIT / MMU / CPU, VFP/NEON, host UI/UX, hibernation/state saving, the serial stack, host-OS compatibility, board detection, crashes, general fixes.
- **`launcher`** - the launcher tool.
- **`ce_apps`** - CERF-built CE binaries and shipped tools (xplorer, romdump, `tools\fileserver.py`, bundled CE apps).
- **`guest_additions`** - the Guest Additions subsystem: display driver, ROM injection, mouse/keyboard, shared folders, task manager, DPI, resolution.
- **`website`** - the cerf.cx docs site.

Subcategories:

- **`new`** - an addition: board support, a new feature/app, a redesign or overhaul.
- **`fixed`** - a bug fix, or an improvement/update to existing behavior.
- **`deleted`** - a removal.

## Procedure

`docs/changelog.yml` is the source; the README table and the website changelog page are generated from it.

1. **Open `docs/changelog.yml`.** The **latest version is the topmost list entry** (currently `TBA` at the top).
2. **Pick the group + subcategory** from the legend above. If that `group:` / `subcat:` key already exists in the top entry, append your line to its `|` block; otherwise add the key (a `|` literal block) in any order. Do not create a new version entry. Do not touch older entries.
3. **Write one raw line.** Plain string - no escaping; colons and `<`, `&`, quotes are fine. `**text**` renders bold. Strip a prefix that just repeats the group (`Guest Additions:`, `Launcher:`), but keep a board name that says which device (`NEC MP700:`, `Zune 30:`).
4. **Run `python compile_readme.py`** (from repo root). Confirm it prints `README.md compiled (vX.Y)`.

## Writing the entry

- **A changelog line, not narration.** State what changed to the product, in the fewest words that are still clear. Smaller is better.
- **One line per change.** If the work spans clearly separate user-visible changes, add one line each - but do not pad; prefer a single tight line.
- **No conversation echoes**, no session history, no model/agent references, no "as you asked".

Example top entry after adding a device fix and a guest-additions feature:

```yaml
- version: v6.6
  date: TBA
  devices:
    fixed: |
      Fixed Device Emulator crash booting Windows Mobile 5.2 ROMs
  guest_additions:
    new: |
      Clipboard sharing with the host
```

## Git

Do **not** run any git command unless the user explicitly asks (e.g. "stage your changes", "commit"). When they do, the changelog edit **and** the regenerated `README.md` are both part of the changeset - include both.
