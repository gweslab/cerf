---
name: supported-devices
description: Update the supported-boards list after work on a board (only user triggered, no agent self-invocation).
---

# supported-devices - sync the boards list with what just landed

The user invoked `/supported-devices`. Update the board's row in `bundled/db.json` to match the board work done this session, then regenerate the README.

**User-invoked only.** Only the user triggers this skill by typing `/supported-devices`. An agent never invokes it on its own initiative - landing board work is not a license to edit the boards list.

## Procedure

1. **Open `bundled/db.json` and read a neighbouring `devices` row.** That row is the schema - it is current, and any column list written elsewhere goes stale. `agent_docs/database.md` covers the rule for what belongs in the database at all, not the columns.
2. **Whole-board bring-up:** append the board's row to `devices` if absent, copying the shape of a neighbouring row rather than a field list from memory - the neighbour is current, any list written here goes stale the next time the schema grows. Its `id` is exactly what `cerf.json board.id` names, and `operating_system_ids` covers the OSes the board actually boots in this cerf version. Set `"supported": true` if the board is now user-ready (`false` = early WIP, hidden by default). Add the `socs` and `soc_families` rows too when the SoC is new.
3. **Feature work (also part of case 2 above):** sync `device_features` to reality. Three states, apply them exactly:
   - `{ "feature_id": "x", "supported": true }` - hardware present AND working in CERF
   - `{ "feature_id": "x", "supported": false }` - hardware present on the real board but unsupported in CERF
   - **entry absent** - the board has no such hardware (never write `false` for hardware that doesn't exist)

   Only `feature_id` values declared in the `device_features` table are valid.
4. **Run `python compile_readme.py`** (from repo root) to regenerate `README.md`. Confirm it prints `README.md compiled (vX.Y)`.

## What to flip - and what not to

- **Flip only what you know.** You worked on the board/feature, so you know which features you brought up, which exist but stay unsupported, and which the hardware simply lacks. Do not guess states for features you didn't touch and can't verify - leave them as they are.
- **`notes` stay blank.** Never write or propose notes from this skill - a new device row carries an empty `notes` array, and existing rows' notes are left untouched.

## Git

Do **not** run any git command unless the user explicitly asks (e.g. "stage your changes", "commit"). When they do, `bundled/db.json` **and** the regenerated `README.md` are both part of the changeset - include both.
