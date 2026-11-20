---
name: supported-devices
description: Update the supported-boards list after work on a board (only user triggered, no agent self-invocation).
---

# supported-devices - sync the boards list with what just landed

The user invoked `/supported-devices`. Update the row of the board and the row of its family in `libCerfCore/db.json`, so that they agree with the board work of this session. The devices page of the website renders from these rows.

**User-invoked only.** Only the user triggers this skill by typing `/supported-devices`. An agent never invokes it on its own initiative - landing board work is not a license to edit the boards list.

## Procedure

1. Open `libCerfCore/db.json`. Read a nearby `board_families` row and a nearby `boards` row. Those rows are the schema.
2. For a whole-board bring-up: if the family has no row, append one to `board_families`. If the board has no row, append one to `boards`. Copy the shape of nearby rows, not a field list from memory. The `id` of the board is exactly the value that `cerf.json board.id` names. Set the `support_level` of the board from what runs now. If the SoC is new, also add its `socs` and `soc_families` rows.
3. For part work, and for a bring-up in step 2: make `device_specs` agree with what runs. Read `agent_docs/database.md` § Device specs first. Each part has one of three states:
   - `{ "generic_part_id": "x", "supported": true }` - the hardware is present and works in CERF
   - `{ "generic_part_id": "x", "supported": false }` - the hardware is present on the real board, and CERF does not support it
   - item absent - the board has no such hardware (never write `false` for hardware that does not exist)

   A `generic_part_id` is valid only when the `device_generic_parts` table declares it. A family holds an item only when every member has it unchanged. Otherwise each member that has the part holds its own item.

## What to flip - and what not to

- **Flip only what you know.** You worked on the board/part, so you know which parts you brought up, which exist but stay unsupported, and which the hardware simply lacks. Do not guess states for parts you didn't touch and can't verify - leave them as they are.
- **`notes` stay blank.** Never write or propose notes from this skill - a new device row carries an empty `notes` array, and existing rows' notes are left untouched.

## Git

Do **not** run any git command unless the user explicitly asks (e.g. "stage your changes", "commit"). When they do, `libCerfCore/db.json` is the changeset.
