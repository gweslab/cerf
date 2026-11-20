---
name: supported-devices
description: Update the supported-boards list after work on a board (only user triggered, no agent self-invocation).
---

# supported-devices - sync the boards list with what just landed

The user invoked `/supported-devices`. Update the board row and the family row in the board database, `libCerfCore/db/`. They must agree with the board work of this session. The devices page of the website renders from these rows.

Only the user triggers this skill by typing `/supported-devices`. An agent never invokes it on its own initiative. Board work that lands is not a license to edit the boards list.

## Procedure

1. Read `agent_docs/database.md` § Files. Then read a nearby row in `libCerfCore/db/board_families/` and a nearby row in `libCerfCore/db/boards/`. Those rows are the schema.
2. For a whole-board bring-up: if the family has no row, add one to `board_families/`. If the board has no row, add one to `boards/`. Copy the shape of nearby rows, not a field list from memory. The name of the row is the `id` of the board, exactly the value that `cerf.json board.id` names. Set the `support_level` of the board from what runs now. If the SoC is new, also add its rows to `socs/` and `soc_families/`.
3. For part work, and for a bring-up in step 2: make `device_specs` agree with what runs. Read `agent_docs/database.md` § Device specs first. Each part has one of three states:
   - `{ "generic_part_id": "x", "supported": true }` - the hardware is present and works in CERF
   - `{ "generic_part_id": "x", "supported": false }` - the hardware is present on the real board, and CERF does not support it
   - item absent - the board has no such hardware (never write `false` for hardware that does not exist)

   A `generic_part_id` is valid only when `device_generic_parts/` declares it.

## What to change

- Change only the states that you know. You worked on the board or the part, so you know which parts you brought up, which exist but stay unsupported, and which the hardware lacks. Do not guess the state of a part that you did not touch and cannot make sure of. Leave it as it is.
- Leave `notes` blank. Never write or propose notes from this skill. A new device row carries an empty `notes` array, and the notes of existing rows stay as they are.

Do not run any git command unless the user explicitly asks, for example "stage your changes" or "commit". When the user asks, the files under `libCerfCore/db/` are the changeset.
