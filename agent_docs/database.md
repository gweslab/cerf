# The board database - `libCerfCore/db.json`

`db.json` holds the board and SoC facts that CERF components share.

The file ships inside the CERF installation. It belongs to that CERF
version. A user never edits it.

## What belongs in it

A board or SoC fact belongs here when any other component can use it.
One caller today is enough.

## The shape

A field belongs to the table whose id determines it. Every SoC of one family
shares the same core, so the core is a family field.

A row states what is true of the board, and what CERF supports on it.

A set that grows when a board or a SoC arrives is a string id. A closed set
that a new board never extends is a C++ enum.

## Board families

Every board belongs to a family. A family is one platform, and the boards in
it share most of their hardware. A member differs in a small set of parts.
Examples are the panel, the keypad, a radio, the RAM or flash size, the
region, and the vendor that sells the board. A hardware revision is a member
of its own. A panel or size variant is also a member of its own.

A field on the family applies to every member. A board sets the field only
where the board differs, and the value of the board wins. `device_features`
merge by `feature_id`, and the `notes` of a board add to the notes of the
family.

The board sets `support_level`. The values are:

- `bootable_full` - a ROM of this board runs in CERF.
- `bootable_partial` - the board runs a ROM that runs in CERF. It differs only
  in hardware that CERF does not model.
- `unknown_partial` - the board never ran in CERF. Its known differences can
  still work.
- `no_support` - the board is broken in CERF, or a known difference breaks the
  guest.

`internal__spec_divergences` records why a board is its own entry. It holds
spec facts only. Each fact compares the board with the baseline of the family.
The baseline is the one board of the family that does not have the field.

A `rom_types` or `storage_types` row binds through `board_ids`,
`board_family_ids`, or both. A row with neither field binds every board.

The name of a family is the name of its platform. Use the public name of the
vendor for the platform. If no public name exists, use the name that the ROM
gives its platform. If the ROM gives no name, use the name of the design that
the other members came from.

## CPU configurations

A `cpu_configs` row with a `soc_id` is the CPU of that SoC. A row without a
`soc_id` is a shared base, not a preset. Only `inherits_cpu_config_id`
reaches it.

A row takes every value of the row that it inherits. Its own values replace
the inherited values. A SoC row and the rows that it inherits give a value to
every parameter of its architecture.

Only a fact that the silicon fixes goes into `cpu_configs`. A rate or a state
that the guest programs stays in code. The CPU clock is one example.

The order of `cpu_config_params` is the display order. Put a new parameter
next to the parameters that it relates to.

## HUD presets - `libCerfCore/huds.json`

`huds.json` holds the on-screen HUDs of the frontend.

A HUD binds through `board_ids`, `board_family_ids`, or both. A HUD that names
the board wins over a HUD that names its family.

A key is the name of a Windows virtual-key code, for example `VK_RETURN`. A
button has `keys` or an `action`. An action is the id of a `DeviceButtons`
action of the board.

The width and the height of a panel are fractions of the length of the screen
edge that the panel sits on. The screen of a HUD is the `lcd_panel_size` of one
of its bound boards. That board has the panel size that is the closest to the size
of the framebuffer.

## Where an id constant lives

Declare each id constant once, in its own header, next to the thing that it
names:

- `libCerfCore/src/boards/<family>/<family_id>_family_id.h` declares
  `namespace BoardFamilyId { inline constexpr std::string_view <Name> = "<id>"; }`
- `libCerfCore/src/boards/<family>/<board_id>_id.h` declares the same in
  `namespace BoardId`. This header exists only when a gate must name one
  member.
- `libCerfCore/src/socs/<chip>/<soc_id>_id.h` declares the same in `namespace SocId`.
  A SoC whose only tree is its core strategy keeps the header under
  `libCerfCore/src/cpu/<core>/`.

The constant name is the PascalCase of the id:
`"nec_mobilepro_900_series"` becomes `NecMobilepro900Series`.

A gate includes only the id headers that it names:

    return emu_.Get<BoardContext>().GetSocId() == SocId::Sa1110;

Do not gather these constants into one shared header.

A template that varies per SoC takes the constant by reference:

    template <uint32_t kBase, const std::string_view& kSoc>
