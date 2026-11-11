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
merge by `feature_id`, `board_config` merges by parameter, and the `notes` of a
board add to the notes of the family.

The code of a family serves every member. It reads a fact that differs
between members, for example the SoC or the RAM size, from the row of the
member. A member with no ROM image is still a member, so the code never limits
itself to the members that have a ROM image.

A member can differ in a part that CERF does not model yet. The member then
runs the family code for that part, and its support level records the
difference.

For example, a regional member has another keyboard layout. Its keys sit on
the same matrix pins as the keys of the baseline, so the family keyboard works
on it. Only some key labels or host key bindings are wrong for that member.
Another member has a part that the baseline lacks, such as a built-in modem.
The family code runs on that member, and the member has no modem in CERF.

Running the family code on such a member is not a guessed implementation.
Code never takes a family service away from a member. A board id check in
`ShouldRegister` that skips the member, or a halt on that member, is such a
removal. A member is `bootable_full` only when CERF models every difference
of that member.

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

## Board configuration

A board configuration parameter lets the user of one device change a fact of
its board, for example the RAM size or a memory card. Its default choice is
Auto. Auto takes the value that the family or board row gives. A real model
stays a member of its own. Its row sets the Auto value for that model. A part
that the user plugs in is never a member of its own.

A parameter is a part that a user can change on the real device. The user
solders it, plugs it in or connects it. The `values` list of the row holds every
part that a user can fit to the board. A value can break the guest, for example a
compatible panel that the ROM does not drive. A RAM size belongs in the list
when the board can take it. A size that the vendor never fitted also belongs in
the list when the guest supports it.

The order of `board_config_params` is the display order.

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

## Guest-additions palettes

A `ga_palettes` row is one palette of the guest-additions display. `bpp` is the
indexed depth of the palette. `values` holds `1 << bpp` `[red, green, blue]`
colors. The first row for a depth is the default of that depth. A device
configuration stores a chosen palette as its colors, never as its `id`. The
manager names such a palette by its colors.

## HUD presets - `libCerfCore/huds.json`

`huds.json` holds the on-screen HUDs of the frontend.

A HUD binds through `board_ids`, `board_family_ids`, or both. A HUD that names
the board wins over a HUD that names its family.

A key is the name of a Windows virtual-key code, for example `VK_RETURN`. A
button has `keys` or an `action`. An action is the id of a `DeviceButtons`
action of the board. A `sticker` is an `icon` or a short `label` in its own
cell, and it takes no press. An example is the icon that the device prints above a
key.

A `rocker` is a device rocker or dial: `up`, `down` and an optional `center` press,
with no left and right. It is one cell, so it keeps up above down when a portrait form
turns its column into a row. A device control that is not a d-pad is never a `dpad`.

Panels on one side stack outward in list order.

A cell with a `grow` of n takes n units of its row or column, together with the gaps
between those units. Cells at the same unit position in two rows or columns with the
same total `grow` line up.

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
  `namespace BoardId`. This header exists only when one member's hardware
  differs from its family and the code for that difference must name the
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
