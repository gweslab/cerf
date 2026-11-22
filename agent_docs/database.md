# The board database - `libCerfCore/db/`

The board database holds the board and SoC facts that CERF components share.

The build compiles the database into one `db.json`. That file ships inside the
CERF installation. It belongs to that CERF version. A user never edits it.

## Files

The database is a tree of directories and small JSON files. The SAD compiler in
`libCerfCore/sad/` compiles it, and `libCerfCore/sad/README.md` describes the
format. Every consumer reads the compiled database, never the files of the tree.

Each table is a directory. Each row is a file named after its `id`, and the
compiler writes that name into the row. A row with `device_specs` is a directory
with the same name. Its `index.json` holds the fields of the row, and its
`device_specs/` directory holds one file for each item. The `rom_types` and
`storage_types` tables repeat an `id` on purpose, so their files have free names
and each row keeps its own `id`.

The database guarantees no row order. A reader that takes the first row of a set
gets the row that `$index` puts first:

- `$index` in each generic part sets the display order of the parts.
- The default palette of each depth has `$index`, so it comes first for its depth.
- The generic `primary` ROM type has `$index`, so the primary ROM comes first among
  the file types of a board.

## What belongs in it

A board or SoC fact belongs here when any other component can use it.
One caller today is enough.

## The shape

A field belongs to the table whose id determines it. Every SoC of one family
shares the same core, so the core is a family field.

A row states what is true of the board, and what CERF supports on it.

A row field is the last level of data definition.

A set that grows when a board or a SoC arrives is a string id. A closed set
that a new board never extends is a C++ enum.

## Board families

Every board belongs to a family. A family is one platform, and the boards in
it share most of their hardware. A member differs in a small set of parts.
Examples are the panel, the keypad, a radio, the RAM or flash size, the
region, and the vendor that sells the board. A hardware revision is a member
of its own. A panel or size variant is also a member of its own.

A family and all its known members enter the database in one change. A member
is known when a source shows that it uses the platform. A family with rows for
only some of its known members is a defect of the database.

A source puts a model on the platform in two cases. It shows a ROM or an
upgrade that the vendor ships for the model and for members together, or it
states that the model is built on a member. A source about one model decides
only that model and the models built on it. A group that one spec forms, such
as CPU speed, decides nothing. A part that no source documents never keeps a
member out, and its row records the parts that are known. A model stays out
only when a source puts it on another platform.

A field on the family applies to every member. A board sets the field only
where the board differs, and the value of the board wins. The `device_specs`
of a board add to the specs of the family (see § Device specs), `board_config`
merges by parameter, and the `notes` of a board add to the notes of the family.

The code of a family serves every member. It reads a fact that differs
between members, for example the SoC or the RAM size, from the row of the
member. A member with no ROM image is still a member, so the code never limits
itself to the members that have a ROM image.

A member can differ in a part that CERF does not model yet. The member then
runs the family code for that part, and its support level records the
difference.

For example, a regional member has another keyboard layout. Its keys sit on
the same matrix pins as the keys of the other members, so the family keyboard
works on it. Only some key labels or host key bindings are wrong for that
member. Another member has a part that the other members lack, such as a
built-in modem.
The family code runs on that member, and the member has no modem in CERF.

Running the family code on such a member is not a guessed implementation.
Code never takes a family service away from a member. These are all removals:

- A board id check in `ShouldRegister` that skips the member
- A halt on that member
- A per-member answer that turns off one feature of the service

A member lacks a part only when a source names the absence. Without such a
source, the member has the part, because its family siblings and the
platforms that its family came from have it. An input path that nobody has
found yet is an open investigation, never an absence. A member is
`bootable_full` only when CERF models every difference of that member.

Family code finds a control that the members share by what the control is,
for example the LED button. A virtual key or a pin of one member does not
find the control on a member whose wiring differs. The control then
disappears on that member with no error. Find the wiring of each member in its own ROM.
Start from the routine that a sibling member uses for that control.

The board sets `support_level`. The values are:

- `bootable_full` - a ROM of this board runs in CERF.
- `bootable_partial` - the board runs a ROM that runs in CERF. It differs only
  in hardware that CERF does not model.
- `unknown_partial` - the board never ran in CERF. Its known differences can
  still work.
- `no_support` - the board is broken in CERF, or a known difference breaks the
  guest.

A `rom_types` or `storage_types` row binds through `board_ids`,
`board_family_ids`, or both. A `storage_types` row with neither field binds every
board. A `rom_types` row with neither field binds every board whose
`rom_placing_mode` is `flat_container`. That row describes an input of
`RomParserService`, and a board on another boot path never reads one.

A storage file is optional by default, because CERF can create or seed it. A
`storage_types` row with `"required": true` names a storage that CERF cannot
create, for example a flash that holds the bootloader of the board.

Settle the member list from platform evidence first, then name the family. An
argument for a name never decides which models are members.

The name of a family is the name of its platform. Use the public name of the
vendor for the platform. If no public name exists, use the name that the ROM
gives its platform. If the ROM gives no name, use the name of the design that
the other members came from.

## Device specs

`device_generic_parts` is the table of generic parts. A generic part is one
kind of hardware, for example a display, a NAND chip or a Wi-Fi radio. It has a
name and an icon. Several parts can share one icon. A part never groups
different kinds of hardware: Wi-Fi, cellular and IrDA are three parts with one
icon. A consumer finds a part by its id, never by a displayed name.

In the display order, parts that share an icon sit next to each other.

The `device_specs` of a family or a board is a list of spec items. A spec item
is one part of the device. It has:

- `generic_part_id` - the generic part. The part is the type of the item.
- `supported` - `true` when CERF models the part, `false` when the device has
  the part and CERF does not model it. A device that does not have a part has
  no item for it.
- `displayed_name` - optional. The name of a stock part that the user cannot
  change, for example a panel model or a keyboard layout.
- the optional fields of its part, for example `display_width` and
  `display_height` of the display part, the panel size in pixels. An item never
  carries a field that its part does not have.

A device can have more than one item of one part. Each item is one component,
for example two displays.

The first display item with a size gives the panel size of the board. The size
is a hardware fact of the panel. CERF opens the emulator window at that size,
and guest additions take it as their default. A later display item can carry
its size, and no component reads it. When a row holds more than one display
item, `$index` puts the panel item first.

**A family holds only the items that every member has, unchanged.** When one
member differs in a part, the family stops holding that part, and each member
that has the part holds its own item. A board item never replaces a family
item. The items of a board add to the items of its family.

When members differ in a part, the displayed name of each item states the known
difference, for example 256 colors and 4096 colors. Only parts that differ in a
way that no source names take a letter, for example the same speaker on other
pins: Speakers A, Speakers B. The letters state that the parts differ, and they
do not state which part CERF supports.

### Clear facts and open facts

A hardware fact is clear when a generic part, a field of that part, or a
board configuration parameter can state it. A clear fact goes into
`device_specs` or `board_config`, never into text.

A fact about a component that CERF models is always clear. When a change
records such a component and no generic part describes it, the change adds the
part: a new `device_generic_parts` row with its own id and name and the icon of
its nearest part. A missing part is never a reason to leave the component out,
or to put it into the displayed name of another part. For example, a graphics
controller beside the display gets a part of its own.

A hardware fact is open when CERF does not model its component and no part
describes that component. A fact is also open when no field of its part can
state it. Examples are a CompactFlash slot, a phone connector, the size of a NOR
flash and the color of a backlight. An open fact stays as text in
`internal__spec_divergences` of the member that differs. When a part or a field
for it exists, the fact moves out of that text.

`internal__spec_divergences` holds hardware facts only. The content, the size
and the language of a ROM, a market, a brand, the bundled software and the CPU
clock never go into it.

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

The values of one parameter can depend on another part of the board, for example
the panels that a graphics controller can drive. Such a dependency needs a
mechanism of its own in the database. The first board that needs it gets that
mechanism, never a flat `values` list or an exception for one board.

A part belongs to the whole family or to a subset of its members. When every
member has the slot or the pads for the part, the family row holds the
parameter. Otherwise the row of each member with the slot or the pads holds it.
A `values` list with only `none` never states that a member lacks the slot or
the pads.

A `board_config_params` row with a `generic_part_id` links the parameter to
that part. The value of the parameter then describes the first item of that
part, after its displayed name: `Display B - Monochrome STN (240x320)`. A
parameter with no generic part does not show as a part, for example the
MIPS16EN pin.

A part that a user can change and that CERF does not model yet still gets its
parameter. Its `values` list holds the values that CERF supports, for example
the one RAM size that the code maps. A member whose real part differs sets its
default to its real part. A default outside the `values` list marks that part
of the member as not supported. cerfman shows "Not supported" next to Auto,
and the website marks the part with the unsupported badge.

## CPU configurations

A `cpu_configs` row with a `soc_id` is the CPU of that SoC. A row without a
`soc_id` is a shared base, not a preset. Only `inherits_cpu_config_id`
reaches it.

A row takes every value of the row that it inherits. Its own values replace
the inherited values. A SoC row and the rows that it inherits give a value to
every parameter of its architecture.

Only a fact that the silicon fixes goes into `cpu_configs`. A rate or a state
that the guest programs stays in code. The CPU clock is one example.

## Guest-additions palettes - `guest_additions/palettes/`

A palette row is one palette of the guest-additions display. `bpp` is the
indexed depth of the palette. `values` holds `1 << bpp` `[red, green, blue]`
colors. The first palette for a depth is the default of that depth. A device
configuration stores a chosen palette as its colors, never as its `id`. The
manager names such a palette by its colors.

## HUD presets - `huds/`

`huds/devices/` holds the on-screen HUDs of the frontend. `huds/elements/` holds
the named elements that the HUDs share.

A HUD binds through `board_ids`, `board_family_ids`, or both. A HUD that names
the board wins over a HUD that names its family.

A key is the name of a Windows virtual-key code, for example `VK_RETURN`. A
button has `keys` or an `action`. An action is the object path of a
`MachineButton`, a list of object ids from the root, for example
`["notification_led", "button"]`. A `sticker` is an `icon` or a short `label` in its own
cell, and it takes no press. An example is the icon that the device prints above a
key.

A `lamp` cell shows the lamp at its `object` path. The `shape` of a lamp is `circle`, a
round LED, or `disc`, a widened oval LED whose whole face lights. A lamp with no
`shape` is a `circle`. A button with a `lamp` is an LED button, and that lamp is its
whole face. A `display` cell shows the characters of the character display at its
`object` path. Lamp and display cells take no press.

An indicator is a lamp that lies over its panel and takes no cell, so it moves no key.
`x` and `y` place its center as fractions of the panel as the preset draws it. `size`
is its height as a fraction of the shorter side of the panel. `aspect` is its width
divided by its height, 1 when absent. On Android, the indicator moves and turns with
its panel.

An LED-only HUD carries its indicator on an empty panel. It needs no layout of the device.

A face is an icon or a label, never both. A control takes the Material Symbols icon of
its meaning wherever one exists. The face is the same on every device, whatever its
keycap prints. Examples are Enter, Tab, Shift, Backspace and the keys of office
programs. When `external/material_symbols` lacks the symbol, you add it from upstream
Material Symbols.

A control keeps a label when the only symbol of its meaning is a trademark, for example
the Windows logo. It also keeps a label when the symbol reads as another meaning, for
example a lock for Num Lock. A symbol of another meaning never stands in for such a
label, for example a home icon for the Windows key. A control also keeps a label when
no Material Symbols symbol carries its meaning, for example Esc or Fn.

A `rocker` is a device rocker or dial: `up`, `down` and an optional `center` press,
with no left and right. It is one cell, so it keeps up above down when Android turns
its column into a row. A device control that is not a d-pad is never a `dpad`.

A preset holds the layout of the device, never its geometry. It keeps the keys of the
device, their rows and their order. Every control is a full key that a finger can press,
and no cell is smaller than one unit. No control has an unusual position unless the user
asks for it. The arrow keys always line up as a group.

A preset starts from the original layout and changes it where the change makes the HUD
easier to use. It moves further from the hardware only when the user asks. A photo of the
device shows which keys exist and where they sit in the layout. The photo never sets the
size or the position of a cell.

A device control that sits elsewhere on the case, for example the power button, is a
full key of the preset. Its position on the case sets neither its place nor its size on
the HUD.

Panels on one side stack outward in list order.

A cell with a `grow` of n takes n units of its row or column. Cells at the same unit
position in two rows or columns with the same total `grow` line up.

The width and the height of a panel are fractions of the length of the screen
edge that the panel sits on. The screen of a HUD is the panel size of one of its
bound boards (see § Device specs). That board has the panel size that is the closest to the size
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
