# ROM Acceptance - what CERF eats and how

CERF runs the original device's software unchanged. The CE binaries - kernel,
OAL, drivers, userspace - are the ROM's own guest code (see `agent_docs/rules.md`
§ WinCE Accuracy). This page is about the layer below that: what *file* CERF
accepts as "the ROM", and how it turns that file into a guest that runs.

The rule that governs: **CERF accepts the original OEM firmware package / dump as
shipped, and extracts or serves the bootable image from it.** It does NOT accept
- and must never be made to require - a pre-extracted, repackaged, or otherwise
modified image produced by an external tool. If a device's bootable image lives
inside an OEM container or a whole-flash dump, CERF parses that container /
serves that flash. It does not ask the user (or a build step, or a remote
manifest) to give it a stripped payload. A device that only boots from a
hand-extracted XIP is a CERF gap to close, not the intended shape.

**A raw hardware *capture* is normalized to the flat container before bundling.**
The "no external pre-extraction" rule above concerns a *recognized container or
filesystem CERF parses itself* (B000FF / NOSAJ / ARNOLD / IMGFS / a whole-flash
FS). It does not extend to raw memory-bus capture artifacts. A dump read from the
bus carries properties of *how it was read* rather than of the ROM. These
properties are chip-select **aliasing / mirroring** (a small flash repeated
across a larger decode window - for example an 8 MB part that appears twice
across a 16 MB window), **floating / undriven-bus** regions, **blank / erased
pad** (`0x00` / `0xFF`), and **address wrap** (the image straddles the physical
device, so it is contiguous only modulo the device size). These are not ROM.
`RomParserService` consumes the flat container only. De-aliasing, de-wrapping,
and pad-trimming are capture normalization performed before bundling, not parser
behavior.

The ROM is the **flat ROMHDR/TOC container** (`physfirst..physlast`). The test for
a raw capture is whether it holds that container fully and intact. If it does,
normalization yields the bundled artifact: a contiguous `physfirst..physlast`
image with file-0 == physfirst (a flat NB0, Axis 1 below) - the flat span
`RomParserService` reads. The pre-extraction that the rule above forbids is a
distinct case: there the bootable image sits inside a container / filesystem CERF
must crack, and a pre-cracked payload is supplied instead. A capture that does
not hold the full container - truncated at the wrap, missing modules - is
incomplete and is re-dumped, not patched.

This sits next to two related pages. `agent_docs/boot_loaders.md` covers whether
CERF skips, models, or fully emulates the OEM bootloader. The Guest-Additions
injection mechanism (`agent_docs/guest_additions.md`) recomposes a ROM by the
same ROMIMAGE rules CERF parses it with.

## Two independent acceptance axes

CERF classifies every supported device on two axes. They are orthogonal - a
device picks one value on each.

### Axis 1 - original container vs raw payload

The OEM ships the bootable image inside a container with a header, sometimes a
signature catalog, sometimes multiple partitions. CERF recognizes the container
by its magic bytes and unwraps it. Recognized containers today:

- **flat NB0 / raw XIP** - no container. The file *is* the XIP. The common case.
- **B000FF** (`kB000FFSignature`, `"B000FF\n"`) - a sectioned image: a list of
  `(base, size, checksum) + data` sections, terminated by a `base==0` section
  whose `size` field carries the kernel entry VA. `AssembleB000FFFlat` assembles
  it into a flat span. Pocket PC / multi-XIP NB0 dumps.
- **NOSAJ** (`kNosajSignature`, `"NOSAJ\0"`) - the SmartBook G138 `.fim`
  package: inline partition descriptors + a byte-reversed `"DiAlOgUe"` launch
  block that frames the OS XIP. `NosajLocateOsXip` resolves it.
- **ARNOLDBOOTBLOCK** (`kArnoldSignature`) - the Siemens SIMpad (`"Arnold"`
  codename) `.bin` firmware package: a fixed header followed by the bootable OS
  XIP, byte-identical to what an extracted `.nb0` carries. `ArnoldLocateOsXip`
  resolves it.
- **Siemens FWF** (OMS+ stream, `cerf::fwf_oms::IsOmsStream`) - the Mobile Panels 2nd generation
  firmware file: an object stream that carries the OS update container. The board programs
  `/flashboot` of its eMMC image from it, and `BoardBootImage::ReadBootImage` reads the OS image
  back from there into the flat span (`rom.is_fwf`); a board without that service refuses the file.

CERF unwraps all of these to a **flat XIP span** that the rest of the pipeline
treats identically.

### Axis 2 - flat XIP vs whole storage

- **Flat XIP** - the bootable image is one contiguous XIP (kernel + ROM
  modules + ROM files), small enough to place in DRAM and execute.
  `RomParserService` (`libCerfCore/src/boot/rom_parser_service.cpp`) handles it. The vast
  majority of boards.
- **Whole storage** - the dump is an entire flash / NAND / disk (often multiple
  GB). The bootable image is a region *inside* it that the device's own boot
  path locates and copies to DRAM. CERF maps the dump on demand and serves it
  through the emulated storage controller. The guest reads it the way real
  hardware does. Ford SYNC 2 (`.sec` → `SecFlash` → i.MX51 NFC) is the current
  example.

## The flat-XIP pipeline (`RomParserService`)

`RomParserService::ParseOne` (`libCerfCore/src/boot/rom_parser_service.cpp`) is the funnel.
For each declared / auto-detected ROM file:

1. **Read the whole file** into `rom.raw`.
2. **Detect the container** by leading magic, in order: B000FF → FWF →
   NOSAJ → ARNOLD → else flat NB0. The chosen branch sets `rom.flat` (a span over the
   bootable XIP) and `rom.flat_base_va` (the VA that file-offset 0 of the flat
   maps to).
3. **Find the ROMHDR.** Scan the flat for every `ECEC` ROM signature
   (`FindAllEcec`, `0x43454345` at XIP+0x40, with the pTOC kernel-VA at
   +0x44). `ResolveRomhdrAtEcec` resolves each marker
   to a ROMHDR. A CE2-era image with no ECEC record uses
   `ResolveRomhdrStructural` instead, which scans for a self-consistent ROMHDR
   validated against an `nk.exe` module name.
4. **Parse the TOC** (`ParseModulesAndFiles`): `nummods` TOCentry records +
   `numfiles` FILESentry records. It resolves names via `load_offset`.
5. **IMGFS** (WM6+ only): `FindImgfsBase` locates the IMGFS superblock. The
   walker (`ce_imgfs_walker`) enumerates flash-filesystem modules. CERF skips
   this step for container formats that are pure XIP (NOSAJ, ARNOLD) and for
   B000FF.

The outputs that every downstream consumer relies on are `rom.flat`,
`rom.flat_base_va`, `rom.entry_va`, and `rom.xips[*].toc`. A new container format
only has to populate `rom.flat` / `rom.flat_base_va` correctly. Steps 3-5 are
shared.

### Adding a container format

Mirror the existing ones - they share a shape:

- A signature constant + a `*LocateOsXip` resolver in
  `libCerfCore/src/boot/rom_image_parse.{h,cpp}` that returns the XIP's `data_off`,
  `flat_size`, and `base_va`. When the container does not store the base VA, the
  resolver recovers it: it verifies the candidate ROMHDR against the container's
  own invariants (NOSAJ verifies `physlast - physfirst == span`, ARNOLD verifies
  `physfirst == candidate base`). This is ROM-content verification, the same kind
  the ECEC resolver already does - not a JIT/MMU heuristic.
- A detection branch + an `is_<format>` flag in `ParseOne` / `ParsedRom` that
  sets `rom.flat` and `rom.flat_base_va`, then lets the shared ECEC/ROMHDR/TOC
  path run.

Everything that locates the XIP, the base, or the entry must come from the ROM's
own bytes - never `cerf.json`, `meta`, a whole-image CRC, or runtime RAM
heuristics (`agent_docs/rules.md` § "Per-device facts come from the ROM").

## The whole-storage pipeline (`SecFlash` + storage controller)

For multi-GB dumps CERF does not extract the bootable image to a flat span - the
guest's own storage stack reads it. Ford SYNC 2:

- **`SecFlash`** (`libCerfCore/src/boot/sec_flash.{h,cpp}`) owns the `.sec` NAND image as a
  `MappedFile` (CERF never maps the ~2 GiB file whole) and a parsed
  `SecContainer` (`libCerfCore/src/boot/sec_container.{h,cpp}`) that de-chunks the package
  (chunked payload + PKCS#7 catalog, `SecHeader` magic `0x400D400D`). It
  registers only when the device dir holds a `.sec`. Consumers `TryGet` and
  tolerate absence.
- **The i.MX51 NAND path** consumes it. `imx51_nand_bootloader_boot.cpp` models
  the NAND boot ROM (reads a flash header from `SecFlash`, copies the bootable
  image to DRAM). `imx51_nfc.cpp` (the NAND Flash Controller) serves NAND pages
  from `SecFlash` on demand, so the guest's flash filesystem reads them like real
  silicon.

`RomParserService` is not involved - `.sec` is not in its file-extension list,
and Sync 2 boots entirely through emulated NAND. This is the same family as the
Zune approach in `agent_docs/boot_loaders.md`. There CERF synthesizes a blank
disk with the expected partition, and the OS boots from it. The bootable image
reaches DRAM through emulated storage + the device's own boot path, not through a
host-side XIP extractor.

The choice of this pipeline is a property of the dump, not a convenience. A
whole-NAND container that wraps a flash filesystem (BINFS / IMGFS over an FTL)
has no single flat XIP to extract. Therefore CERF must emulate the controller
faithfully and let the guest read its own storage.

## Where the file comes from

`RomParserService::OnReady` resolves the file set from `DeviceConfig`:
`rom_primary` (+ `rom_extensions`, or `rom_recovery` under `--recovery`). The
`rom` block of `cerf.json` or the `--rom-primary` flag names them - the
configuration declares the bootable file, and CERF does not search for it. The
configuration declares the board the same way (`cerf.json board.id` /
`--board-id`), which selects the `BoardContext`. SoC, OS version, memory map, and
the XIP / base / entry resolution above all still come from the ROM's own bytes.
They never come from `cerf.json` or `meta` (`agent_docs/rules.md` § "Per-device
facts come from the ROM"). The bundled device tree (`bundled/devices/<name>/`)
holds the original OEM file - the package or dump as shipped, not a derived
artifact.
