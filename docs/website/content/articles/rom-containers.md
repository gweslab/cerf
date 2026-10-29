# Windows CE ROM containers

--8<-- "ai-summary.md"

A reference for the file formats Windows CE ROMs actually ship in, how they differ across CE
versions, and how to extract them. This is the layer *below* "the ROM" - what wraps the bootable
image, not the CE binaries inside it. It is written down almost nowhere else; this page is grounded
in CERF's own ROM parser and the `extract-wince-rom` tool.

## The thing inside every container: ROMHDR + TOC

Whatever the outer wrapper, a Windows CE XIP ("execute in place") region is the same shape: a
**ROMHDR** followed by a **table of contents (TOC)** listing the modules (executables that run
directly from ROM) and the files (everything else - fonts, registry, data).

The ROMHDR records the region's physical span (`physfirst`..`physlast`), the module and file
counts, the RAM layout, and a **copy table** that tells the kernel which writable sections to copy
from ROM into RAM at boot. The TOC entries point at each module's headers and each file's payload.

From CE 3 onward the ROMHDR is marked by an **`ECEC` signature** (the bytes `43 45 43 45`) at a
fixed offset inside the region, so a parser finds it by scanning for that marker. Earlier CE has no
such marker and the header is located structurally (below).

## The outer container formats

The XIP region above may sit inside a wrapper. CERF recognises these by their leading bytes and
unwraps each to the same flat XIP span:

| Container | Marker | Where it is seen |
| --- | --- | --- |
| **Flat NB0 / raw XIP** | none - the file *is* the XIP | the common case |
| **B000FF** | `B000FF\n` | Pocket PC / multi-XIP NB0 dumps |
| **NOSAJ** | `NOSAJ\0` | the SmartBook G138 `.fim` package |
| **ARNOLDBOOTBLOCK** | `Arnold...` | the Siemens SIMpad `.bin` firmware |

- **Flat NB0** is no container at all: the file starts at `physfirst` and the ROMHDR is inside it.
- **B000FF** is a list of `(base, size, checksum)` sections plus their data, terminated by a section
  whose `base` is zero and whose size field carries the kernel entry point. It is assembled into one
  flat span before parsing.
- **NOSAJ** and **ARNOLD** are OEM firmware packages that frame a single bootable XIP with their own
  header; the XIP inside is byte-identical to what a plain `.nb0` would carry. The base address,
  when the container does not store it, is recovered by validating a candidate ROMHDR against the
  container's own invariants - not guessed.

The rule CERF follows: **it accepts the original OEM package or dump as shipped and extracts the
bootable image from it.** It never expects a pre-extracted payload. If a device's image lives inside
a container, CERF cracks the container. NOSAJ and ARNOLD are proprietary OEM packages handled by
CERF itself - the standalone extractor below does not know them; it reads the common formats
(flat NB0, B000FF, IMGFS).

## IMGFS: the flash filesystem (Windows Mobile 6+)

From Windows Mobile 6, the modules no longer all live in a single XIP TOC. There is a small XIP for
the kernel, and the rest of the OS lives in **IMGFS** - a flash filesystem laid over the NOR/NAND
image through a Flash Translation Layer (FTL). It is not a table of contents you can index; it is a
filesystem you have to walk, page by page, following the FTL's logical-to-physical map, with each
module's sections XPRESS-compressed.

So a WM6.5 ROM is really two things stacked: a classic XIP up front (found by its `ECEC` marker) and
an IMGFS blob behind it that the FTL walker enumerates.

## Whole-storage dumps

Some dumps are not a small XIP at all but an entire flash or NAND - often gigabytes - with the
bootable image as a *region inside* that the device's own boot ROM locates and copies to RAM. There
is no flat XIP to lift out. Here the storage controller is emulated and the guest reads its own
flash exactly as the hardware did (CERF does this for the Ford SYNC 2 `.sec` NAND image, served
through the emulated i.MX51 NAND controller).

## How the formats differ across CE versions

The container zoo grew with CE. The moving parts, oldest to newest:

- **CE 1.0** is its own world - see [below](#windows-ce-10-a-different-format-entirely).
- **CE 2.0 / 2.11** predate the `ECEC` signature (added in CE 3), so the ROMHDR is found by a
  structural scan validated against the presence of `nk.exe` in the TOC. Their module header
  (`e32_rom`) also differs by version: CE 2.11 has no `sect14` field and places the subsystem field
  earlier; CE 2.0 additionally lacks a `vsize` field, shifting things again and deriving the image
  size from the section records. Compression is the CE3-era "BIN" scheme.
- **CE 3 through CE 5 / Pocket PC / Windows Mobile 5** carry the `ECEC` marker, a stable 32-byte TOC
  with module headers as `e32_rom` / `o32_rom` records, and LZX-family compression. This is the
  "classic" XIP most boards use.
- **Windows Mobile 6+** keep the classic XIP for the kernel and move the bulk of the OS into IMGFS
  (above), with XPRESS compression.

CERF's parser handles all of these behind one interface: it detects the container, finds every
ROMHDR (by `ECEC` where present, structurally where not), walks the TOC, and - on WM6+ - walks
IMGFS as well. Every fact about a ROM comes from the ROM's own bytes; nothing is read from a
sidecar file.

## Windows CE 1.0: a different format entirely

CE 1.0 (1996-97, the original Handheld PC "Pegasus" clamshells) shares the outer shape - a flat
image, a standard 84-byte ROMHDR, multi-XIP, a copy table - but the module and file layout **is not
CE 2.x** and none of the later parsing applies.

- **No `ECEC` marker** (it did not exist yet); the ROMHDR is found structurally, and CE 1.0 is
  distinguished from CE 2.x by its TOC.
- **The TOC entry is 304 bytes** (CE 2.x uses 32), and it stores the module name **inline** rather
  than as a pointer. That inline name is the detection discriminator: a CE 2.x parser reads that
  offset as a virtual address, sees ASCII bytes instead, and finds nothing - so the two formats
  never collide.
- **Modules keep their full PE headers in ROM.** The TOC entry points straight at the module's
  `IMAGE_NT_HEADERS` and section headers. There is no `e32_rom` / `o32_rom` indirection;
  reconstructing a module is copying the in-ROM PE headers and pulling each section from where its
  header points.
- **Compression is LZW**, not the LZ77 / LZX of later CE - a variable-width (9-to-12 bit),
  LSB-first LZW with a clear code at 256 and no end-of-information code. Data files are paged in
  4 KB chunks, each page either stored or a single LZW stream.
- **Writable sections share their image RVA** with a read-only neighbour (the writable `.data` is
  relocated to RAM by the copy table, so its image RVA is only nominal). A faithful reconstruction
  has to preserve both.

CERF boots CE 1.0 on the Philips Velo 1 (Toshiba TX3912 / PR31500, MIPS-I). The full byte-level
specification lives in the repository, validated against that ROM: every module reconstructs as a
valid MIPS PE and all 238 files decompress to their exact length.

## A module in a ROM is not a normal PE

This is the part that trips everyone who tries to treat an extracted module like an ordinary
executable. A module inside an XIP is **not** the `.exe` or `.dll` its maker compiled. To make it
execute in place from ROM, with no loader and no free RAM to fix things up, the ROM builder took
that PE apart and re-baked it:

- **The addresses are frozen.** A normal PE carries a base-relocation table so a loader can move it
  anywhere in memory. The ROM builder **strips that table** - the module only ever runs at its one
  ROM address, so every pointer inside it is a fixed number for that exact slot. Nothing in the XIP
  can be relocated, rebased, or moved. It is hard-wired to where it sits, by design, and there is no
  information left in the image to undo that. This is the single biggest reason you cannot simply
  lift a module out, move it, and expect it to run.
- **It carries CE metadata that PE cannot express.** The kernel's MMU can map a section at a runtime
  address different from its link-time slot (a *split address*), and two sections can share one
  image address (a *shared RVA*) because one is relocated to RAM at boot and the other is the real
  read-only resident. A standard PE section header has exactly one address field and no room for
  either case.

So a faithfully "extracted" module is a reconstruction, not the original file. The `extract-wince-rom`
tool rebuilds each module as a PE that a disassembler will open, and appends a **`.cerom` section**
carrying the CE-specific data (the original section records, and the bytes of any shared-RVA
section that could not fit in the normal table). Tools that do not know about `.cerom` - IDA,
Ghidra, the Windows loader - simply ignore it.

Because the relocation table is gone, the rebuilt PE is marked *relocations stripped*: it is for
**reading the code**, not for running or re-linking. The tool can *guess* a relocation table by
scanning for values that look like in-range pointers, but that is off by default and inherently
unreliable - ARM instruction bytes and coincidental numbers collide with real pointers, so the
guess corrupts as much as it fixes. There is no ground truth to recover, because the ROM builder
threw it away.

## Extracting a ROM yourself

[**extract-wince-rom**](https://github.com/gweslab/extract-wince-rom) is a standalone tool for
pulling a ROM apart to **read its code** - it decomposes a ROM into its PE executables, files,
registry and a `rom_meta.json` describing the ROMHDR / TOC:

```
python extract_wince_rom.py -o out_dir  firmware.nb0
```

It reads the common container formats - flat NB0, B000FF, and IMGFS on WM6+ - and reconstructs
every module as a PE a disassembler will open (CPU taken from the ROMHDR, or `--machine` when the
ROM leaves it blank), from CE 1.0 through Windows Phone 7. It is CPU-agnostic: ARM, x86 and MIPS
ROMs all work. It does **not** handle the proprietary OEM packages (NOSAJ, ARNOLD) - those are
CERF's own concern.

!!! note "It is a disassembly aid, not a rebuild"

    Per the section above, the modules it emits are reconstructions with their relocation tables
    stripped and CE metadata parked in a `.cerom` section. They are for opening in IDA or Ghidra to
    read the code - not for running, re-linking, or as ground truth for how the live kernel lays a
    module out in memory. Reconstruction is best-effort and not independently verified against a
    reference builder.
