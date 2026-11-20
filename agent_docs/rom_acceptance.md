# ROM acceptance: what CERF boots from

CERF has two boot paths. Decide which one a device takes before you write any code
for it. A wrong choice is not a detail that a later fix repairs. It puts machine
state into a read-only input, and every service that trusts that input breaks.

## The decision

Ask one question: can the guest write the storage that holds its own OS image?

The guest writes it when one of these is true:

- The bootloader can reflash the OS.
- The OS flash driver writes the region that holds the OS image. Examples are an
  IMGFS, a registry hive, a flash file store and a recovery partition.
- An update or recovery mode of the device rewrites the image.

| Answer | Path |
|---|---|
| No. The image is a fixed ROM, or it comes as a read-only container. | Path 1: the shortcut |
| Yes. The device boots from storage that the guest writes. | Path 2: whole storage is the primary boot device |

Almost every old device (about 98%) takes path 1. The rest take path 2, and for
those devices path 1 is wrong, however well it seems to boot.

## Path 1: the shortcut (`RomParserService`)

CERF reads a generic Windows CE ROM container, places the XIP regions in memory and
starts the kernel directly. It skips the OEM bootloader.

Path 1 works because of the design of Windows CE. Windows CE lets a ROM container
go anywhere and boot in any way (*Inside Windows CE*). The bootloader only
orchestrates the boot. It does not have to exist or act. The simplest boot that
Microsoft gives is to place the image in RAM and start the kernel. Path 1 is that
boot.

`RomParserService` is the input of the instance. These rules hold for it:

- It reads. It never writes.
- Its result is fixed for the life of the instance. Every service can cache what
  it derives from that result, and none of them subscribes to a change.
- It never reports machine state. Bytes that the guest writes are machine state.
- It never parses again at reset to follow a guest update. A device whose guest
  installs another OS image takes path 2.

### The input of path 1

CERF accepts the original OEM firmware package or dump as shipped. CERF extracts
the bootable image itself. It never requires a pre-extracted, repackaged or
modified image from an external tool. A device that boots only from a
hand-extracted XIP is a CERF gap to close.

A new container format only locates the XIP span and its base VA, from the bytes
of the container. The shared path finds the ROMHDR and parses the TOC.

### A raw capture of a ROM chip

A dump read from the memory bus carries artifacts of how it was read:

- Aliasing or mirroring: a small chip repeats across a larger decode window. For
  example, an 8 MB part appears twice across 16 MB.
- Floating or undriven bus regions.
- Blank or erased pad (`0x00` / `0xFF`) at the ends.
- Address wrap: the image runs past the end of the chip, so it is contiguous only
  modulo the chip size.

These artifacts are not ROM. Normalization before bundling removes them. It drops
a mirror copy, rotates a wrapped dump so the image is contiguous, and trims erased
pad at the ends. Normalization never cuts ROM content. A bootloader, a boot
monitor, an updater or a gap inside the chip is ROM content, and it stays.

Normalization is not parser behavior. `RomParserService` reads the normalized
file. A capture that does not hold the whole ROMHDR / TOC container is incomplete.
Dump it again. Do not patch it.

## Path 2: whole storage is the primary boot device

CERF models the storage hardware of the device over a persistent, writable image
file. The hardware is a NAND chip and its controller, an eMMC, or a flash chip on
the memory bus. The image is machine state. What the guest writes stays written,
across resets and across runs. The storage image is the input of the device, and
`RomParserService` does not own it.

Path 2 takes one of two forms.

### Form A: the device boots from storage through its own boot path

Reset enters the boot ROM or the bootloader of the device. That code reads the
storage, as on the hardware.

- Ford SYNC 2: NAND is always the primary boot device, and a bootloader boots from
  it.
- A device with NOR flash on the memory bus, for example the HP iPAQ hx4700: the
  flash is mapped at the reset address. The bootloader and the kernel region run
  in place from it. The OS flash driver writes the IMGFS and the file store in
  the same flash. The flash chip model is the controller here: its command set
  programs and erases the storage image. This is the SYNC 2 form.

### Form B: CERF provides the whole storage and jumps into the container on it

The device has no bootloader that CERF runs. CERF still models the whole storage.
At boot, CERF finds the generic Windows CE container on the storage and starts its
kernel directly.

- CERF reads the container from the storage at each boot. The container is never
  a separate input.
- The guest can rewrite its own container. The next boot then starts what the
  storage holds at that time.

Nokia Lumia 800 takes this form. The primary boot device is the eMMC. It is work in
progress: CERF seeds the eMMC, and the direct boot from it is not wired yet.

### Seeding the storage on the first boot

If the storage image does not exist, CERF can seed it from an OEM container.
After that, the storage image is the only input, and the container is no longer
necessary to boot.

- SYNC 2 seeds the factory boot region of the NAND from the `.sec` update
  container. The bootloader then enters factory recovery mode and reads the `.sec`
  over the emulated USB. It formats the NAND and flashes it fully.
- Lumia 800 seeds the whole eMMC.

A dump of the whole storage of a device can also be the seed. It is the storage as
read, not a ROM container, so path 1 normalization does not apply to it. It can
hold the data of its owner.

This is obviously optional, not everything is possible to seed, and some devices
might want to have only one boot source.

## A device that boots both ways

A complex device keeps its bootloader in writable storage. The bootloader reads
that storage first. The Windows CE image is in the same storage. The OS does not
have to access that storage, because Windows CE does not require it. The more
complex a device is, the more often its user mode writes the storage.

Take a device whose writable NOR flash holds its bootloader and its OS image, as
in form A. Its OS never writes the flash. CERF can boot it in two ways. Path 1
boots from `rom.primary`, a generic container such as an upgrade package. Path 2
boots from a storage image of the flash, through the bootloader.

Both boots are correct together while the guest OS does not write the storage.
Path 1 never runs the bootloader, so a bootloader that can reflash the OS does
not make path 1 wrong here.

The path that CERF implements first depends on what is available. CERF often
relies on upgrade packages, because those are the images that people can get
online. A dump of the storage can come later.

### Storage that the OS writes, with no dump

A write into the storage has its own correctness bar. Take a device whose OS
keeps user data in a partition of its writable storage. No dump of that storage
exists. CERF then models the storage as a regular writable storage type of the
device. A boot does not require it. CERF can synthesize it as a blank device. The
storage does not have to be bootable.

This is close to the Lumia 800, where CERF seeds the whole eMMC with the OS. Here
CERF does not know what the storage holds. It cannot place anything on it,
because no bootloader is available to read it.

### The target and the result

The target is the most correct shape of the device. What CERF builds is flexible,
and the correct set of boots differs by device. Some devices have one correct
boot: the bootloader from storage. Other devices have a boot from `rom.primary`,
a boot from storage, and a blank storage that CERF synthesizes at boot. The guest
OS keeps user data in that storage. Its content is unknown.

## Live tech debts

Those were done wrong. Lack the proper writable storage config, proper save, or save it
into save state. 

- SiemensSimaticTp177b4 SpansionS29Gl256
- SMDK2410 NOR flash (really bad case and nobody wants to clean this mess)
- Whatever OMAP 35xx is doing 
- Zune 30 is a surprise example. A bootloader spins HDD and loads NK.BIN from there.
  Then guest OS writes and reads that HDD for music and user data but never for NK.BIN itself.
  We own no bootloader. We provide HDD for OS as proper writable storage but we also hold NK.BIN
  separately as a regular `rom.primary` boot. Is that correct? Reading what this page says is
  actually yes, it's one of non-realistic but flexible ways. What's the most corrrect approach?
  Obtaining a bootloader is rather impossible I believe. The more correct approach might be CERF
  reading NK.BIN from HDD directly and booting. This way ordinary HDD dumps will boot
  their own OS. They dont do now so that's a real gap. 
- Basically every flash/storage CERF models that doesn't go into `storage` and is not configurable 
  in Board Settings is wrong.

The emulator somehow works in this state so we just don't touch those tech debts because it works. Any new code must be done properly.
That's a harsh reality of foundation done incorrectly so now everything rests on really bad architecture. 
For example at the very beginning of the project we incorrectly imagined that what you need is 
a WinCE container itself with the rest of flash thrown away. The book and practice confirms it's a working path.
Then the practice also confirm that throwing everything away is wrong because you force people into manual parse the upgrade packages.
Then the practice demolishes it by making guest OS heavy coupled with a bootloader and a proprietary NAND layout.
