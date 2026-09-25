# Save and restore

CERF snapshots a running machine into a single state file: the CPU, the MMU, all of RAM, the flash
contents, and the registers of every emulated component on the board.

**Save state...** and **Load state...** are in the Actions menu. Closing the window offers to save
on the way out.

![The shutdown dialog offering to save the state](/assets/articles/hibernation/save-on-exit.png)

## 🚨 CERF Upgrades will break your saved state

!!! note

    A state file belongs to the exact CERF build that wrote it. Any other build refuses the file.
    If a newer build didn't refuse your save state that's a luck.

    Consider persisting your files on various kinds of extrenal storage CERF provides and using
    OEM/3rd party backup apps for Windows CE.

    That's called a save state migration subsystem and it's absent in CERF and we have no plans on it.
    The reason is the scale - CERF models much more than one board. This note exists for people who mistakenly 
    compare CERF with a single machine emulator like VirtualBox/VMware/MS Device Emulator. While that would be
    realistic for a single board, today hibernation code spans for more than 1000 files, so implementing
    such a subsystem would take an enormous effort and support :(
