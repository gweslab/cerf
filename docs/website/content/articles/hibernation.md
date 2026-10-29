# Save and restore

CE Runtime Foundation lets you to snapshot your whole device into a save state file and load it back.

Use **Save state…** and **Load state…** in the Actions menu or just close the emulator instance and answer in the dialog.

## 🚨 CERF Upgrades will break your saved state

!!! note

    **A state file belongs to the exact CERF build that wrote it.** Any other build refuses the file.
    If a newer build didn't refuse your save state that's a luck.

    Consider persisting your files on various kinds of extrenal storage CERF provides and using
    OEM/3rd party backup apps for Windows CE.

    The dev team has no plans on developing a migration mechanism since it covers more than one device
    and more than a thousand files of source code. Sorry.
