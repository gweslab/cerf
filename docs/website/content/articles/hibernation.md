# Save and restore

CE Runtime Foundation lets you to snapshot your whole device into a save state file and load it back.

Use **Save state…** and **Load state…** in the Actions menu or just close the emulator instance and answer in the dialog.

## 🚨 CERF Upgrades will break your saved state

!!! note

    **Only the emulator build that wrote a state file can resume it.**

    In a worse scenario emulator attempts to restore only RAM which gives you a chance
    to restore your data but with a warm reboot.

    Consider persisting your files on various kinds of extrenal storage CERF provides and using
    OEM/3rd party backup apps for Windows CE.

