# Save and restore

CE Runtime Foundation lets you to snapshot your whole device into a save state file and load it back.

Use **Save state…** and **Load state…** in the Actions menu or just close the emulator instance and answer in the dialog.

## Crash state

There are many scenarios where you can get a crash during emulator use. That's done with only the good purposes however
it affects you the worst possible way - if you didn't save anything you will lose all your data. Nobody likes that.
CE Runtime Foundation 10+ fixes this - now all your data gets saved into a separate save state file.

- You can toggle this in your emulator settings. This is enabled by default.
- Big RAM devices will use much more disk space. 

## 🚨 CERF Upgrades will break your saved state

!!! note

    **Only the emulator build that wrote a state file can resume it.**

    In a worse scenario emulator attempts to restore only RAM which gives you a high chance
    to restore your data but with a warm reboot.

    Rarely we update RAM layouts so you might lose your whole save state.

    Consider persisting your files on various kinds of extrenal storage the emulator provides and using
    OEM/3rd party backup apps for Windows CE.
