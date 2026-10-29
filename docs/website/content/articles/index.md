# Articles

Everything CERF does that is not obvious from the UI - what the features are, how to drive them,
and reference for the parts underneath.

!!! warning

    Some articles don't get updated often and might be out of sync with the latest emulator version or be ahead of it.


## General about emulator

- [**Guest Additions**](guest-additions.md) - how do Guest Additions works
- [**PC Cards and serial ports**](pc-cards.md) - what you can put into a PCMCIA slot/Serial port
- [**Getting the guest online**](networking.md) - put a network card in the slot and browse the web
  from Windows CE.
- [**Touch and mouse**](pointer-input.md) - when taps do not land, and the calibration trap.
- [**Feedback**](/feedback) - send a feedback or a bug report
- [**Running your own ROM**](own-rom.md) - boot a dump of a board CERF already supports.
- [**Connecting to ActiveSync**](activesync.md) - connect a guest handheld to a desktop ActiveSync
  and move files both ways.

## Advanced users and developers

- [**The configuration files**](cerf-json.md) - the three layers of `cerf.json`, and what each one
  can set.
- [**ROM bundle repositories**](bundle-repositories.md) - where the emulator downloads ROMs from,
  running your own, and copyright removal.
- [**Save and restore**](hibernation.md) - how saved state works
- [**Windows CE ROM containers**](rom-containers.md) - the ROM file formats, how they differ across
  CE versions, and how to extract them.
