# CERF v2 Roadmap + Ideas

> [!NOTE]
> CERF v1 died due to architecture failure - became an overengineering hell. But the working artifact doesn't exist yet - CERF v2 needs to actually become this artifact - it must work and introduce at least a single new fully working BSP to confirm it's existance is more then just a weird copy of official Device Emulator. That's the milestone on which CERF v2 will be released.

- [x] DevEmu BSP / SMDK 2410 SoC - MVP implementation - boot, display, touch
- [x] Windows CE 3 Poseidon SoC+BSP - easiest next target, introduces first time ever proper Windows CE 3 ARM emulator to the world
- [x] CERF v2 branch replaces CERF v1 on GitHub - long awaited release
- [ ] Device frame in main window - devices need keypads, soft keys. Some devices need even more complex physical keys. Could be set up on board detection.
- [ ] First thing that ALL devices lack today is the shared with host storage. For many devices this could be done via PCMCIA storage card emulation into host directory. Some might have no PCMCIA, but have ATA disks, etc.
- [ ] Runtime PCMCIA slot switcher could be implemented
- [ ] DevEmu BSP - Full implementation
- [ ] Other BSPs and SoCs: OMAP 3510, SA-1110, etc.
- [ ] CERF's guest additions - drop in pathes inside ROMs with CERF's ARM binaries - any drivers? any apps? - research point in future
- [x] launcher.exe - Launch cerf.exe and manage bundles in single GUI window.
