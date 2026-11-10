---
name: implement-device-goal
description: Give user a generic /goal text for device bringup
---

Give user the following text:

===

This goal text gives you a full device support for a basic usage:

```
/goal The device implementation is finished.

Order:
- The device boots to shell and renders it.
- Each input device is implemented and tested.
- Bring guest additions if a device has a place for this mod and use guest
  additions for easier user-mode tests when applicable
- Ensure soft reset works
- Ensure every guest-initiated reboot works: find each way the ROM resets itself
  (IOCTL_HAL_REBOOT 0x0101003C in OEMIoControl, watchdog/deadman units, reset
  registers, companion-chip reset triggers), model the hardware it writes, and
  trigger it from inside the guest (a setting that asks for a restart, bare Win32 app loaded through --guest-additions)
  until it reaches a clean boot with no reboot loop
- Ensure CPU suspend/resume works
- Ensure hibernation works
- Ensure touch/keypad input still works after a chain of soft reset + cpu suspend
- Implement sound input/output depending if device supports those
- Implement PC Cards if a device has these slots and ensure they work
- Ensure PC Cards still work after CPU suspend/soft reset
- Identical scenario for COM ports - implement and smoke test if a device has COM ports
- Implement phone line if a device has one (optional - might be too complex, PC Card/COM might replace that)


Hint for implementer agent only: Each chunk is wrapped into Skill(verify). Don't jump chunks, get LEGIT everywhere. Solve questions via Skill(verify-options)

Hint for goal agent only: when agent says that the device is implemented - this means so, you mark the goal completed. Don't invent hidden goals.
```