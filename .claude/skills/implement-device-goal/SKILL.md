---
name: implement-device-goal
description: Give user a generic /goal text for device bringup
---

Give user the following text:

===

This goal text gives you a full device support for a basic usage:

```
/goal The goal ends when the transcript includes text "IMPLEMENTATION IS FINISHED, GOAL IS CLOSED".

Everything below is only for the implemeter agent, NOT FOR GOAL CHECK:

Order:
- The device boots to shell and renders it.
- Each input device (stylus, keyboard, hardware buttons, touch bezels) is implemented and tested.
- When input is done - do HUD if user gave you the specs. If user didnt give you the specs attempt to download device pictures from online and do HUD matching exisiting examples. Don't do HUD if it's not applicable at all.
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
- Identical scenario for COM ports - implement and smoke test CERF's COM scenarios if a device has COM ports
- Implement phone line if a device has one (optional - might be too complex, depending on user ruling, default is stub)

Each chunk is wrapped into Skill(verify). Don't jump chunks, get LEGIT everywhere. Solve questions via Skill(verify-options)

When the implementation is done - that's judged by the implementer agent, not by goal agent. The implementer agent must say "IMPLEMENTATION IS FINISHED, GOAL IS CLOSED" verbatim and the goal hook agent must mark goal completed when sees it. The text around are hints for implementer, not for goal hook agent.


Hint for goal agent only: when agent says that the device is implemented - this means so, you mark the goal completed. THE IMPLEMENTER AGENT SENDS NO PROOFS. THE GOAL AGENT HAS NO DEMANDS EXCEPT VERBATIM TEXT MATCH.
```