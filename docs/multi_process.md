# Multi-Process Support

## Current State (Phase 1)
- Each WinCE process spawns a separate cerf.exe instance on the host
- ShellExecuteEx and CreateProcessW detect ARM PEs via IsArmPE() and spawn `cerf.exe <mapped_path>`
- Apps are isolated: separate emulated memory, HWNDs, registry, etc.

## Phase 2: Integrated Multi-Process
- Run multiple ARM processes within a single cerf instance
- Requires:
  - Process table with separate memory spaces per process
  - Shared HWND namespace (so FindWindow/SendMessage work cross-process)
  - Shared registry state
  - Thread scheduling (cooperative or preemptive)
  - IPC mechanisms (WM_COPYDATA, shared memory, named events/mutexes)
- Benefits:
  - Inter-process communication works (FindWindow, SendMessage between apps)
  - Shared clipboard, shell notifications, DDE
  - Explorer.exe can track/manage running app windows in the taskbar
  - Lower overhead than multiple cerf.exe processes
