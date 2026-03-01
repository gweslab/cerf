# CERF - Windows CE Runtime Foundation

## Project Overview

CERF is an ARM CPU emulator + Win32 API compatibility layer that runs Windows CE ARM binaries on modern x64 desktop Windows. It interprets ARMv5TE instructions (ARM + Thumb modes), loads WinCE PE executables, and thunks COREDLL.DLL API calls to native Win32 APIs.

## Architecture

```
cerf/
  main.cpp              - Entry point, CLI parsing, emulation loop setup
  arm_cpu.h             - ArmCpu class declaration (registers, flags, method signatures)
  arm_cpu.cpp           - CPU core: condition checks, barrel shifter, Run/Step loop, trace buffer
  arm_insn.cpp          - ARM mode instruction handlers (ExecuteArm + data processing, multiply, load/store, branch, etc.)
  thumb_insn.cpp        - Thumb mode instruction handlers (ExecuteThumb + all Thumb opcodes)
  mem.h                 - EmulatedMemory class (32-bit address space with page-based allocation)
  pe_loader.h/.cpp      - WinCE PE loader (sections, imports, relocations)
  win32_thunks.h        - Win32Thunks class declaration, ThunkEntry struct
  win32_thunks.cpp      - Core thunk infrastructure: ordinal map, EmuWndProc/EmuDlgProc callbacks, thunk dispatch, module management
  thunks_memory.cpp     - Memory allocation (VirtualAlloc, HeapAlloc, malloc, etc.) and string operations (wcslen, wcscpy, wsprintfW, MultiByteToWideChar, etc.)
  thunks_gdi.cpp        - GDI: DC management, BitBlt, drawing, fonts, text, regions, DIB sections
  thunks_windowing.cpp  - Windows: RegisterClass, CreateWindowEx, message loop, dialogs, menus, input, rect operations
  thunks_system.cpp     - System: GetSystemMetrics, time, sync primitives, TLS, locale, registry stubs, resources, file I/O stubs
```

## Key Concepts

- **Thunking**: ARM code calls COREDLL functions via the IAT. These point to magic addresses (0xFE000000+, `THUNK_BASE`) that the CPU intercepts, executing native Win32 equivalents.
- **WinCE trap calls**: Some WinCE apps call APIs via hardcoded trap addresses in the `0xF000xxxx` range (descending from `0xF0010000`). The emulator decodes these as `api_index = (0xF0010000 - addr) / 4` and dispatches to the same thunk handlers. `THUNK_BASE` was moved to `0xFE000000` to avoid colliding with this range.
- **Owner-draw marshaling**: `WM_DRAWITEM` and `WM_MEASUREITEM` carry native 64-bit struct pointers in lParam. `EmuWndProc`/`EmuDlgProc` marshal these into 32-bit ARM layout in emulated memory before forwarding to ARM callbacks.
- **64-bit handle safety**: Native Windows uses 64-bit pointers/handles. ARM code uses 32-bit. Handles are sign-extended via `(intptr_t)(int32_t)` when passing to native APIs, and truncated back to uint32_t for ARM registers.
- **Callback bridging**: Native callbacks (WndProc, DlgProc, TimerProc) invoke back into ARM code via `callback_executor`. Sentinel address 0xCAFEC000 signals callback return.
- **WinCE fullscreen**: WinCE apps run fullscreen by default. CERF sizes windows to the desktop work area and hides borders, preserving the app's original window style for correct rendering.

## Building

```
msbuild cerf.sln /p:Configuration=Release /p:Platform=x64
```

Output: `build/Release/x64/cerf.exe`

## Testing

```
cerf.exe <path-to-wince-arm-exe>
```

Primary test app: Solitaire (`tmp/arm_test_apps/solitare.exe`). The game should launch, display cards, handle clicks, and show the Options dialog.

## Conventions

- C++17, MSVC (Visual Studio 2022, v143 toolset)
- No external dependencies beyond Win32 SDK
- `printf` for debug/trace output with `[THUNK]`, `[PE]`, `[EMU]` prefixes
- Static linking (`/MT` runtime)
- Thunk functions return `true` when handled, setting `regs[0]` as the return value
