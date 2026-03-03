# CERF - Windows CE Runtime Foundation

## Project Overview

CERF is an ARM CPU emulator + Win32 API compatibility layer that runs Windows CE ARM binaries on modern x64 desktop Windows. It interprets ARMv5TE instructions (ARM + Thumb modes), loads WinCE PE executables, and thunks COREDLL.DLL API calls to native Win32 APIs. Non-core WinCE DLLs (commctrl, commdlg, ole32, etc.) are loaded and executed as real ARM code — only coredll is thunked.

## Architecture

```
cerf/
  main.cpp                        - Entry point, CLI parsing, emulation loop setup
  log.h / log.cpp                 - Categorized logging (THUNK, PE, EMU, TRACE, CPU, REG, DBG, VFS)
  cpu/
    mem.h                          - EmulatedMemory class (32-bit address space, page-based)
    arm_cpu.h                      - ArmCpu class declaration (registers, flags, methods)
    arm_cpu.cpp                    - CPU core: condition checks, barrel shifter, Run/Step loop
    arm_insn.cpp                   - ARM mode instruction handlers
    thumb_insn.cpp                 - Thumb mode instruction handlers
  loader/
    pe_loader.h/.cpp               - WinCE PE loader (sections, imports, relocations, exports)
  thunks/
    win32_thunks.h                 - Win32Thunks class, ThunkEntry, ThunkedDllInfo table
    win32_thunks.cpp               - Core thunk infrastructure, dispatch, callbacks, ARM DLL loader
    coredll/                       - COREDLL.DLL thunks (one file per functional group)
      memory.cpp                   - VirtualAlloc, HeapAlloc, malloc, LocalAlloc, etc.
      string.cpp                   - wcslen, wcscpy, wsprintfW, MultiByteToWideChar, etc.
      crt.cpp                      - C runtime: atoi, qsort, time, rand, etc.
      arm_runtime.cpp              - ARM compiler runtime helpers (__rt_sdiv, __rt_udiv, etc.)
      gdi_dc.cpp                   - Device contexts, SelectObject, DeleteObject
      gdi_draw.cpp                 - BitBlt, drawing primitives, DIB sections
      gdi_text.cpp                 - Text output, font creation
      gdi_region.cpp               - Regions, clipping
      window.cpp                   - RegisterClass, CreateWindowEx, window management
      window_props.cpp             - Get/SetWindowLong, window properties
      dialog.cpp                   - DialogBox, CreateDialog, dialog procedures
      message.cpp                  - Message loop, SendMessage, PostMessage
      menu.cpp                     - Menu creation and management
      input.cpp                    - Keyboard, mouse, cursor, caret
      file.cpp                     - File I/O (CreateFile, ReadFile, etc.)
      registry.cpp                 - Registry operations
      system.cpp                   - GetSystemMetrics, time, sync, TLS, locale
      resource.cpp                 - LoadString, LoadBitmap, LoadIcon, etc.
      module.cpp                   - GetModuleHandle, LoadLibrary, GetProcAddress
      process.cpp                  - Process/thread management
      shell.cpp                    - Shell APIs (SH* functions, file dialogs)
      imagelist.cpp                - ImageList_* and InitCommonControls (coredll re-exports)
      misc.cpp                     - Debug, clipboard, sound, COM, IMM stubs
      vfs.cpp                      - Virtual filesystem: WinCE ↔ host path translation
bundled/                           - Files bundled with the build output
  cerf.ini                         - Configuration (device=wince5)
  devices/
    wince5/                        - WinCE 5.0 device profile
      registry_to_import.reg       - Default registry entries (imported on first run)
      fs/                          - Virtual filesystem root
        Windows/                   - \Windows (ARM DLLs, system files)
        My Documents/              - \My Documents
        Application Data/          - \Application Data
        Program Files/             - \Program Files
```

## Key Concepts

- **Thunking**: ARM code calls COREDLL functions via the IAT. These point to magic addresses (0xFE000000+, `THUNK_BASE`) that the CPU intercepts, executing native Win32 equivalents.
- **Only coredll is thunked**: coredll.dll is the WinCE kernel/system bridge — the only DLL that talks to the OS. All other WinCE DLLs (commctrl, commdlg, ole32, ceshell, aygshell) are user-mode libraries that just use coredll APIs internally. They are loaded and executed as real ARM code in the emulator.
- **Virtual filesystem**: Two-layer path mapping. Multi-letter root dirs (`\Windows\foo`) resolve under `devices/<device>/fs/`. Single-letter root dirs (`\c\foo`) pass through to real host drives (`C:\foo`). Drive letter syntax (`C:\foo`) is equivalent to `\c\foo`. The VFS layer is in `vfs.cpp`; `cerf.ini` selects the active device profile.
- **Bundled device files**: The `bundled/` directory contains device profiles. At build time its contents are copied next to cerf.exe. Each device has a `fs/` directory (virtual filesystem root), a `registry_to_import.reg` (default registry), and a `registry.txt` (persisted registry state).
- **ARM DLL loading**: `LoadArmDll()` searches the exe directory then `devices/<device>/fs/Windows/` for ARM DLLs, loads them via `PELoader::LoadDll()`, and recursively resolves their imports (which may load more ARM DLLs).
- **coredll re-exports**: coredll.def re-exports functions from other DLLs (e.g. ImageList_* from commctrl, GetOpenFileNameW from commdlg, SH* from ceshell/aygshell). These are thunked as native implementations in coredll so apps that import them by ordinal from coredll still work.
- **WinCE trap calls**: Some WinCE apps call APIs via hardcoded trap addresses in the `0xF000xxxx` range (descending from `0xF0010000`). The emulator decodes these as `api_index = (0xF0010000 - addr) / 4` and dispatches to the same thunk handlers.
- **Owner-draw marshaling**: `WM_DRAWITEM` and `WM_MEASUREITEM` carry native 64-bit struct pointers in lParam. `EmuWndProc`/`EmuDlgProc` marshal these into 32-bit ARM layout in emulated memory before forwarding to ARM callbacks.
- **64-bit handle safety**: Native Windows uses 64-bit pointers/handles. ARM code uses 32-bit. Handles are sign-extended via `(intptr_t)(int32_t)` when passing to native APIs, and truncated back to uint32_t for ARM registers.
- **Callback bridging**: Native callbacks (WndProc, DlgProc, TimerProc) invoke back into ARM code via `callback_executor`. Sentinel address 0xCAFEC000 signals callback return.
- **WinCE fullscreen**: WinCE apps run fullscreen by default. CERF sizes windows to the desktop work area and hides borders, preserving the app's original window style for correct rendering.

## Building

```
msbuild cerf.sln /p:Configuration=Release /p:Platform=x64
```

Output: `build/Release/x64/cerf.exe` with `build/Release/x64/devices/wince5/fs/Windows/` containing bundled ARM DLLs, `build/Release/x64/cerf.ini`, etc.

## Testing

```
cerf.exe [options] <path-to-arm-wince-exe>
```

Options: `--trace`, `--log=CATEGORIES`, `--no-log=CATEGORIES`, `--log-file=PATH`, `--flush-outputs`, `--device=NAME`, `--quiet`

Test apps in `tmp/arm_test_apps/`: solitare.exe, chearts.exe, Zuma-arm.exe

## References

The `references/` directory (gitignored) holds local WinCE SDK materials including `coredll.def` (ordinal map) and ARM DLL builds. See `references/README.md` for setup.

## Conventions

- C++17, MSVC (Visual Studio 2022, v143 toolset)
- No external dependencies beyond Win32 SDK
- `LOG()` macro for categorized output: `LOG(THUNK, ...)`, `LOG(PE, ...)`, `LOG(EMU, ...)`, etc.
- Categories: THUNK, PE, EMU, TRACE, CPU, REG, DBG, VFS (defined in `log.h`)
- `LOG_ERR(...)` for errors (always prints to stderr), `LOG_RAW(...)` for uncategorized output
- Static linking (`/MT` runtime)
- Thunk functions return `true` when handled, setting `regs[0]` as the return value

## IMPORTANT: Virtual Filesystem Path Rules

**All file API thunks MUST use `MapWinCEPath()` for input paths and `MapHostToWinCE()` for output paths.** Never let WinCE programs see or use real host filesystem paths.

Path translation rules (implemented in `thunks/coredll/vfs.cpp`):
- `\c\foo\bar` → `C:\foo\bar` (single-letter root = host drive pass-through)
- `\d\` → `D:\` (any single letter = real host drive)
- `C:\foo\bar` → `C:\foo\bar` (drive letter syntax = same pass-through)
- `\Windows\foo` → `<cerf_dir>/devices/<device>/fs/Windows/foo` (multi-letter root = device fs)
- `\My Documents\file.txt` → `<cerf_dir>/devices/<device>/fs/My Documents/file.txt`
- `\anything` → `<cerf_dir>/devices/<device>/fs/anything`
- `relative.txt` → `<cerf_dir>/devices/<device>/fs/relative.txt`

Reverse mapping (`MapHostToWinCE`): host drive paths (`C:\foo`) become `\c\foo`; paths under device fs root get prefix stripped and leading `\` added.

## IMPORTANT: Thunk File Organization

**Each functional group within coredll MUST have its own `.cpp` file in `thunks/coredll/`.** No single thunks file should exceed 100-200 lines. When a file grows beyond that, split it into smaller focused files.

- Each file has its own `Register*Handlers()` method declared in `win32_thunks.h` and called from the constructor in `win32_thunks.cpp`.
- New files must be added to `cerf.vcxproj` under `<ClCompile>`.

**NEVER pile unrelated thunks into an existing file.** Create a new file proactively.

## IMPORTANT: Logging is Encouraged

**Feel free to add, extend, or enhance LOG() calls in any thunk or subsystem.** Verbose, detailed logging is valuable for debugging future issues. When investigating a problem, adding extra logging (parameter values, return values, intermediate state) is always appropriate — don't hold back. Detailed logs have proven invaluable for diagnosing issues across sessions.

## IMPORTANT: Stub Functions Must Log

**Every stub function MUST print a console warning** so unimplemented calls are visible during testing. Use the format:
```cpp
LOG(THUNK, "[THUNK] FunctionName(...) -> stub\n");
```
Never create a silent stub that just returns a value without logging. This is critical for debugging which functions apps actually call.

## IMPORTANT: Capturing App Output

**Always use `--flush-outputs`** when capturing logs. Without it, buffered output will be truncated when the process is killed.
```
cerf.exe --flush-outputs [options] <app.exe> > log.txt 2>&1
```
Apps run a GUI message loop and won't exit on their own. Launch in background, wait ~10s, then read the log file. Use `taskkill //f //im cerf.exe` when done investigating.

## IMPORTANT: App Interaction & Visual Verification

Use `tools/interact.py` to screenshot, click, type, and inspect running apps. See `tools/INTERACTION_GUIDE.md` for full reference.

**CRITICAL**: After EVERY mouse/keyboard interaction, take a screenshot and verify the result before proceeding.

```bash
# Inspect windows (classes, titles, coordinates, child tree)
python3 tools/interact.py windows

# Take screenshot (saved to screenshot.png, then read it with Read tool)
python3 tools/interact.py screenshot

# Click/type/key (auto-foregrounds the cerf window first)
python3 tools/interact.py click X Y          # use center coords from 'windows' output
python3 tools/interact.py dclick X Y         # double-click (e.g. open ListView items)
python3 tools/interact.py key enter          # press named key
python3 tools/interact.py type "text"        # type text string
python3 tools/interact.py combo ctrl+a       # key combinations

# Old inspection tool (still works, less features)
python3 tools/inspect_cerf.py
```

Workflow: launch app → `windows` to get coordinates → `screenshot` to see UI → `click`/`key` to interact → `screenshot` to verify → repeat. Always `taskkill //f //im cerf.exe` when done.

## IDA Pro MCP Servers (Reverse Engineering)

IDA Pro instances are connected via MCP for decompiling WinCE ARM DLLs. See `tools/IDA_MCP_GUIDE.md` for full reference.

Available instances: `ida-ceshell`, `ida-commctrl`, `ida-commdlg`, `ida-target-app`, `ida-windows-ce-original-coredll`. Use `ToolSearch` to load tools before calling them (e.g. `ToolSearch query: "+ida-commctrl decompile"`).

Key tools: `ida_decompile` (C pseudocode), `ida_list_functions`, `ida_get_exports`, `ida_get_xrefs` (cross-references), `ida_get_names`, `ida_get_strings`.

**Target app** changes per session — ask user to switch if needed. You can also ask user to open additional IDA instances for other DLLs.
