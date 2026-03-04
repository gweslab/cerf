# App Compatibility Survey

Quick test results for WinCE apps from `references/Optional Programs/`.

## Working Well

| App | Size | Description | Status |
|-----|------|-------------|--------|
| Clock.exe (DeClock) | 20KB | Multi-timezone digital clock + calendar | Fully functional, live updating |
| notepad.exe | 27KB | WinCE Notepad | Fully functional, typing works |
| calc.exe | 34KB | Calculator with history | Buttons and computation work |
| Converter.exe | 39KB | Unit converter (temp, length, etc.) | Fully functional after atof fix |
| PLamp.exe | 15KB | Flashlight / screen color tool | Fully functional, color buttons work |
| CpuLoad.exe | 20KB | CPU load monitor | Shows CPU %, slider works |
| VolumeCtrl.exe | 46KB | Volume control with custom dial | Custom GDI drawing works |
| WinWatch.exe | 24KB | Window position fixer | Complex dialog with checkboxes works |
| Life.exe (G_Life) | game | Conway's Game of Life | Grid, cell placement, auto-run work |
| Patiences.exe | game | Solitaire card game | Runs, green baize drawn, cards are blank white |
| solitare.exe | 18KB | WinCE Solitaire (Optional Programs) | Fully functional — cards, game panel, title bar all working |

## Partially Working

| App | Issue |
|-----|-------|
| Mem.exe (Enjoy Memory) | Chinese memory manager — shows "? M" for memory values (missing GetStoreInformation) |
| CETree SysMetrics.exe | Stuck on "CPU speed" benchmark (emulation too slow for tight loops) |
| Patiences.exe | Cards render as white rectangles (bitmap/StretchBlt issue) |
| PEInfo.exe | Shows empty window (needs a file to open, may work with interaction) |
| BananaPC.exe | Creates tiny 51x16 taskbar widget (works but useless outside WinCE taskbar) |

| spread_excel.exe (SpreadCE) | WinCE 7 app — window sizing and menu text work, but bottom menu bar clicks don't open menus (ARM modal message loop issue) |

## Not Working

| App | Issue |
|-----|-------|
| Regedit.exe (TascalRegEdit) | Loops showing "Debug" error dialogs |
| ITaskMgr.exe | "Application initialize failed" |
| Crux_View.exe | Segfault on startup |
| DMinesweeper.exe | Crash on startup |
| Tetris.exe | Runs but no windows created |

## Fixes Applied

1. **atof (ordinal 995)**: Added CRT thunk needed by Converter.exe and other apps
2. **atol (ordinal 994)**: Added CRT thunk
3. **Float format specifiers**: Added %f/%e/%g/%G/%E support to wprintf_format helper — doubles occupy two consecutive 32-bit ARM args
4. **Dialog template DWORD alignment**: Fixed FixupDlgTemplate font name replacement corrupting DLGITEMTEMPLATE alignment when font name size changes (e.g. "MS Sans Serif" → "Tahoma"). This broke solitare.exe's game panel.
5. **SystemParametersInfoW SPI_GETWORKAREA**: Marshal RECT output to emulated memory. Fixed ResInfo.exe off-screen positioning.
6. **Window title text**: Fixed DefWindowProcW WM_SETTEXT to marshal ARM string pointers to native strings. Added WS_CAPTION to top-level windows.
7. **WinCE 7 coredll ordinal 5403**: Mapped to SystemParametersInfoW — used by WinCE 7 aygshell.dll. Fixed SpreadExcel main window sizing.
8. **SM_CXEDGE/SM_CYEDGE override**: Return 1 (WinCE value) instead of 2 (desktop). Fixed ARM commctrl.dll toolbar button text truncation.
9. **WM_SETTINGCHANGE lParam translation**: Desktop sends lParam=0, WinCE convention is lParam=SPI constant. Translated in EmuWndProc callback.
10. **SPI action 0xE1 (WinCE 7 SPI_GETSIPINFO)**: Implemented in SystemParametersInfoW thunk. Returns SIPINFO struct with work area. Only 0xE1 is handled (not 0x68 — handling 0x68 breaks WinCE 5 app layouts).
