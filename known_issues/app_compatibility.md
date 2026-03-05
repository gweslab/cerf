# App Compatibility Survey

Quick test results for WinCE apps from `references/Optional Programs/`.

## Working Well

| App | Size | Description | Status |
|-----|------|-------------|--------|
| Clock.exe (DeClock) | 20KB | Multi-timezone digital clock + calendar | Fully functional, live updating |
| notepad.exe | 27KB | WinCE Notepad | Fully functional, typing works |
| calc.exe | 34KB | Calculator with history | Buttons and computation work |
| Converter.exe | 39KB | Unit converter (temp, length, etc.) | BROKEN — crashes on startup (AYGSHELL DllMain vtable call to NULL, pre-existing) |
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

| explorer.exe | WinCE 5 HPC shell — desktop icons with wallpaper, Start Menu (Programs/Favorites/Settings/Run/Suspend), taskbar with clock, launching apps from menu (.lnk shortcuts), right-click Properties opens Display Properties control panel (ctlpnl.exe + cplmain.cpl), live wallpaper change. Missing: folder navigation (needs COM/IShellFolder), some icons wrong |
| ctlpnl.exe (Control Panel) | Display Properties dialog works — Background and Backlight tabs, image dropdown, Browse button, tile checkbox. Launched via ShellExecuteEx from explorer or directly with `cerf.exe ctlpnl.exe cplmain.cpl,7` |
| spread_excel.exe (SpreadCE) | WinCE 7 app — window sizing and menu text work, but bottom menu bar clicks don't open menus (ARM modal message loop issue) |
| DocOpen.exe (PHM Tools) | File open dialog works after memcpy/DllMain fixes. Toolbar buttons now work (memory allocator fix). ComboBox doesn't render until clicked. |
| Run.exe (PHM Tools) | Browse dialog works after DllMain fix. Wrong icon in dialog (warning icon instead of app icon). |

## Not Working

| App | Issue |
|-----|-------|
| explorer.exe | WinCE 5 desktop shell — see "Partially Working" section |
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
11. **memcpy/memmove/memset cross-region safety**: Check host pointer contiguity before native memcpy. Fallback regions (NOT identity-mapped) may have non-adjacent host addresses for adjacent emulated pages. Fall back to byte-by-byte copy. Fixed DocOpen.exe crash.
12. **ARM DLL DllMain initialization**: Call DllMain(DLL_PROCESS_ATTACH) for on-demand loaded ARM DLLs before forwarding API calls. Fixed g_pShellMalloc NULL crash in ceshell.dll's SHGetOpenFileName (Run.exe Browse, DocOpen.exe).
13. **CreateThread inline execution**: Implemented pseudo-thread model — runs thread function synchronously via callback_executor with `in_pseudo_thread` flag. GetMessageW drains pending messages then returns WM_QUIT in pseudo-thread mode, allowing thread message loops to exit cleanly. Main WinMain message pump handles all windows.
14. **EventModify**: Replaced stub with real implementation calling SetEvent/ResetEvent/PulseEvent based on func parameter (WinCE kernel API).
15. **WinCE kernel API stubs**: Added RegisterDesktop (1507), RegisterTaskBar (892), RegisterTaskBarEx (1506), SignalStarted (639), OpenEventW (1496), CreateAPISet (559), RegisterAPISet (635), MapCallerPtr (1602), and many other explorer.exe dependencies.
16. **WS_POPUP desktop window sizing**: Skip WS_CAPTION injection for WS_POPUP top-level windows (desktop, taskbar) — use dimensions as-is from WinCE GetSystemMetrics.
17. **InsertMenuW MF_OWNERDRAW dwItemData**: MF_OWNERDRAW items pass lpNewItem as dwItemData (ARM pointer to menu data struct), not as a string. Fixed to pass `(LPCWSTR)(uintptr_t)lpNewItem` for owner-drawn items, matching AppendMenuW behavior. Fixed empty Programs submenu in explorer.
18. **GetTimeFormatW / GetDateFormatW**: Implemented proper thunks (were stubbed as 0). Read SYSTEMTIME from ARM memory, call native API, write result back. Fixed clock displaying as 8px-wide window.
19. **ShellExecuteEx .lnk resolution**: WinCE .lnk shortcuts use simple `#\path\to\target.exe` text format. ShellExecuteEx now reads .lnk files, extracts the target path, and launches via cerf.exe if target is ARM PE.
20. **Desktop wallpaper**: Bundled windowsce.bmp in VFS `\Windows\`, updated registry from .jpg to .bmp path. SHLoadDIBitmap only handles .bmp, not .jpg.
21. **ShellExecuteEx `\Windows\` search path**: Bare filenames (e.g. `ctlpnl.exe`) now resolved via `\Windows\<filename>` fallback when initial VFS mapping fails. Also passes ShellExecuteEx params to spawned cerf child processes.
22. **cerf.exe argument parsing**: First non-option arg is the ARM exe path; subsequent args are ignored by cerf and available to the ARM app via GetCommandLineW.
23. **WinMain lpCmdLine**: Populate R2 (lpCmdLine) from argv arguments after the exe path, instead of hardcoded empty string. Fixed ctlpnl.exe DEBUGCHK at line 60.
24. **StringCbCopyExW (ordinal 1692)**: Byte-count version of StringCchCopyExW. Used by ctlpnl.exe ParseCPLCmdLine.
25. **StringCbPrintfW (ordinal 1700)**: Byte-count version of StringCchPrintfW. Used by commctrl.dll property sheet code.
26. **LoadLibraryW dependency DllMain initialization**: Call DllMain for ALL pending ARM DLLs (dependencies first), not just the directly-loaded DLL. Fixed commctrl.dll g_hinst=0 causing InitToolbarClass/PropertySheetW to fail. This was the root cause of ctlpnl.exe showing no property sheet dialog.
27. **Case-insensitive registry value names**: WinCE registry is case-insensitive for value names. Normalize to lowercase on read/write/delete/load. Fixed Display Properties wallpaper lookup ('Wallpaper' vs 'wallpaper').
28. **SPI_SETDESKWALLPAPER**: Implemented in SystemParametersInfoW — don't forward WinCE VFS paths to native Windows. Broadcast WM_SETTINGCHANGE for desktop wallpaper refresh.
29. **PostMessageW(HWND_BROADCAST, WM_SETTINGCHANGE) → SendMessageW**: PostMessage during nested in-process execution gets lost because the modal message loop ends before dispatching. Convert to synchronous SendMessage for reliable delivery.
30. **memcpy bogus length protection**: Skip memcpy calls with length > 8MB (0x800000) instead of capping at 1MB. Prevents hangs from ARM code passing garbage lengths (e.g. 0x80000000 from stale COM object state). Fixed Display Properties second-open hang.
31. **Memory allocator address space collision + pre-reservation**: LocalAlloc (starting 0x00800000) grew past LocalReAlloc's range (0x00900000) after 240+ allocations, creating overlapping memory regions. Fixed by reorganizing with wider gaps (LocalAlloc→0x00800000, LocalReAlloc→0x00A00000, HeapAlloc→0x00C00000). Also fixed identity-mapping failures: Windows VirtualAlloc requires 64KB-aligned addresses for MEM_RESERVE, so page-by-page allocations at non-64KB-aligned addresses failed. Added pre-reservation of large contiguous blocks at each allocator base, with subsequent page commits within the reservation. Fixed HeapCreate to return handles instead of allocating overlapping memory. Made malloc/calloc/realloc share a single counter.
