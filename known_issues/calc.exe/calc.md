# calc.exe (WinCE Calculator) Known Issues

## Setup
- App location: `calc.exe` (copy to build/Release/x64/ or use full path)
- Reference screenshot: `tmp/ce_rose_calc.png` (real WinCE Rose theme)
- Run: `cerf.exe --flush-outputs calc.exe`

## Issues

### X button infinite loop (REGRESSION)
- **Status**: OPEN
- **Symptom**: Clicking the X (close) button causes an infinite loop / hang
- **Root cause**: Not fully diagnosed. Related to WM_CLOSE/WM_SYSCOMMAND/WM_DESTROY message handling. Debug logging was added to EmuWndProc and DestroyWindow thunks. The DestroyWindow thunk was reordered to erase hwnd_wndproc_map AFTER DestroyWindow returns (so WM_DESTROY reaches ARM code).
- **Regression from**: Theming subclass WM_NCPAINT/WM_NCACTIVATE handling (now mostly resolved by switching to inline hook approach)
- **Files**: `cerf/thunks/callbacks.cpp`, `cerf/thunks/coredll/window.cpp`
- **Note**: DO NOT attempt to debug this by running the app and clicking X — it may generate massive log files. Kill the process immediately if it hangs.

### Scrollbar dithering uses Win11 stock colors
- **Status**: OPEN (cosmetic, low priority)
- **Symptom**: ListBox scrollbar track shows ~8-9 pixels of #f0f0f0 per row (Win11 stock COLOR_3DFACE) instead of Rose themed color
- **Root cause**: user32.dll's scrollbar painting code reads the kernel-side color table directly, bypassing the GetSysColor hook
- **Workaround**: None. This is a limitation of the inline hook approach — the kernel color table is not accessible from user mode.

### Caption color slightly different from reference
- **Status**: OPEN (cosmetic)
- **Symptom**: Our active caption is #9f6070, reference WinCE shows #9c6173
- **Root cause**: Registry SysColor data has slightly different values than the reference device. This is a registry data issue, not a code issue.
