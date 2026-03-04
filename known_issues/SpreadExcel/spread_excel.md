# SpreadExcel (SpreadCE) - spread_excel.exe

**Source:** `references/WinCE7_Apps_[TechKnowForum.net]/SpreadExcel/spread_excel.exe`
**Type:** WinCE 7 spreadsheet app (SpreadCE v1.17 by Bye Design Ltd)

## Issues

### 1. Completely wrong main window size - RESOLVED
The main window was created at 320x240 and never resized to fill the screen. Three root causes:
- **Ordinal 5403**: ARM aygshell.dll called coredll trap ordinal 5403 (SystemParametersInfoW in WinCE 7 coredll) which was unhandled, returning 0.
- **WM_SETTINGCHANGE lParam**: Desktop Windows sends WM_SETTINGCHANGE with wParam=SPI_SETSIPINFO (0xE0) and lParam=0 (string pointer). WinCE convention is lParam=SPI_SETSIPINFO (224). The app checks lParam==224.
- **SPI action 0xE1**: The app's WM_SETTINGCHANGE handler calls SHSipInfo(0xE1, 0, &sipinfo, 0) via aygshell, which calls SystemParametersInfoW(0xE1, ...) through trap ordinal 5403. Action 0xE1 is a WinCE 7 variant of SPI_GETSIPINFO. Without handling it, the SIPINFO output buffer was never written, producing garbage SetWindowPos values (y=908584, cx=908628, cy=-908584).

**Fixes:**
- Added ordinal 5403 as alias for SystemParametersInfoW (WinCE 7 aygshell uses this ordinal)
- Translate WM_SETTINGCHANGE lParam from desktop convention to WinCE convention in EmuWndProc callback
- Handle SPI action 0xE1 as SIPINFO query (returns work area as visible desktop, SIP hidden)

**Important:** SPI_GETSIPINFO (0x68) must NOT be handled — WinCE 5 apps (cecmd.exe etc.) call it during init, and returning TRUE changes their layout code path, causing dark/missing column headers and toolbar areas. Only 0xE1 (WinCE 7 variant used by aygshell) should be handled.

### 2. Truncated menu bar captions - RESOLVED
Bottom menu bar showed "F... E... Ins... Form..." instead of "File Edit Insert Format".
Root cause: SM_CXEDGE returns 2 on desktop Windows vs 1 on WinCE. The ARM commctrl.dll toolbar code calculates button width using DrawTextW DT_CALCRECT, but subtracts g_cxEdge from the text area during painting. The 1px difference caused every button to be 1px too narrow, triggering ellipsis truncation.

**Fix:** Override SM_CXEDGE and SM_CYEDGE to return 1 (WinCE value) in GetSystemMetrics thunk.

### 3. Menu bar does not react to clicking - OPEN
Clicking "File", "Edit", etc. in the bottom menu bar does not open popup menus.
The WM_LBUTTONDOWN reaches the ARM ToolbarWindow32 WndProc, but the toolbar's internal modal message loop (SetCapture + GetMessage wait for WM_LBUTTONUP) doesn't work correctly. The WM_LBUTTONUP never arrives at the captured toolbar. Likely an issue with how the ARM emulation handles re-entrant message dispatch during modal loops inside WndProc handlers.

### 4. Toolbar background color - OPEN
The top toolbar (icon bar) has a dark/maroon background instead of light gray. May be related to how the ARM commctrl.dll toolbar paint code interacts with desktop Windows GDI (image list blitting, pattern brushes).
