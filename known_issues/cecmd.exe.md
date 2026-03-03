# cecmd.exe (Total Commander/CE) - Known Issues

## 1. Black ListView column headers — RESOLVED

**Description**: The SysHeader32 column headers in the file list panels render with a black/unstyled background.

**Root cause**: `GetBkColor` (ordinal 913) was not thunked. ARM commctrl's `Header_t::Draw` calls `SetBkColor` then `GetBkColor` to save/restore the DC background color. Without the thunk, `GetBkColor` returned 0 (black), so the header background was painted black.

**Fix**: Added thunks for `GetBkColor` (913), `GetTextColor` (914), `GetClipRgn` (972), and `SetAssociatedMenu` (299 stub). Headers now render correctly with 3D button styling and proper text.

---

## 2. No file/folder icons in ListView rows — RESOLVED

**Description**: The file listing in both panels shows no icons next to file/folder names. On real WinCE, each row has a small icon (folder icon for directories, file type icons for files).

**Root cause (multi-part)**:
1. `ceshell.dll`'s `CIconCache::RebuildSystemImageList` loads icon resources 5376-5381 from itself for system file type icons (folder, file, etc.). Our bundled `ceshell.dll` has **no icon resources at all** — `FindResourceW` returns NULL for all icon IDs.
2. HDC sign-extension bug in `ImageList_Draw`, `ImageList_DrawEx`, and `ImageList_DrawIndirect` — GDI handles need zero-extension `(HDC)(uintptr_t)` not sign-extension `(HDC)(intptr_t)(int32_t)`.
3. **`callback_executor` didn't push stack arguments** for functions with >4 args. `SHGetFileInfo` has 5 args — the 5th (`uFlags`) was never placed on the ARM stack, so ARM code read garbage.
4. **`InterlockedCompareExchange` (ordinal 1492) was not thunked.** `CIconCache` uses a singleton pattern via `InterlockedCompareExchange` to cache the icon cache pointer. Without the thunk, the global pointer was never updated — each `SHGetFileInfo` call created a new `CIconCache` (new image lists) and the return value was wrong (1 instead of HIMAGELIST).

**Fix**:
- Added native icon fallback in `LoadImageW` for ceshell icon IDs 5376-5381 using `ExtractIconExW` from `shell32.dll`
- Fixed HDC zero-extension in ImageList draw functions
- Fixed `callback_executor` in `main.cpp` to push args[4+] onto the ARM stack
- Added `InterlockedCompareExchange` thunk (ordinal 1492) in `system.cpp`

All 6 system icons (file, exe, closed folder, open folder, drive, shortcut) now load at both 16x16 and 32x32 sizes. File list shows correct folder icons.

---

## 3. Black areas in Properties dialog / tab control — RESOLVED

**Description**: The Properties dialog (Alt+Enter on a file/folder) had a black area at the top. The SysTabControl32 tabs ("General", "Disk space") rendered with black backgrounds.

**Root cause**: WinCE added `COLOR_STATIC=25` and `COLOR_STATICTEXT=26` to the system color palette. Desktop Windows doesn't define index 25 (returns 0 = black), and index 26 maps to `COLOR_HOTLIGHT` (different meaning). ARM commctrl's `Tab_t::Paint` calls `GetSysColor(0x40000019)` (= index 25 with WinCE flag) for the tab background color, getting black.

**Fix**:
- Mapped WinCE color indices in `GetSysColor` and `GetSysColorBrush` thunks: index 25→`COLOR_3DFACE`, index 26→`COLOR_WINDOWTEXT`
- Also fixed window class brush mapping in `RegisterClassW`: brush_val 26→`COLOR_3DFACE+1`, 27→`COLOR_WINDOWTEXT+1`
- Added `GetDiskFreeSpaceExW` implementation (needed by "Disk space" tab)

Tab headers now visible, gray background, proper layout. "Disk space" tab shows correct free/total space.

---

## 4. No icon in Properties dialog — RESOLVED

**Description**: The Properties dialog should display a large icon representing the selected item type.

**Root cause**: Same as Issue 2 — missing `InterlockedCompareExchange` thunk meant `CIconCache` was never cached, so `SHGetFileInfo` couldn't return the system HIMAGELIST.

**Fix**: Resolved by the same fixes as Issue 2. The Properties dialog now shows the correct folder/file icon.

---

## 5. Wrong fonts — RESOLVED

**Description**: Text in file panels, toolbars, buttons, combo boxes, and dialogs used desktop Windows fonts (Segoe UI, System bitmap font) instead of the WinCE system font (Tahoma).

**Root cause (multi-part)**:
1. `GetStockObject(DEFAULT_GUI_FONT)` returned the desktop "MS Shell Dlg" font. On real WinCE, the system font is configured via `HKLM\System\GDI\SYSFNT` registry (Nm=Tahoma, Ht=-12, Wt=400).
2. `CreateFontIndirectW` with face name "System" created the desktop bitmap System font instead of the WinCE Tahoma.
3. Native controls (ComboBox, Button, Edit) defaulted to Segoe UI because on desktop Windows that's the default, while on real WinCE the default is Tahoma — no explicit WM_SETFONT needed.
4. Dialog templates with DS_SETFONT specified "System" font, which mapped to the desktop bitmap font.
5. Dialog templates without DS_SETFONT got no font at all, falling back to the desktop System font.

**Fix**:
- `gdi_text.cpp`: Read WinCE system font from `HKLM\System\GDI\SYSFNT` registry at startup. `GetStockObject(DEFAULT_GUI_FONT)` now returns a font created from those registry values. `CreateFontIndirectW` maps "System" face name to the configured WinCE system font.
- `window.cpp`: After `CreateWindowExW`, automatically send `WM_SETFONT` with the WinCE system font to all child controls (ComboBox, Button, Edit, etc.).
- `dialog.cpp`: `FixupDlgTemplate` replaces the font name in dialog templates with the WinCE system font (Tahoma). Preserves original point size for DS_SETFONT templates. Adds DS_SETFONT with 8pt default when absent.
- `message.cpp`: Sign-extend HFONT handle in `WM_SETFONT` messages for 64-bit safety.

File list, path ComboBoxes, toolbar buttons, and Properties dialog all now use Tahoma with correct sizing.

---

## 6. Command bar ? button showed wrong icon — RESOLVED

**Description**: The ? (help) button in the command bar showed a "What's This?" cursor icon instead of a simple "?" question mark.

**Root cause**: See `commctrl.dll.md` Issue 2. ARM commctrl loaded `stdsmXP.bmp` (which has a cursor+? icon at index 11) instead of `stdsm.2bp` (which has a simple "?" at index 11) because `GetDeviceCaps(BITSPIXEL)` returned 32 on desktop Windows.

**Fix**: Return 2 for `BITSPIXEL` in `GetDeviceCaps` thunk so commctrl loads the WinCE mono bitmap set.

---

## 7. "Missing status bar" investigation — NOT A BUG

**Description**: The dark bar at the bottom of the real WinCE screenshot (showing "Total Commander/CE" and clock) appeared to be a missing status bar in cerf.

**Finding**: This is the **WinCE system taskbar**, not a cecmd status bar. cecmd.exe never creates an `msctls_statusbar32` window. The bar is part of the WinCE shell (`explorer.exe`), not the app. No fix needed.

---

## Screenshots

- Current: `screenshots/cecmd_current.png`
- Expected: See reference screenshots provided by user (real WinCE device running cecmd.exe)
