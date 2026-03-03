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

## 5. Wrong fonts — OPEN

**Description**: The app appears to use the system font (possibly MS Shell Dlg or System), but on real WinCE it uses a different font — likely Arial or the default WinCE theme font. Text in the file panels, toolbars, and dialogs looks different from the real device.

**Expected**: Font rendering should match the real WinCE device (see `screenshots/cecmd_real.png`). Likely needs a default font override or WinCE-specific `SystemParametersInfo` / `GetStockObject(DEFAULT_GUI_FONT)` mapping.

**Theoretical font priority** (for the solution):
1. Device's `\Windows\Fonts\` directory (bundled WinCE fonts)
2. Real desktop Windows fonts (host system fallback)
3. Default behaviour (system font)

**Font files location**: WinCE fonts are present in the `references/` directory (see `references/README.md`) but are **not bundled** with cerf. They need to be manually copied to `devices/wince5/fs/Windows/Fonts/` after each build (not checked into the repo or bundled via vcxproj).

---

## Screenshots

- Current: `screenshots/cecmd_current.png`
- Expected: See reference screenshots provided by user (real WinCE device running cecmd.exe)
