# commctrl.dll (Common Controls) - Known Issues

## 1. Command bar close (X) button had no icon — RESOLVED

**Description**: WinCE command bars (the title/menu bar area) show an X button (close) in the top-right corner. The button existed but rendered without its icon glyph.

**Root cause (multi-part)**:
1. ARM commctrl's `CommandBar_AddAdornments` sends `TB_ADDBITMAP` with `HINST_COMMCTRL (-1)` and bitmap ID 140 (close). The ARM toolbar's `AddBitmap` → `MapToStandardBitmaps` maps ID 140 to `btClose`, then `LoadSystemBitmap(btClose)` calls `SHLoadDIBitmap("\\windows\\close.2bp")`.
2. `SHLoadDIBitmap` is coredll ordinal 487. ceshell.dll "exports" it but it's a **PE forwarder** back to `COREDLL.SHLoadDIBitmap` — creating a circular reference. Our `forwardToArm("ceshell.dll", "SHLoadDIBitmap")` tried to execute the forwarder string as ARM code.
3. The `.2bp` files (WinCE 2-bits-per-pixel bitmaps) were missing from our bundled filesystem.
4. Desktop Windows doesn't support 2bpp BMPs — `CreateDIBitmap` returns NULL for 2bpp data.

**Fix**:
- Implemented `SHLoadDIBitmap` natively in `shell.cpp`: reads BMP from VFS, converts WinCE 2bpp format to 4bpp for desktop Windows.
- Bundled `close.2bp`, `ok.2bp`, `stdsmxp.bmp`, `stdsm.2bp`, `viewsmxp.bmp`, `viewsm.2bp` in `devices/wince5/fs/Windows/`.
- Removed the `TB_ADDBITMAP` skip for bitmap IDs 140/142 — no longer needed since the ARM toolbar can now load the bitmaps via `SHLoadDIBitmap`.

---

## 2. Help (?) button showed wrong icon — RESOLVED

**Description**: The command bar ? (help) button showed a "What's This?" cursor icon (mouse pointer with question mark) instead of a simple "?" question mark, as seen on real WinCE devices.

**Root cause**: ARM commctrl's `InitGlobalColors` calls `GetDeviceCaps(hdc, BITSPIXEL)` and stores it in `g_nBitsPerPixel`. In `MapToStandardBitmaps`, when `g_nBitsPerPixel == 2`, it loads mono-style bitmaps (resource 122 → `stdsm.2bp`); otherwise it loads XP-style bitmaps (resource 120 → `stdsmXP.bmp`). On our desktop Windows, `BITSPIXEL` returns 32, so commctrl always loaded `stdsmXP.bmp` which has a "What's This?" cursor at index 11 (STD_HELP). The WinCE mono bitmap `stdsm.2bp` has the correct simple "?" at that index.

**Fix**: In the `GetDeviceCaps` thunk (`gdi_dc.cpp`), return `2` for `BITSPIXEL`. This tells ARM commctrl we have a 2bpp display, causing it to load `stdsm.2bp` which has the correct simple "?" icon matching real WinCE devices.

**Files changed**: `cerf/thunks/coredll/gdi_dc.cpp`

---
