#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* ImageList and common controls init — coredll re-exports from commctrl.
   When an app links against coredll (which re-exports these),
   we handle them natively. When an app loads the real ARM commctrl.dll,
   that DLL runs as ARM code and calls coredll itself.

   HIMAGELIST is a user-mode pointer (struct _IMAGELIST*), NOT a kernel
   handle like HWND/HMENU. It cannot survive 32-bit truncation + sign-extension.
   We use WrapHandle/UnwrapHandle to map native 64-bit pointers to safe
   32-bit tokens that ARM code can store and pass back. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <commctrl.h>

void Win32Thunks::RegisterImageListHandlers() {
    /* InitCommonControlsEx / InitCommonControls — forward to ARM commctrl.dll.
       The ARM DLL must run its own init (sets fControlInitalized, registers window
       classes with ARM WndProcs, initializes critical sections). We resolve the
       export and call into ARM code. If commctrl isn't loaded yet, we load it. */
    Thunk("InitCommonControlsEx", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] InitCommonControlsEx(icc=0x%08X)\n", regs[0]);
        LoadedDll* cc = LoadArmDll("commctrl.dll");
        if (cc && callback_executor) {
            uint32_t addr = PELoader::ResolveExportName(mem, cc->pe_info, "InitCommonControlsEx");
            if (addr) {
                uint32_t args[1] = { regs[0] };
                regs[0] = callback_executor(addr, args, 1);
                return true;
            }
        }
        LOG(API, "[API]   commctrl.dll not available, using native fallback\n");
        INITCOMMONCONTROLSEX icc = {};
        icc.dwSize = sizeof(icc);
        icc.dwICC = regs[0] ? mem.Read32(regs[0] + 4) : 0xFFFF;
        regs[0] = InitCommonControlsEx(&icc);
        return true;
    });
    Thunk("InitCommonControls", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] InitCommonControls()\n");
        LoadedDll* cc = LoadArmDll("commctrl.dll");
        if (cc && callback_executor) {
            uint32_t addr = PELoader::ResolveExportName(mem, cc->pe_info, "InitCommonControls");
            if (addr) {
                callback_executor(addr, nullptr, 0);
                regs[0] = 0;
                return true;
            }
        }
        InitCommonControls(); regs[0] = 0; return true;
    });
    Thunk("ImageList_Create", 742, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* WinCE default: ILC_MASK (0x1) with no ILC_COLORxx → screen depth (16bpp).
           Desktop default: ILC_COLOR (0) → 4bpp (16 colors), making icons look terrible.
           Upgrade to ILC_COLOR32 when no color depth is specified. */
        UINT flags = regs[2];
        if ((flags & 0xFE) == 0) flags |= ILC_COLOR32;
        HIMAGELIST h = ImageList_Create(regs[0], regs[1], flags, regs[3], ReadStackArg(regs, mem, 0));
        uint32_t wrapped = h ? WrapHandle((HANDLE)h) : 0;
        LOG(API, "[API] ImageList_Create(cx=%d, cy=%d, flags=0x%X, init=%d, grow=%d) -> 0x%08X\n",
            regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0), wrapped);
        regs[0] = wrapped;
        return true;
    });
    Thunk("ImageList_Destroy", 743, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HIMAGELIST h = (HIMAGELIST)UnwrapHandle(regs[0]);
        LOG(API, "[API] ImageList_Destroy(0x%08X -> %p)\n", regs[0], h);
        regs[0] = ImageList_Destroy(h);
        if (regs[0]) RemoveHandle(regs[0]);
        return true;
    });
    Thunk("ImageList_Add", 738, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Add((HIMAGELIST)UnwrapHandle(regs[0]),
            (HBITMAP)(intptr_t)(int32_t)regs[1], (HBITMAP)(intptr_t)(int32_t)regs[2]);
        return true;
    });
    Thunk("ImageList_Draw", 748, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ImageList_Draw((HIMAGELIST)UnwrapHandle(regs[0]), regs[1],
            (HDC)(uintptr_t)regs[2], regs[3], ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    });
    Thunk("ImageList_DrawEx", 749, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HIMAGELIST himl = (HIMAGELIST)UnwrapHandle(regs[0]);
        int i = (int)regs[1];
        HDC hdc = (HDC)(uintptr_t)regs[2];
        int x = (int)regs[3];
        int y = (int)ReadStackArg(regs, mem, 0);
        int dx = (int)ReadStackArg(regs, mem, 1);
        int dy = (int)ReadStackArg(regs, mem, 2);
        COLORREF rgbBk = ReadStackArg(regs, mem, 3);
        COLORREF rgbFg = ReadStackArg(regs, mem, 4);
        UINT fStyle = ReadStackArg(regs, mem, 5);
        LOG(API, "[API] ImageList_DrawEx(himl=%p, i=%d, hdc=%p, x=%d, y=%d, dx=%d, dy=%d, style=0x%X)\n",
            himl, i, hdc, x, y, dx, dy, fStyle);
        regs[0] = ImageList_DrawEx(himl, i, hdc, x, y, dx, dy, rgbBk, rgbFg, fStyle);
        return true;
    });
    Thunk("ImageList_GetImageCount", 756, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HIMAGELIST h = (HIMAGELIST)UnwrapHandle(regs[0]);
        int count = ImageList_GetImageCount(h);
        LOG(API, "[API] ImageList_GetImageCount(0x%08X -> %p) -> %d\n", regs[0], h, count);
        regs[0] = count;
        return true;
    });
    Thunk("ImageList_LoadImage", 758, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], lpbmp = regs[1], cx = regs[2], cGrow = regs[3];
        COLORREF crMask = ReadStackArg(regs, mem, 0);
        UINT uType = ReadStackArg(regs, mem, 1);
        UINT uFlags = ReadStackArg(regs, mem, 2);
        LOG(API, "[API] ImageList_LoadImage(0x%08X, %d, cx=%d, cGrow=%d, crMask=0x%X, type=%d, flags=0x%X)\n",
               hmod, lpbmp, cx, cGrow, crMask, uType, uFlags);
        HMODULE native_mod = NULL;
        bool is_arm = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) { if (pair.second.base_addr == hmod) { is_arm = true; break; } }
        if (is_arm) native_mod = GetNativeModuleForResources(hmod);
        else native_mod = (HMODULE)(intptr_t)(int32_t)hmod;
        HIMAGELIST h = native_mod ? ImageList_LoadImageW(native_mod, MAKEINTRESOURCEW(lpbmp), cx, cGrow, crMask, uType, uFlags) : NULL;
        regs[0] = h ? WrapHandle((HANDLE)h) : 0;
        return true;
    });
    Thunk("ImageList_GetIconSize", 755, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cx, cy; BOOL ret = ImageList_GetIconSize((HIMAGELIST)UnwrapHandle(regs[0]), &cx, &cy);
        if (regs[1]) mem.Write32(regs[1], cx); if (regs[2]) mem.Write32(regs[2], cy);
        regs[0] = ret; return true;
    });
    Thunk("ImageList_AddMasked", 739, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HIMAGELIST himl = (HIMAGELIST)UnwrapHandle(regs[0]);
        HBITMAP hbm = (HBITMAP)(intptr_t)(int32_t)regs[1];
        COLORREF crMask = (COLORREF)regs[2];
        int ret = ImageList_AddMasked(himl, hbm, crMask);
        LOG(API, "[API] ImageList_AddMasked(himl=%p, hbm=%p, crMask=0x%08X) -> %d\n",
            himl, hbm, crMask, ret);
        regs[0] = ret;
        return true;
    });
    Thunk("ImageList_SetBkColor", 763, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_SetBkColor((HIMAGELIST)UnwrapHandle(regs[0]), (COLORREF)regs[1]);
        return true;
    });
    Thunk("ImageList_GetBkColor", 752, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_GetBkColor((HIMAGELIST)UnwrapHandle(regs[0]));
        return true;
    });
    Thunk("ImageList_Remove", 760, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HIMAGELIST h = (HIMAGELIST)UnwrapHandle(regs[0]);
        LOG(API, "[API] ImageList_Remove(0x%08X -> %p, i=%d)\n", regs[0], h, (int)regs[1]);
        regs[0] = ImageList_Remove(h, (int)regs[1]);
        return true;
    });
    Thunk("ImageList_ReplaceIcon", 762, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ImageList_ReplaceIcon(himl=0x%08X, i=%d, hicon=0x%08X)\n",
            regs[0], (int)regs[1], regs[2]);
        regs[0] = ImageList_ReplaceIcon((HIMAGELIST)UnwrapHandle(regs[0]),
            (int)regs[1], (HICON)(intptr_t)(int32_t)regs[2]);
        LOG(API, "[API]   -> %d\n", (int)regs[0]);
        return true;
    });
    Thunk("ImageList_GetIcon", 754, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)ImageList_GetIcon(
            (HIMAGELIST)UnwrapHandle(regs[0]), (int)regs[1], regs[2]);
        return true;
    });
    Thunk("ImageList_DrawIndirect", 750, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* WinCE IMAGELISTDRAWPARAMS is 56 bytes with 32-bit handles:
           +0 cbSize, +4 himl(32), +8 i, +12 hdcDst(32),
           +16 x, +20 y, +24 cx, +28 cy, +32 xBitmap, +36 yBitmap,
           +40 rgbBk, +44 rgbFg, +48 fStyle, +52 dwRop */
        uint32_t p = regs[0];
        if (!p) { regs[0] = FALSE; return true; }
        IMAGELISTDRAWPARAMS ildp = {};
        ildp.cbSize  = sizeof(IMAGELISTDRAWPARAMS);
        ildp.himl    = (HIMAGELIST)UnwrapHandle(mem.Read32(p + 4));
        ildp.i       = (int)mem.Read32(p + 8);
        /* GDI handles always fit in 32 bits with upper 32 bits zero — zero-extend,
           NOT sign-extend, to avoid corrupting handles with bit 31 set. */
        ildp.hdcDst  = (HDC)(uintptr_t)mem.Read32(p + 12);
        ildp.x       = (int)mem.Read32(p + 16);
        ildp.y       = (int)mem.Read32(p + 20);
        ildp.cx      = (int)mem.Read32(p + 24);
        ildp.cy      = (int)mem.Read32(p + 28);
        ildp.xBitmap = (int)mem.Read32(p + 32);
        ildp.yBitmap = (int)mem.Read32(p + 36);
        ildp.rgbBk   = (COLORREF)mem.Read32(p + 40);
        ildp.rgbFg   = (COLORREF)mem.Read32(p + 44);
        ildp.fStyle  = mem.Read32(p + 48);
        ildp.dwRop   = mem.Read32(p + 52);
        BOOL ret = ImageList_DrawIndirect(&ildp);
        LOG(API, "[API] ImageList_DrawIndirect(himl=%p, i=%d, hdc=%p, x=%d, y=%d, style=0x%X) -> %d\n",
            ildp.himl, ildp.i, ildp.hdcDst, ildp.x, ildp.y, ildp.fStyle, ret);
        regs[0] = ret;
        return true;
    });
    Thunk("ImageList_DragMove", 746, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_DragMove((int)regs[0], (int)regs[1]);
        return true;
    });
    Thunk("ImageList_DragShowNolock", 747, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_DragShowNolock(regs[0]);
        return true;
    });
    Thunk("ImageList_DragEnter", 744, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_DragEnter((HWND)(intptr_t)(int32_t)regs[0], (int)regs[1], (int)regs[2]);
        return true;
    });
    Thunk("ImageList_DragLeave", 745, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_DragLeave((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("ImageList_GetDragImage", 753, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt, ptHotspot;
        HIMAGELIST h = ImageList_GetDragImage(&pt, &ptHotspot);
        if (regs[0]) { mem.Write32(regs[0], pt.x); mem.Write32(regs[0]+4, pt.y); }
        if (regs[1]) { mem.Write32(regs[1], ptHotspot.x); mem.Write32(regs[1]+4, ptHotspot.y); }
        regs[0] = (uint32_t)(uintptr_t)h;
        return true;
    });
    Thunk("ImageList_SetDragCursorImage", 764, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_SetDragCursorImage(
            (HIMAGELIST)UnwrapHandle(regs[0]), (int)regs[1], (int)regs[2], (int)regs[3]);
        return true;
    });
    Thunk("ImageList_SetOverlayImage", 766, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HIMAGELIST h = (HIMAGELIST)UnwrapHandle(regs[0]);
        LOG(API, "[API] ImageList_SetOverlayImage(0x%08X -> %p, iImage=%d, iOverlay=%d)\n",
            regs[0], h, (int)regs[1], (int)regs[2]);
        regs[0] = ImageList_SetOverlayImage(h, (int)regs[1], (int)regs[2]);
        return true;
    });
}
