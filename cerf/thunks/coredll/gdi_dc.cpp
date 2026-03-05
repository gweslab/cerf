#define NOMINMAX
/* GDI thunks: DC management, object selection, device caps */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>
#include <algorithm>

void Win32Thunks::RegisterGdiDcHandlers() {
    Thunk("CreateCompatibleDC", 910, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateCompatibleDC((HDC)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("DeleteDC", 911, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DeleteDC((HDC)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("GetDC", 262, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetDC((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ReleaseDC", 263, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ReleaseDC((HWND)(intptr_t)(int32_t)regs[0], (HDC)(intptr_t)(int32_t)regs[1]); return true;
    });
    Thunk("GetWindowDC", 270, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetWindowDC((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("CreateDCW", 909, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring driver = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)(uintptr_t)CreateDCW(driver.c_str(), NULL, NULL, NULL); return true;
    });
    Thunk("SelectObject", 921, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        HGDIOBJ hobj = (HGDIOBJ)(intptr_t)(int32_t)regs[1];
        HGDIOBJ prev = SelectObject(hdc, hobj);
        LOG(API, "[API] SelectObject(hdc=0x%08X, obj=0x%08X) -> prev=0x%08X\n",
            (uint32_t)(uintptr_t)hdc, (uint32_t)(uintptr_t)hobj, (uint32_t)(uintptr_t)prev);
        regs[0] = (uint32_t)(uintptr_t)prev; return true;
    });
    Thunk("DeleteObject", 912, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DeleteObject((HGDIOBJ)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("GetStockObject", 919, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        /* DEFAULT_GUI_FONT (17) and SYSTEM_FONT (13): WinCE configures these
           via HKLM\System\GDI\SYSFNT registry (typically Tahoma).
           Desktop Windows returns Segoe UI / System bitmap font.
           Override to match the WinCE device's configured font. */
        if (regs[0] == DEFAULT_GUI_FONT || regs[0] == SYSTEM_FONT) {
            static HFONT s_wce_font = NULL;
            if (!s_wce_font) {
                LOGFONTW lf = {};
                lf.lfHeight = wce_sysfont_height;
                lf.lfWeight = wce_sysfont_weight;
                lf.lfCharSet = DEFAULT_CHARSET;
                lf.lfQuality = DEFAULT_QUALITY;
                lf.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
                wcscpy_s(lf.lfFaceName, wce_sysfont_name.c_str());
                s_wce_font = CreateFontIndirectW(&lf);
                LOG(API, "[API] GetStockObject(%d) -> created '%ls' h=%d wt=%d font %p\n",
                    regs[0], wce_sysfont_name.c_str(), wce_sysfont_height, wce_sysfont_weight, s_wce_font);
            }
            if (s_wce_font) {
                regs[0] = (uint32_t)(uintptr_t)s_wce_font;
                return true;
            }
        }
        regs[0] = (uint32_t)(uintptr_t)GetStockObject(regs[0]); return true;
    });
    Thunk("GetDeviceCaps", 916, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int index = (int)regs[1];
        if (index == HORZRES) { regs[0] = WINCE_SCREEN_WIDTH; return true; }
        if (index == VERTRES) { regs[0] = WINCE_SCREEN_HEIGHT; return true; }
        // Return 16 for BITSPIXEL to match typical WinCE 5.0 devices (16bpp).
        // Desktop returns 32 which is unrealistic; apps like cecmd check
        // BITSPIXEL*PLANES >= 15 to choose high-color vs low-color bitmaps.
        // Note: previously returned 2 to force commctrl mono bitmaps, but that
        // broke all apps' bitmap selection (e.g. cecmd loaded bitmap 105 instead of 155).
        if (index == BITSPIXEL) {
            regs[0] = 16;
            return true;
        }
        regs[0] = GetDeviceCaps((HDC)(intptr_t)(int32_t)regs[0], index);
        return true;
    });
    Thunk("SaveDC", 908, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SaveDC((HDC)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("RestoreDC", 907, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = RestoreDC((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true;
    });
    Thunk("GetObjectW", 918, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HGDIOBJ hobj = (HGDIOBJ)(intptr_t)(int32_t)regs[0];
        int cb = (int)regs[1]; uint32_t buf_addr = regs[2];
        if (buf_addr && cb > 0) {
            if (cb == 24) {
                /* 32-bit BITMAP: {bmType, bmWidth, bmHeight, bmWidthBytes, bmPlanes(16), bmBitsPixel(16), bmBits} = 24 bytes */
                BITMAP bm = {}; int ret = GetObjectW(hobj, sizeof(BITMAP), &bm);
                if (ret > 0) {
                    /* Look up emulated pvBits for this HBITMAP */
                    uint32_t emu_bits = 0;
                    auto it = hbitmap_to_emu_pvbits.find((uint32_t)(uintptr_t)hobj);
                    if (it != hbitmap_to_emu_pvbits.end()) emu_bits = it->second;
                    mem.Write32(buf_addr+0, bm.bmType); mem.Write32(buf_addr+4, bm.bmWidth);
                    mem.Write32(buf_addr+8, bm.bmHeight); mem.Write32(buf_addr+12, bm.bmWidthBytes);
                    mem.Write16(buf_addr+16, bm.bmPlanes); mem.Write16(buf_addr+18, bm.bmBitsPixel);
                    mem.Write32(buf_addr+20, emu_bits); regs[0] = 24;
                    LOG(API, "[API] GetObjectW(hbm=0x%08X, BITMAP) -> %dx%d %dbpp bmBits=0x%08X\n",
                        (uint32_t)(uintptr_t)hobj, bm.bmWidth, bm.bmHeight, bm.bmBitsPixel, emu_bits);
                } else regs[0] = 0;
            } else {
                std::vector<uint8_t> buf(std::max(cb, 64), 0);
                int ret = GetObjectW(hobj, (int)buf.size(), buf.data());
                if (ret > 0) mem.WriteBytes(buf_addr, buf.data(), std::min(ret, cb));
                regs[0] = ret;
            }
        } else regs[0] = GetObjectW(hobj, 0, NULL);
        return true;
    });
    Thunk("SetStretchBltMode", 920, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetStretchBltMode((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("GetCurrentObject", 915, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetCurrentObject((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true;
    });
    Thunk("SetROP2", 928, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetROP2((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true;
    });
    Thunk("SetViewportOrgEx", 983, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetViewportOrgEx((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], NULL); return true;
    });
}
