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
        regs[0] = (uint32_t)(uintptr_t)SelectObject((HDC)(intptr_t)(int32_t)regs[0], (HGDIOBJ)(intptr_t)(int32_t)regs[1]); return true;
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
                LOG(THUNK, "[THUNK] GetStockObject(%d) -> created '%ls' h=%d wt=%d font %p\n",
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
        if (index == HORZRES || index == VERTRES) {
            RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
            regs[0] = (index == HORZRES) ? (uint32_t)(wa.right - wa.left) : (uint32_t)(wa.bottom - wa.top);
            return true;
        }
        // Return 2 for BITSPIXEL so ARM commctrl loads WinCE-style mono toolbar
        // bitmaps (stdsm.2bp) instead of XP-style bitmaps (stdsmXP.bmp) which have
        // wrong icons (e.g. "What's This?" cursor instead of simple "?" for STD_HELP)
        if (index == BITSPIXEL) {
            regs[0] = 2;
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
                BITMAP bm = {}; int ret = GetObjectW(hobj, sizeof(BITMAP), &bm);
                if (ret > 0) {
                    mem.Write32(buf_addr+0, bm.bmType); mem.Write32(buf_addr+4, bm.bmWidth);
                    mem.Write32(buf_addr+8, bm.bmHeight); mem.Write32(buf_addr+12, bm.bmWidthBytes);
                    mem.Write16(buf_addr+16, bm.bmPlanes); mem.Write16(buf_addr+18, bm.bmBitsPixel);
                    mem.Write32(buf_addr+20, 0); regs[0] = 24;
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
