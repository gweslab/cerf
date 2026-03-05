/* GDI thunks: regions, clipping, palette, paint */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterGdiRegionHandlers() {
    Thunk("SelectPalette", 954, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SelectPalette((HDC)(intptr_t)(int32_t)regs[0], (HPALETTE)(intptr_t)(int32_t)regs[1], regs[2]); return true;
    });
    Thunk("RealizePalette", 953, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = RealizePalette((HDC)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("CreateRectRgn", 980, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateRectRgn(regs[0], regs[1], regs[2], regs[3]); return true;
    });
    Thunk("CombineRgn", 968, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = CombineRgn((HRGN)(intptr_t)(int32_t)regs[0], (HRGN)(intptr_t)(int32_t)regs[1], (HRGN)(intptr_t)(int32_t)regs[2], regs[3]); return true;
    });
    Thunk("SelectClipRgn", 979, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SelectClipRgn((HDC)(intptr_t)(int32_t)regs[0], (HRGN)(intptr_t)(int32_t)regs[1]); return true;
    });
    Thunk("IntersectClipRect", 975, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = IntersectClipRect((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0)); return true;
    });
    Thunk("GetClipBox", 971, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; int ret = GetClipBox((HDC)(intptr_t)(int32_t)regs[0], &rc);
        mem.Write32(regs[1], rc.left); mem.Write32(regs[1]+4, rc.top);
        mem.Write32(regs[1]+8, rc.right); mem.Write32(regs[1]+12, rc.bottom);
        LOG(API, "[API] GetClipBox(hdc=0x%08X) -> %d, rc={%d,%d,%d,%d}\n",
            regs[0], ret, rc.left, rc.top, rc.right, rc.bottom);
        regs[0] = ret; return true;
    });
    Thunk("GetClipRgn", 972, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetClipRgn((HDC)(intptr_t)(int32_t)regs[0], (HRGN)(intptr_t)(int32_t)regs[1]);
        return true;
    });
    Thunk("SetLayout", 1890, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetLayout((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("GetLayout", 1891, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetLayout((HDC)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("CreateRectRgnIndirect", 969, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc;
        rc.left = (LONG)mem.Read32(regs[0]);
        rc.top = (LONG)mem.Read32(regs[0] + 4);
        rc.right = (LONG)mem.Read32(regs[0] + 8);
        rc.bottom = (LONG)mem.Read32(regs[0] + 12);
        regs[0] = (uint32_t)(uintptr_t)CreateRectRgnIndirect(&rc);
        return true;
    });
    Thunk("EqualRgn", 91, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = EqualRgn((HRGN)(intptr_t)(int32_t)regs[0], (HRGN)(intptr_t)(int32_t)regs[1]);
        return true;
    });
    Thunk("BeginPaint", 260, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hw, &ps);
        uint32_t ps_addr = regs[1];
        mem.Write32(ps_addr+0, (uint32_t)(uintptr_t)hdc); mem.Write32(ps_addr+4, ps.fErase);
        mem.Write32(ps_addr+8, ps.rcPaint.left); mem.Write32(ps_addr+12, ps.rcPaint.top);
        mem.Write32(ps_addr+16, ps.rcPaint.right); mem.Write32(ps_addr+20, ps.rcPaint.bottom);
        LOG(API, "[API] BeginPaint(0x%p) -> hdc=0x%08X, fErase=%d, rcPaint={%d,%d,%d,%d}\n",
            hw, (uint32_t)(uintptr_t)hdc, ps.fErase,
            ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right, ps.rcPaint.bottom);
        regs[0] = (uint32_t)(uintptr_t)hdc; return true;
    });
    Thunk("EndPaint", 261, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        PAINTSTRUCT ps = {}; ps.hdc = (HDC)(intptr_t)(int32_t)mem.Read32(regs[1]);
        EndPaint((HWND)(intptr_t)(int32_t)regs[0], &ps); regs[0] = 1; return true;
    });
    Thunk("ExcludeClipRect", 970, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ExcludeClipRect((HDC)(intptr_t)(int32_t)regs[0],
            (int)regs[1], (int)regs[2], (int)regs[3], (int)ReadStackArg(regs, mem, 0));
        return true;
    });
}
