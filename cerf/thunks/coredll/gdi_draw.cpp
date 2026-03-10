/* GDI thunks: BitBlt, drawing primitives, DIB operations */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "msimg32.lib")

void Win32Thunks::RegisterGdiDrawHandlers() {
    Thunk("BitBlt", 903, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC dst = (HDC)(intptr_t)(int32_t)regs[0];
        int x = (int)regs[1], y = (int)regs[2], w = (int)regs[3];
        int h = (int)ReadStackArg(regs, mem, 0);
        HDC src_dc = (HDC)(intptr_t)(int32_t)ReadStackArg(regs, mem, 1);
        int sx = (int)ReadStackArg(regs,mem,2), sy = (int)ReadStackArg(regs,mem,3);
        DWORD rop = ReadStackArg(regs,mem,4);
        GdiFlush();  /* Ensure ARM pvBits writes are visible to native GDI */
        BOOL ret = BitBlt(dst, x, y, w, h, src_dc, sx, sy, rop);
        LOG(API, "[API] BitBlt(dst=0x%p, %d,%d,%dx%d, src=0x%p, %d,%d, rop=0x%08X) -> %d\n",
            dst, x, y, w, h, src_dc, sx, sy, rop, ret);
        regs[0] = ret;
        return true;
    });
    Thunk("PatBlt", 938, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = PatBlt((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0), ReadStackArg(regs,mem,1));
        return true;
    });
    Thunk("SetBkColor", 922, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetBkColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("GetBkColor", 913, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetBkColor((HDC)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("SetBkMode", 923, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SetBkMode(hdc=0x%08X, mode=%d [%s])\n", regs[0], regs[1], regs[1]==1?"TRANSPARENT":"OPAQUE");
        regs[0] = SetBkMode((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true;
    });
    Thunk("SetTextColor", 924, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetTextColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("GetTextColor", 914, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetTextColor((HDC)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("SetBrushOrgEx", 943, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt;
        BOOL ret = SetBrushOrgEx((HDC)(intptr_t)(int32_t)regs[0], (int)regs[1], (int)regs[2], regs[3] ? &pt : NULL);
        if (regs[3] && ret) { mem.Write32(regs[3], pt.x); mem.Write32(regs[3] + 4, pt.y); }
        regs[0] = ret; return true;
    });
    Thunk("CreateCompatibleBitmap", 902, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Create as DIB section instead of DDB so ARM code can directly access pixel data.
           ARM apps may memcpy pixels between DIB sections and "compatible" bitmaps,
           which only works if all bitmaps have pvBits in emulated memory. */
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        int w = (int)regs[1], h = (int)regs[2];
        if (w <= 0 || h <= 0) { regs[0] = 0; return true; }
        /* Use native desktop bpp so bitmaps match the screen DC format.
           ARM code gets the same bpp from GetDeviceCaps(BITSPIXEL). */
        int bpp = GetDeviceCaps(hdc ? hdc : GetDC(NULL), BITSPIXEL);
        BITMAPINFOHEADER bih = {};
        bih.biSize = sizeof(bih);
        bih.biWidth = w;
        bih.biHeight = -h; /* top-down for direct memory access */
        bih.biPlanes = 1;
        bih.biBitCount = (WORD)bpp;
        bih.biCompression = BI_RGB;
        void* pvBits = nullptr;
        HBITMAP hbm = CreateDIBSection(hdc, (BITMAPINFO*)&bih, DIB_RGB_COLORS, &pvBits, NULL, 0);
        if (hbm && pvBits) {
            uint32_t stride = ((w * bpp + 31) / 32) * 4;
            uint32_t data_size = stride * h;
            uint32_t emu_addr = next_dib_addr;
            next_dib_addr += (data_size + 0xFFF) & ~0xFFF;
            mem.AddExternalRegion(emu_addr, data_size, (uint8_t*)pvBits);
            hbitmap_to_emu_pvbits[(uint32_t)(uintptr_t)hbm] = emu_addr;
            LOG(API, "[API] CreateCompatibleBitmap(%dx%d, %dbpp) -> hbm=0x%08X pvBits=emu:0x%08X (%u bytes)\n",
                w, h, bpp, (uint32_t)(uintptr_t)hbm, emu_addr, data_size);
        } else {
            LOG(API, "[API] CreateCompatibleBitmap(%dx%d) -> 0x%08X (FAILED)\n", w, h, (uint32_t)(uintptr_t)hbm);
        }
        regs[0] = (uint32_t)(uintptr_t)hbm;
        return true;
    });
    Thunk("CreateBitmap", 901, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int w = (int)regs[0], h = (int)regs[1];
        UINT planes = regs[2], bpp = regs[3];
        HBITMAP hbm;
        /* Safety net: if ARM code requests a bpp that doesn't match the screen
           (e.g. from a hardcoded value), use CreateCompatibleBitmap to avoid
           SelectObject failures when selecting into a screen-compatible DC. */
        if (planes == 1 && bpp >= 8 && bpp != (UINT)GetDeviceCaps(GetDC(NULL), BITSPIXEL)) {
            HDC screenDC = GetDC(NULL);
            hbm = CreateCompatibleBitmap(screenDC, w, h);
            ReleaseDC(NULL, screenDC);
        } else {
            hbm = CreateBitmap(w, h, planes, bpp, NULL);
        }
        LOG(API, "[API] CreateBitmap(%d, %d, planes=%d, bpp=%d) -> 0x%08X%s\n",
            w, h, planes, bpp, (uint32_t)(uintptr_t)hbm, hbm ? "" : " (FAILED)");
        regs[0] = (uint32_t)(uintptr_t)hbm;
        return true;
    });
    Thunk("GetPixel", 936, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetPixel((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true; });
    Thunk("SetPixel", 944, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetPixel((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]); return true; });
    Thunk("Rectangle", 941, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = Rectangle((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0)); return true;
    });
    Thunk("FillRect", 935, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc={mem.Read32(regs[1]),mem.Read32(regs[1]+4),mem.Read32(regs[1]+8),mem.Read32(regs[1]+12)};
        regs[0] = FillRect((HDC)(intptr_t)(int32_t)regs[0], &rc, (HBRUSH)(intptr_t)(int32_t)regs[2]); return true;
    });
    Thunk("DrawFocusRect", 933, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc={mem.Read32(regs[1]),mem.Read32(regs[1]+4),mem.Read32(regs[1]+8),mem.Read32(regs[1]+12)};
        regs[0] = DrawFocusRect((HDC)(intptr_t)(int32_t)regs[0], &rc); return true;
    });
    Thunk("GetNearestColor", 952, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetNearestColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("LineTo", 1652, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = LineTo((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true; });
    Thunk("MoveToEx", 1651, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = MoveToEx((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], NULL); return true; });
    Thunk("SetViewportOrgEx", 983, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetViewportOrgEx((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], NULL); return true; });
    Thunk("StretchBlt", 905, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC dst = (HDC)(intptr_t)(int32_t)regs[0];
        int xD=(int)regs[1], yD=(int)regs[2], wD=(int)regs[3];
        int hD=(int)ReadStackArg(regs,mem,0);
        HDC src = (HDC)(intptr_t)(int32_t)ReadStackArg(regs,mem,1);
        int xS=(int)ReadStackArg(regs,mem,2), yS=(int)ReadStackArg(regs,mem,3);
        int wS=(int)ReadStackArg(regs,mem,4), hS=(int)ReadStackArg(regs,mem,5);
        DWORD rop = ReadStackArg(regs,mem,6);
        GdiFlush();
        BOOL ret = StretchBlt(dst, xD, yD, wD, hD, src, xS, yS, wS, hS, rop);
        LOG(API, "[API] StretchBlt(dst=0x%p, %d,%d,%dx%d, src=0x%p, %d,%d,%dx%d, rop=0x%08X) -> %d\n",
            dst, xD, yD, wD, hD, src, xS, yS, wS, hS, rop, ret);
        regs[0] = ret;
        return true;
    });
    /* MaskBlt(hdcDest, xDest, yDest, width, height, hdcSrc, xSrc, ySrc, hbmMask, xMask, yMask, rop) */
    Thunk("MaskBlt", 904, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdcDest = (HDC)(intptr_t)(int32_t)regs[0];
        int xDest = (int)regs[1], yDest = (int)regs[2], w = (int)regs[3];
        int h = (int)ReadStackArg(regs, mem, 0);
        HDC hdcSrc = (HDC)(intptr_t)(int32_t)ReadStackArg(regs, mem, 1);
        int xSrc = (int)ReadStackArg(regs, mem, 2), ySrc = (int)ReadStackArg(regs, mem, 3);
        HBITMAP hbmMask = (HBITMAP)(intptr_t)(int32_t)ReadStackArg(regs, mem, 4);
        int xMask = (int)ReadStackArg(regs, mem, 5), yMask = (int)ReadStackArg(regs, mem, 6);
        DWORD rop = ReadStackArg(regs, mem, 7);
        BOOL ret = MaskBlt(hdcDest, xDest, yDest, w, h, hdcSrc, xSrc, ySrc, hbmMask, xMask, yMask, rop);
        LOG(API, "[API] MaskBlt(dst=0x%p %d,%d %dx%d src=0x%p %d,%d mask=0x%p rop=0x%08X) -> %d\n",
            hdcDest, xDest, yDest, w, h, hdcSrc, xSrc, ySrc, hbmMask, rop, ret);
        regs[0] = ret;
        return true;
    });
    Thunk("CreateDIBSection", 90, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0]; uint32_t bmi_addr = regs[1];
        BITMAPINFOHEADER bih; bih.biSize = mem.Read32(bmi_addr);
        bih.biWidth = (LONG)mem.Read32(bmi_addr+4); bih.biHeight = (LONG)mem.Read32(bmi_addr+8);
        bih.biPlanes = mem.Read16(bmi_addr+12); bih.biBitCount = mem.Read16(bmi_addr+14);
        bih.biCompression = mem.Read32(bmi_addr+16); bih.biSizeImage = mem.Read32(bmi_addr+20);
        bih.biXPelsPerMeter = (LONG)mem.Read32(bmi_addr+24); bih.biYPelsPerMeter = (LONG)mem.Read32(bmi_addr+28);
        bih.biClrUsed = mem.Read32(bmi_addr+32); bih.biClrImportant = mem.Read32(bmi_addr+36);
        int nColors = (bih.biBitCount <= 8) ? ((bih.biClrUsed > 0) ? bih.biClrUsed : (1 << bih.biBitCount)) : 0;
        /* BI_BITFIELDS (3): 3 DWORD color masks follow the header (e.g. RGB565 for 16bpp) */
        if (bih.biCompression == BI_BITFIELDS && nColors < 3) nColors = 3;
        std::vector<uint8_t> bmi_buf(sizeof(BITMAPINFOHEADER) + nColors * sizeof(RGBQUAD), 0);
        memcpy(bmi_buf.data(), &bih, sizeof(bih));
        for (int i = 0; i < nColors; i++) { uint32_t clr = mem.Read32(bmi_addr+40+i*4); memcpy(bmi_buf.data()+sizeof(BITMAPINFOHEADER)+i*4, &clr, 4); }
        void* pvBits = nullptr;
        HBITMAP hbm = CreateDIBSection(hdc, (BITMAPINFO*)bmi_buf.data(), regs[2], &pvBits, NULL, 0);
        uint32_t ppvBits_addr = regs[3];
        if (ppvBits_addr && pvBits && hbm) {
            /* Map native pvBits into emulated address space so ARM code can write pixels */
            int absH = bih.biHeight < 0 ? -bih.biHeight : bih.biHeight;
            uint32_t stride = ((bih.biWidth * bih.biBitCount + 31) / 32) * 4;
            uint32_t data_size = stride * absH;
            uint32_t emu_addr = next_dib_addr;
            next_dib_addr += (data_size + 0xFFF) & ~0xFFF; /* page-align */
            mem.AddExternalRegion(emu_addr, data_size, (uint8_t*)pvBits);
            mem.Write32(ppvBits_addr, emu_addr);
            hbitmap_to_emu_pvbits[(uint32_t)(uintptr_t)hbm] = emu_addr;
            LOG(API, "[API] CreateDIBSection(%dx%d, %dbpp, biH=%d) -> hbm=0x%08X pvBits=emu:0x%08X (%u bytes)\n",
                bih.biWidth, absH, bih.biBitCount, bih.biHeight, (uint32_t)(uintptr_t)hbm, emu_addr, data_size);
        } else {
            if (ppvBits_addr) mem.Write32(ppvBits_addr, 0);
            LOG(API, "[API] CreateDIBSection(%dx%d, %dbpp) -> 0x%08X (pvBits=NULL)\n",
                bih.biWidth, bih.biHeight, bih.biBitCount, (uint32_t)(uintptr_t)hbm);
        }
        regs[0] = (uint32_t)(uintptr_t)hbm;
        return true;
    });
    Thunk("StretchDIBits", 1667, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        int xD=(int)regs[1],yD=(int)regs[2],wD=(int)regs[3],hD=(int)ReadStackArg(regs,mem,0);
        int xS=(int)ReadStackArg(regs,mem,1),yS=(int)ReadStackArg(regs,mem,2),wS=(int)ReadStackArg(regs,mem,3),hS=(int)ReadStackArg(regs,mem,4);
        uint32_t bits_addr=ReadStackArg(regs,mem,5), bmi_addr=ReadStackArg(regs,mem,6);
        UINT usage=ReadStackArg(regs,mem,7); DWORD rop=ReadStackArg(regs,mem,8);
        BITMAPINFOHEADER bih; bih.biSize=mem.Read32(bmi_addr); bih.biWidth=(LONG)mem.Read32(bmi_addr+4);
        bih.biHeight=(LONG)mem.Read32(bmi_addr+8); bih.biPlanes=mem.Read16(bmi_addr+12);
        bih.biBitCount=mem.Read16(bmi_addr+14); bih.biCompression=mem.Read32(bmi_addr+16);
        bih.biSizeImage=mem.Read32(bmi_addr+20); bih.biXPelsPerMeter=(LONG)mem.Read32(bmi_addr+24);
        bih.biYPelsPerMeter=(LONG)mem.Read32(bmi_addr+28); bih.biClrUsed=mem.Read32(bmi_addr+32);
        bih.biClrImportant=mem.Read32(bmi_addr+36);
        int nC=(bih.biBitCount<=8)?((bih.biClrUsed>0)?bih.biClrUsed:(1<<bih.biBitCount)):0;
        if (bih.biCompression == BI_BITFIELDS && nC < 3) nC = 3;
        std::vector<uint8_t> bmi_buf(sizeof(BITMAPINFOHEADER)+nC*sizeof(RGBQUAD),0);
        memcpy(bmi_buf.data(),&bih,sizeof(bih));
        for(int i=0;i<nC;i++){uint32_t c=mem.Read32(bmi_addr+40+i*4);memcpy(bmi_buf.data()+sizeof(BITMAPINFOHEADER)+i*4,&c,4);}
        regs[0]=StretchDIBits(hdc,xD,yD,wD,hD,xS,yS,wS,hS,mem.Translate(bits_addr),(BITMAPINFO*)bmi_buf.data(),usage,rop);
        return true;
    });
    Thunk("SetDIBitsToDevice", 1726, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc=(HDC)(intptr_t)(int32_t)regs[0]; int xD=(int)regs[1],yD=(int)regs[2],w=(int)regs[3];
        int h=(int)ReadStackArg(regs,mem,0),xS=(int)ReadStackArg(regs,mem,1),yS=(int)ReadStackArg(regs,mem,2);
        uint32_t startScan=ReadStackArg(regs,mem,3),numScans=ReadStackArg(regs,mem,4);
        uint32_t bits_addr=ReadStackArg(regs,mem,5),bmi_addr=ReadStackArg(regs,mem,6),usage=ReadStackArg(regs,mem,7);
        BITMAPINFOHEADER bih={}; bih.biSize=mem.Read32(bmi_addr);
        bih.biWidth=(int32_t)mem.Read32(bmi_addr+4); bih.biHeight=(int32_t)mem.Read32(bmi_addr+8);
        bih.biPlanes=mem.Read16(bmi_addr+12); bih.biBitCount=mem.Read16(bmi_addr+14);
        bih.biCompression=mem.Read32(bmi_addr+16); bih.biSizeImage=mem.Read32(bmi_addr+20);
        bih.biClrUsed=mem.Read32(bmi_addr+32);
        int nC=bih.biClrUsed; if(nC==0&&bih.biBitCount<=8) nC=1<<bih.biBitCount;
        if (bih.biCompression == BI_BITFIELDS && nC < 3) nC = 3;
        std::vector<uint8_t> bmi_buf(sizeof(BITMAPINFOHEADER)+nC*4);
        memcpy(bmi_buf.data(),&bih,sizeof(bih));
        for(int i=0;i<nC;i++){uint32_t c=mem.Read32(bmi_addr+40+i*4);memcpy(bmi_buf.data()+sizeof(BITMAPINFOHEADER)+i*4,&c,4);}
        regs[0]=SetDIBitsToDevice(hdc,xD,yD,w,h,xS,yS,startScan,numScans,mem.Translate(bits_addr),(BITMAPINFO*)bmi_buf.data(),usage);
        return true;
    });
    Thunk("TransparentImage", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0]=TransparentBlt((HDC)(intptr_t)(int32_t)regs[0],(int)regs[1],(int)regs[2],(int)regs[3],
            (int)ReadStackArg(regs,mem,0),(HDC)(intptr_t)(int32_t)ReadStackArg(regs,mem,1),
            (int)ReadStackArg(regs,mem,2),(int)ReadStackArg(regs,mem,3),
            (int)ReadStackArg(regs,mem,4),(int)ReadStackArg(regs,mem,5),ReadStackArg(regs,mem,6));
        return true;
    });
    Thunk("TransparentBlt", 906, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdcDest = (HDC)(intptr_t)(int32_t)regs[0];
        int xD=(int)regs[1], yD=(int)regs[2], wD=(int)regs[3], hD=(int)ReadStackArg(regs,mem,0);
        HDC hdcSrc = (HDC)(intptr_t)(int32_t)ReadStackArg(regs,mem,1);
        int xS=(int)ReadStackArg(regs,mem,2), yS=(int)ReadStackArg(regs,mem,3);
        int wS=(int)ReadStackArg(regs,mem,4), hS=(int)ReadStackArg(regs,mem,5);
        UINT crTrans = ReadStackArg(regs,mem,6);
        GdiFlush();
        regs[0] = TransparentBlt(hdcDest, xD, yD, wD, hD, hdcSrc, xS, yS, wS, hS, crTrans);
        return true;
    });
    Thunk("InvertRect", 1770, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[1]); rc.top=mem.Read32(regs[1]+4);
        rc.right=mem.Read32(regs[1]+8); rc.bottom=mem.Read32(regs[1]+12);
        regs[0]=InvertRect((HDC)(intptr_t)(int32_t)regs[0],&rc); return true;
    });
    Thunk("GradientFill", 1763, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        uint32_t vertex_addr = regs[1];
        ULONG nVertex = regs[2];
        uint32_t mesh_addr = regs[3];
        ULONG nMesh = ReadStackArg(regs, mem, 0);
        ULONG ulMode = ReadStackArg(regs, mem, 1);
        /* TRIVERTEX/GRADIENT_RECT/GRADIENT_TRIANGLE are POD, same layout 32/64-bit */
        uint8_t* pVertex = mem.Translate(vertex_addr);
        uint8_t* pMesh = mem.Translate(mesh_addr);
        if (!pVertex || !pMesh) { regs[0] = 0; return true; }
        regs[0] = GradientFill(hdc, (TRIVERTEX*)pVertex, nVertex, pMesh, nMesh, ulMode);
        return true;
    });
    Thunk("Polygon", 939, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=1; return true; });
    Thunk("Polyline", 940, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=1; return true; });
    Thunk("CreatePen", 926, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreatePen(regs[0], regs[1], regs[2]); return true;
    });
    Thunk("CreatePenIndirect", 930, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* LOGPEN: { UINT lopnStyle; POINT lopnWidth; COLORREF lopnColor; } = 16 bytes */
        LOGPEN lp;
        lp.lopnStyle = mem.Read32(regs[0]);
        lp.lopnWidth.x = (LONG)mem.Read32(regs[0] + 4);
        lp.lopnWidth.y = (LONG)mem.Read32(regs[0] + 8);
        lp.lopnColor = mem.Read32(regs[0] + 12);
        regs[0] = (uint32_t)(uintptr_t)CreatePenIndirect(&lp);
        return true;
    });
    Thunk("CreateSolidBrush", 931, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateSolidBrush(regs[0]); return true;
    });
    Thunk("CreateDIBPatternBrushPt", 929, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* lpPackedDIB points to a BITMAPINFO + bits in emulated memory.
           Copy it to host memory and create the brush natively. */
        uint32_t dib_addr = regs[0], usage = regs[1];
        uint8_t* host = mem.Translate(dib_addr);
        if (host) {
            regs[0] = (uint32_t)(uintptr_t)CreateDIBPatternBrushPt(host, usage);
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("DrawEdge", 932, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc={mem.Read32(regs[1]),mem.Read32(regs[1]+4),mem.Read32(regs[1]+8),mem.Read32(regs[1]+12)};
        regs[0] = DrawEdge((HDC)(intptr_t)(int32_t)regs[0], &rc, regs[2], regs[3]);
        /* Write back modified rect when BF_ADJUST (0x2000) is set */
        if (regs[3]&0x2000) { mem.Write32(regs[1],rc.left); mem.Write32(regs[1]+4,rc.top); mem.Write32(regs[1]+8,rc.right); mem.Write32(regs[1]+12,rc.bottom); }
        return true;
    });
    Thunk("DrawFrameControl", 987, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc={(LONG)mem.Read32(regs[1]),(LONG)mem.Read32(regs[1]+4),(LONG)mem.Read32(regs[1]+8),(LONG)mem.Read32(regs[1]+12)};
        regs[0] = DrawFrameControl((HDC)(intptr_t)(int32_t)regs[0], &rc, regs[2], regs[3]);
        return true;
    });
}
