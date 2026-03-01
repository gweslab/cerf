/* GDI thunks: BitBlt, drawing primitives, DIB operations */
#define NOMINMAX
#include "win32_thunks.h"
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
        regs[0] = BitBlt(dst, x, y, w, h, src_dc, (int)ReadStackArg(regs,mem,2), (int)ReadStackArg(regs,mem,3), ReadStackArg(regs,mem,4));
        return true;
    });
    Thunk("PatBlt", 938, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = PatBlt((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0), ReadStackArg(regs,mem,1));
        return true;
    });
    Thunk("SetBkColor", 922, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetBkColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("SetBkMode", 923, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetBkMode((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("SetTextColor", 924, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetTextColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("CreateCompatibleBitmap", 902, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateCompatibleBitmap((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true;
    });
    Thunk("CreateBitmap", 901, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateBitmap(regs[0], regs[1], regs[2], regs[3], NULL); return true;
    });
    Thunk("GetPixel", 936, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetPixel((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true; });
    Thunk("SetPixel", 944, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetPixel((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]); return true; });
    Thunk("Rectangle", 941, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = Rectangle((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs,mem,0)); return true;
    });
    Thunk("FillRect", 935, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left = mem.Read32(regs[1]); rc.top = mem.Read32(regs[1]+4);
        rc.right = mem.Read32(regs[1]+8); rc.bottom = mem.Read32(regs[1]+12);
        regs[0] = FillRect((HDC)(intptr_t)(int32_t)regs[0], &rc, (HBRUSH)(intptr_t)(int32_t)regs[2]); return true;
    });
    Thunk("DrawFocusRect", 933, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left = mem.Read32(regs[1]); rc.top = mem.Read32(regs[1]+4);
        rc.right = mem.Read32(regs[1]+8); rc.bottom = mem.Read32(regs[1]+12);
        regs[0] = DrawFocusRect((HDC)(intptr_t)(int32_t)regs[0], &rc); return true;
    });
    Thunk("GetNearestColor", 952, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetNearestColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("LineTo", 1652, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = LineTo((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]); return true; });
    Thunk("MoveToEx", 1651, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = MoveToEx((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], NULL); return true; });
    Thunk("SetViewportOrgEx", 983, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetViewportOrgEx((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], NULL); return true; });
    Thunk("StretchBlt", 905, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = StretchBlt((HDC)(intptr_t)(int32_t)regs[0], (int)regs[1], (int)regs[2], (int)regs[3],
            (int)ReadStackArg(regs,mem,0), (HDC)(intptr_t)(int32_t)ReadStackArg(regs,mem,1),
            (int)ReadStackArg(regs,mem,2), (int)ReadStackArg(regs,mem,3),
            (int)ReadStackArg(regs,mem,4), (int)ReadStackArg(regs,mem,5), ReadStackArg(regs,mem,6));
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
        std::vector<uint8_t> bmi_buf(sizeof(BITMAPINFOHEADER) + nColors * sizeof(RGBQUAD), 0);
        memcpy(bmi_buf.data(), &bih, sizeof(bih));
        for (int i = 0; i < nColors; i++) { uint32_t clr = mem.Read32(bmi_addr+40+i*4); memcpy(bmi_buf.data()+sizeof(BITMAPINFOHEADER)+i*4, &clr, 4); }
        void* pvBits = nullptr;
        HBITMAP hbm = CreateDIBSection(hdc, (BITMAPINFO*)bmi_buf.data(), regs[2], &pvBits, NULL, 0);
        if (regs[3]) mem.Write32(regs[3], 0);
        regs[0] = (uint32_t)(uintptr_t)hbm;
        printf("[THUNK] CreateDIBSection(%dx%d, %dbpp) -> 0x%08X\n", bih.biWidth, bih.biHeight, bih.biBitCount, regs[0]);
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
    ThunkOrdinal("TransparentBlt", 906);
    Thunk("InvertRect", 1770, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[1]); rc.top=mem.Read32(regs[1]+4);
        rc.right=mem.Read32(regs[1]+8); rc.bottom=mem.Read32(regs[1]+12);
        regs[0]=InvertRect((HDC)(intptr_t)(int32_t)regs[0],&rc); return true;
    });
    Thunk("GradientFill", 1763, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=1; return true; });
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
}
