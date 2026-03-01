/* Win32 thunks: GDI drawing and device context functions */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include <cstdio>
#include <algorithm>
#include <vector>

#pragma comment(lib, "msimg32.lib")

bool Win32Thunks::ExecuteGdiThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem) {
    if (func == "CreateCompatibleDC") {
        regs[0] = (uint32_t)(uintptr_t)CreateCompatibleDC((HDC)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "DeleteDC") {
        regs[0] = DeleteDC((HDC)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetDC") {
        regs[0] = (uint32_t)(uintptr_t)GetDC((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "ReleaseDC") {
        regs[0] = ReleaseDC((HWND)(intptr_t)(int32_t)regs[0], (HDC)(intptr_t)(int32_t)regs[1]);
        return true;
    }
    if (func == "GetWindowDC") {
        regs[0] = (uint32_t)(uintptr_t)GetWindowDC((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "CreateDCW") {
        std::wstring driver = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)(uintptr_t)CreateDCW(driver.c_str(), NULL, NULL, NULL);
        return true;
    }
    if (func == "GetObjectW") {
        HGDIOBJ hobj = (HGDIOBJ)(intptr_t)(int32_t)regs[0];
        int cb = (int)regs[1];
        uint32_t buf_addr = regs[2];
        if (buf_addr && cb > 0) {
            if (cb == 24) {
                /* Likely requesting BITMAP struct (32-bit size=24) */
                BITMAP bm = {};
                int ret = GetObjectW(hobj, sizeof(BITMAP), &bm);
                if (ret > 0) {
                    mem.Write32(buf_addr + 0,  bm.bmType);
                    mem.Write32(buf_addr + 4,  bm.bmWidth);
                    mem.Write32(buf_addr + 8,  bm.bmHeight);
                    mem.Write32(buf_addr + 12, bm.bmWidthBytes);
                    mem.Write16(buf_addr + 16, bm.bmPlanes);
                    mem.Write16(buf_addr + 18, bm.bmBitsPixel);
                    mem.Write32(buf_addr + 20, 0); /* bmBits - NULL for ARM */
                    regs[0] = 24;
                } else {
                    regs[0] = 0;
                }
                printf("[THUNK] GetObjectW(%p, %d) -> %d (%dx%d %dbpp)\n",
                       hobj, cb, (int)regs[0], bm.bmWidth, bm.bmHeight, bm.bmBitsPixel);
            } else {
                std::vector<uint8_t> buf(std::max(cb, 64), 0);
                int ret = GetObjectW(hobj, (int)buf.size(), buf.data());
                if (ret > 0) {
                    int copy_size = std::min(ret, cb);
                    mem.WriteBytes(buf_addr, buf.data(), copy_size);
                }
                regs[0] = ret;
                printf("[THUNK] GetObjectW(%p, %d) -> %d\n", hobj, cb, ret);
            }
        } else {
            regs[0] = GetObjectW(hobj, 0, NULL);
        }
        return true;
    }
    if (func == "SelectObject") {
        regs[0] = (uint32_t)(uintptr_t)SelectObject((HDC)(intptr_t)(int32_t)regs[0], (HGDIOBJ)(intptr_t)(int32_t)regs[1]);
        return true;
    }
    if (func == "DeleteObject") {
        regs[0] = DeleteObject((HGDIOBJ)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "GetStockObject") {
        regs[0] = (uint32_t)(uintptr_t)GetStockObject(regs[0]);
        return true;
    }
    if (func == "CreateSolidBrush") {
        regs[0] = (uint32_t)(uintptr_t)CreateSolidBrush(regs[0]);
        return true;
    }
    if (func == "CreatePen") {
        regs[0] = (uint32_t)(uintptr_t)CreatePen(regs[0], regs[1], regs[2]);
        return true;
    }
    if (func == "BitBlt") {
        HDC dst = (HDC)(intptr_t)(int32_t)regs[0];
        int x = (int)regs[1], y = (int)regs[2], w = (int)regs[3];
        int h = (int)ReadStackArg(regs, mem, 0);
        HDC src_dc = (HDC)(intptr_t)(int32_t)ReadStackArg(regs, mem, 1);
        int sx = (int)ReadStackArg(regs, mem, 2);
        int sy = (int)ReadStackArg(regs, mem, 3);
        DWORD rop = ReadStackArg(regs, mem, 4);
        regs[0] = BitBlt(dst, x, y, w, h, src_dc, sx, sy, rop);
        return true;
    }
    if (func == "PatBlt") {
        regs[0] = PatBlt((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3],
                         ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    }
    if (func == "SetBkColor") {
        regs[0] = SetBkColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "SetBkMode") {
        regs[0] = SetBkMode((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "SetTextColor") {
        regs[0] = SetTextColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "GetDeviceCaps") {
        int index = (int)regs[1];
        if (index == HORZRES || index == VERTRES) {
            RECT work_area;
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0);
            regs[0] = (index == HORZRES)
                ? (uint32_t)(work_area.right - work_area.left)
                : (uint32_t)(work_area.bottom - work_area.top);
            return true;
        }
        regs[0] = GetDeviceCaps((HDC)(intptr_t)(int32_t)regs[0], index);
        return true;
    }
    if (func == "CreateCompatibleBitmap") {
        regs[0] = (uint32_t)(uintptr_t)CreateCompatibleBitmap((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]);
        return true;
    }
    if (func == "CreateBitmap") {
        regs[0] = (uint32_t)(uintptr_t)CreateBitmap(regs[0], regs[1], regs[2], regs[3], NULL);
        return true;
    }
    if (func == "GetPixel") {
        regs[0] = GetPixel((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]);
        return true;
    }
    if (func == "SetPixel") {
        regs[0] = SetPixel((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    }
    if (func == "Rectangle") {
        regs[0] = Rectangle((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3],
                            ReadStackArg(regs, mem, 0));
        return true;
    }
    if (func == "FillRect") {
        RECT rc;
        rc.left = mem.Read32(regs[1]);
        rc.top = mem.Read32(regs[1] + 4);
        rc.right = mem.Read32(regs[1] + 8);
        rc.bottom = mem.Read32(regs[1] + 12);
        regs[0] = FillRect((HDC)(intptr_t)(int32_t)regs[0], &rc, (HBRUSH)(intptr_t)(int32_t)regs[2]);
        return true;
    }
    if (func == "DrawFocusRect") {
        RECT rc;
        rc.left = mem.Read32(regs[1]);
        rc.top = mem.Read32(regs[1] + 4);
        rc.right = mem.Read32(regs[1] + 8);
        rc.bottom = mem.Read32(regs[1] + 12);
        regs[0] = DrawFocusRect((HDC)(intptr_t)(int32_t)regs[0], &rc);
        return true;
    }
    if (func == "SaveDC") {
        regs[0] = SaveDC((HDC)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "RestoreDC") {
        regs[0] = RestoreDC((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "GetNearestColor") {
        regs[0] = GetNearestColor((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "SelectPalette") {
        regs[0] = (uint32_t)(uintptr_t)SelectPalette((HDC)(intptr_t)(int32_t)regs[0], (HPALETTE)(intptr_t)(int32_t)regs[1], regs[2]);
        return true;
    }
    if (func == "RealizePalette") {
        regs[0] = RealizePalette((HDC)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "CreateRectRgn") {
        regs[0] = (uint32_t)(uintptr_t)CreateRectRgn(regs[0], regs[1], regs[2], regs[3]);
        return true;
    }
    if (func == "CombineRgn") {
        regs[0] = CombineRgn((HRGN)(intptr_t)(int32_t)regs[0], (HRGN)(intptr_t)(int32_t)regs[1],
                             (HRGN)(intptr_t)(int32_t)regs[2], regs[3]);
        return true;
    }
    if (func == "SelectClipRgn") {
        regs[0] = SelectClipRgn((HDC)(intptr_t)(int32_t)regs[0], (HRGN)(intptr_t)(int32_t)regs[1]);
        return true;
    }
    if (func == "IntersectClipRect") {
        regs[0] = IntersectClipRect((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3],
                                    ReadStackArg(regs, mem, 0));
        return true;
    }
    if (func == "LineTo") {
        regs[0] = LineTo((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2]);
        return true;
    }
    if (func == "MoveToEx") {
        regs[0] = MoveToEx((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], NULL);
        return true;
    }
    if (func == "SetTextAlign") {
        regs[0] = SetTextAlign((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "GetTextAlign") {
        regs[0] = GetTextAlign((HDC)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "SetViewportOrgEx") {
        regs[0] = SetViewportOrgEx((HDC)(intptr_t)(int32_t)regs[0], regs[1], regs[2], NULL);
        return true;
    }
    if (func == "StretchBlt") {
        HDC hdcDest = (HDC)(intptr_t)(int32_t)regs[0];
        int xDest = (int)regs[1], yDest = (int)regs[2];
        int wDest = (int)regs[3];
        int hDest = (int)ReadStackArg(regs, mem, 0);
        HDC hdcSrc = (HDC)(intptr_t)(int32_t)ReadStackArg(regs, mem, 1);
        int xSrc = (int)ReadStackArg(regs, mem, 2);
        int ySrc = (int)ReadStackArg(regs, mem, 3);
        int wSrc = (int)ReadStackArg(regs, mem, 4);
        int hSrc = (int)ReadStackArg(regs, mem, 5);
        DWORD rop = ReadStackArg(regs, mem, 6);
        regs[0] = StretchBlt(hdcDest, xDest, yDest, wDest, hDest, hdcSrc, xSrc, ySrc, wSrc, hSrc, rop);
        return true;
    }
    if (func == "SetStretchBltMode") {
        regs[0] = SetStretchBltMode((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "CreateDIBSection") {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        uint32_t bmi_addr = regs[1];
        UINT usage = regs[2];
        uint32_t ppvBits_addr = regs[3];
        BITMAPINFOHEADER bih;
        bih.biSize = mem.Read32(bmi_addr);
        bih.biWidth = (LONG)mem.Read32(bmi_addr + 4);
        bih.biHeight = (LONG)mem.Read32(bmi_addr + 8);
        bih.biPlanes = mem.Read16(bmi_addr + 12);
        bih.biBitCount = mem.Read16(bmi_addr + 14);
        bih.biCompression = mem.Read32(bmi_addr + 16);
        bih.biSizeImage = mem.Read32(bmi_addr + 20);
        bih.biXPelsPerMeter = (LONG)mem.Read32(bmi_addr + 24);
        bih.biYPelsPerMeter = (LONG)mem.Read32(bmi_addr + 28);
        bih.biClrUsed = mem.Read32(bmi_addr + 32);
        bih.biClrImportant = mem.Read32(bmi_addr + 36);
        int nColors = 0;
        if (bih.biBitCount <= 8) nColors = (bih.biClrUsed > 0) ? bih.biClrUsed : (1 << bih.biBitCount);
        size_t bmi_size = sizeof(BITMAPINFOHEADER) + nColors * sizeof(RGBQUAD);
        std::vector<uint8_t> bmi_buf(bmi_size, 0);
        memcpy(bmi_buf.data(), &bih, sizeof(bih));
        for (int i = 0; i < nColors; i++) {
            uint32_t clr = mem.Read32(bmi_addr + 40 + i * 4);
            memcpy(bmi_buf.data() + sizeof(BITMAPINFOHEADER) + i * 4, &clr, 4);
        }
        void* pvBits = nullptr;
        HBITMAP hbm = CreateDIBSection(hdc, (BITMAPINFO*)bmi_buf.data(), usage, &pvBits, NULL, 0);
        if (ppvBits_addr != 0) {
            mem.Write32(ppvBits_addr, 0);
        }
        regs[0] = (uint32_t)(uintptr_t)hbm;
        printf("[THUNK] CreateDIBSection(%dx%d, %dbpp) -> 0x%08X\n", bih.biWidth, bih.biHeight, bih.biBitCount, regs[0]);
        return true;
    }
    if (func == "StretchDIBits") {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        int xDest = (int)regs[1], yDest = (int)regs[2];
        int wDest = (int)regs[3];
        int hDest = (int)ReadStackArg(regs, mem, 0);
        int xSrc = (int)ReadStackArg(regs, mem, 1);
        int ySrc = (int)ReadStackArg(regs, mem, 2);
        int wSrc = (int)ReadStackArg(regs, mem, 3);
        int hSrc = (int)ReadStackArg(regs, mem, 4);
        uint32_t bits_addr = ReadStackArg(regs, mem, 5);
        uint32_t bmi_addr = ReadStackArg(regs, mem, 6);
        UINT usage = ReadStackArg(regs, mem, 7);
        DWORD rop = ReadStackArg(regs, mem, 8);
        BITMAPINFOHEADER bih;
        bih.biSize = mem.Read32(bmi_addr);
        bih.biWidth = (LONG)mem.Read32(bmi_addr + 4);
        bih.biHeight = (LONG)mem.Read32(bmi_addr + 8);
        bih.biPlanes = mem.Read16(bmi_addr + 12);
        bih.biBitCount = mem.Read16(bmi_addr + 14);
        bih.biCompression = mem.Read32(bmi_addr + 16);
        bih.biSizeImage = mem.Read32(bmi_addr + 20);
        bih.biXPelsPerMeter = (LONG)mem.Read32(bmi_addr + 24);
        bih.biYPelsPerMeter = (LONG)mem.Read32(bmi_addr + 28);
        bih.biClrUsed = mem.Read32(bmi_addr + 32);
        bih.biClrImportant = mem.Read32(bmi_addr + 36);
        int nColors = 0;
        if (bih.biBitCount <= 8) nColors = (bih.biClrUsed > 0) ? bih.biClrUsed : (1 << bih.biBitCount);
        size_t bmi_size = sizeof(BITMAPINFOHEADER) + nColors * sizeof(RGBQUAD);
        std::vector<uint8_t> bmi_buf(bmi_size, 0);
        memcpy(bmi_buf.data(), &bih, sizeof(bih));
        for (int i = 0; i < nColors; i++) {
            uint32_t clr = mem.Read32(bmi_addr + 40 + i * 4);
            memcpy(bmi_buf.data() + sizeof(BITMAPINFOHEADER) + i * 4, &clr, 4);
        }
        uint8_t* bits_ptr = mem.Translate(bits_addr);
        regs[0] = StretchDIBits(hdc, xDest, yDest, wDest, hDest, xSrc, ySrc, wSrc, hSrc,
                                bits_ptr, (BITMAPINFO*)bmi_buf.data(), usage, rop);
        return true;
    }
    if (func == "TransparentImage" || func == "TransparentBlt") {
        HDC hdcDest = (HDC)(intptr_t)(int32_t)regs[0];
        int xDest = (int)regs[1], yDest = (int)regs[2];
        int wDest = (int)regs[3];
        int hDest = (int)ReadStackArg(regs, mem, 0);
        HDC hdcSrc = (HDC)(intptr_t)(int32_t)ReadStackArg(regs, mem, 1);
        int xSrc = (int)ReadStackArg(regs, mem, 2);
        int ySrc = (int)ReadStackArg(regs, mem, 3);
        int wSrc = (int)ReadStackArg(regs, mem, 4);
        int hSrc = (int)ReadStackArg(regs, mem, 5);
        UINT crTransparent = ReadStackArg(regs, mem, 6);
        regs[0] = TransparentBlt(hdcDest, xDest, yDest, wDest, hDest,
                                 hdcSrc, xSrc, ySrc, wSrc, hSrc, crTransparent);
        return true;
    }
    if (func == "GetClipBox") {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        RECT rc;
        int ret = GetClipBox(hdc, &rc);
        uint32_t rect_addr = regs[1];
        mem.Write32(rect_addr, rc.left);
        mem.Write32(rect_addr + 4, rc.top);
        mem.Write32(rect_addr + 8, rc.right);
        mem.Write32(rect_addr + 12, rc.bottom);
        regs[0] = ret;
        return true;
    }
    if (func == "SetLayout") {
        regs[0] = SetLayout((HDC)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "GetLayout") {
        regs[0] = GetLayout((HDC)(intptr_t)(int32_t)regs[0]);
        return true;
    }

    /* Font / text */
    if (func == "CreateFontIndirectW") {
        LOGFONTW lf = {};
        lf.lfHeight = (LONG)mem.Read32(regs[0]);
        lf.lfWidth = (LONG)mem.Read32(regs[0]+4);
        lf.lfWeight = (LONG)mem.Read32(regs[0]+16);
        lf.lfCharSet = mem.Read8(regs[0]+23);
        for (int i = 0; i < 32; i++) {
            lf.lfFaceName[i] = mem.Read16(regs[0]+28+i*2);
            if (!lf.lfFaceName[i]) break;
        }
        regs[0] = (uint32_t)(uintptr_t)CreateFontIndirectW(&lf);
        return true;
    }
    if (func == "GetTextMetricsW") {
        TEXTMETRICW tm;
        BOOL ret = GetTextMetricsW((HDC)(intptr_t)(int32_t)regs[0], &tm);
        if (ret && regs[1]) {
            mem.Write32(regs[1]+0, tm.tmHeight);
            mem.Write32(regs[1]+4, tm.tmAscent);
            mem.Write32(regs[1]+8, tm.tmDescent);
            mem.Write32(regs[1]+12, tm.tmInternalLeading);
            mem.Write32(regs[1]+16, tm.tmExternalLeading);
            mem.Write32(regs[1]+20, tm.tmAveCharWidth);
            mem.Write32(regs[1]+24, tm.tmMaxCharWidth);
            mem.Write32(regs[1]+28, tm.tmWeight);
            mem.Write32(regs[1]+32, tm.tmOverhang);
            mem.Write32(regs[1]+36, tm.tmDigitizedAspectX);
            mem.Write32(regs[1]+40, tm.tmDigitizedAspectY);
            mem.Write16(regs[1]+44, tm.tmFirstChar);
            mem.Write16(regs[1]+46, tm.tmLastChar);
            mem.Write16(regs[1]+48, tm.tmDefaultChar);
            mem.Write16(regs[1]+50, tm.tmBreakChar);
            mem.Write8(regs[1]+52, tm.tmItalic);
            mem.Write8(regs[1]+53, tm.tmUnderlined);
            mem.Write8(regs[1]+54, tm.tmStruckOut);
            mem.Write8(regs[1]+55, tm.tmPitchAndFamily);
            mem.Write8(regs[1]+56, tm.tmCharSet);
        }
        regs[0] = ret;
        return true;
    }
    if (func == "ExtTextOutW" || func == "DrawTextW") {
        /* Stub - return success */
        regs[0] = 1;
        return true;
    }
    if (func == "GetTextExtentExPointW") {
        /* Stub */
        regs[0] = 1;
        return true;
    }
    if (func == "CreateRectRgnIndirect" || func == "EqualRgn") {
        regs[0] = 0;
        return true;
    }
    if (func == "InvertRect") {
        RECT rc;
        rc.left = mem.Read32(regs[1]); rc.top = mem.Read32(regs[1]+4);
        rc.right = mem.Read32(regs[1]+8); rc.bottom = mem.Read32(regs[1]+12);
        regs[0] = InvertRect((HDC)(intptr_t)(int32_t)regs[0], &rc);
        return true;
    }
    if (func == "GradientFill") {
        regs[0] = 1; /* Stub */
        return true;
    }
    if (func == "Polygon" || func == "Polyline") {
        regs[0] = 1; /* Stub */
        return true;
    }

    /* Paint */
    if (func == "BeginPaint") {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint((HWND)(intptr_t)(int32_t)regs[0], &ps);
        uint32_t ps_addr = regs[1];
        mem.Write32(ps_addr + 0, (uint32_t)(uintptr_t)hdc);
        mem.Write32(ps_addr + 4, ps.fErase);
        mem.Write32(ps_addr + 8, ps.rcPaint.left);
        mem.Write32(ps_addr + 12, ps.rcPaint.top);
        mem.Write32(ps_addr + 16, ps.rcPaint.right);
        mem.Write32(ps_addr + 20, ps.rcPaint.bottom);
        regs[0] = (uint32_t)(uintptr_t)hdc;
        return true;
    }
    if (func == "EndPaint") {
        PAINTSTRUCT ps = {};
        ps.hdc = (HDC)(intptr_t)(int32_t)mem.Read32(regs[1]);
        EndPaint((HWND)(intptr_t)(int32_t)regs[0], &ps);
        regs[0] = 1;
        return true;
    }

    return false;
}
