#include "probe.h"

ProbeGdi g_probe;

FARPROC ProbeSym(const WCHAR* name) {
    return g_probe.core != NULL ? GetProcAddressW(g_probe.core, name) : NULL;
}

BOOL ProbeLoadGdi(void) {
    ProbeGdi& g = g_probe;
    g.core   = LoadLibraryW(L"coredll.dll");
    g.ods    = (PFN_ODS)ProbeSym(L"OutputDebugStringW");
    g.getdc  = (PFN_GetDC)ProbeSym(L"GetDC");
    g.ccdc   = (PFN_CreateCompatibleDC)ProbeSym(L"CreateCompatibleDC");
    g.sel    = (PFN_SelectObject)ProbeSym(L"SelectObject");
    g.delobj = (PFN_DeleteObject)ProbeSym(L"DeleteObject");
    g.deldc  = (PFN_DeleteDC)ProbeSym(L"DeleteDC");
    g.cdib   = (PFN_CreateDIBSection)ProbeSym(L"CreateDIBSection");
    g.blt    = (PFN_BitBlt)ProbeSym(L"BitBlt");
    g.sblt   = (PFN_StretchBlt)ProbeSym(L"StretchBlt");
    g.mblt   = (PFN_MaskBlt)ProbeSym(L"MaskBlt");
    g.timg   = (PFN_TransparentImage)ProbeSym(L"TransparentImage");
    g.grad   = (PFN_GradientFill)ProbeSym(L"GradientFill");
    g.alpha  = (PFN_AlphaBlend)ProbeSym(L"AlphaBlend");
    g.pbrush = (PFN_CreatePatternBrush)ProbeSym(L"CreatePatternBrush");
    g.pblt   = (PFN_PatBlt)ProbeSym(L"PatBlt");
    g.poly   = (PFN_Polyline)ProbeSym(L"Polyline");
    g.cbmp   = (PFN_CreateBitmap)ProbeSym(L"CreateBitmap");
    g.caps   = (PFN_GetDeviceCaps)ProbeSym(L"GetDeviceCaps");
    return g.getdc && g.ccdc && g.sel && g.delobj && g.deldc && g.cdib && g.blt && g.pblt &&
           g.poly;
}

void Say(const WCHAR* tag, DWORD a, DWORD b) {
    WCHAR buf[112];
    int   n = 0, i;
    const WCHAR* p;
    if (g_probe.ods == NULL) return;
    for (p = L"gdiprobe: "; *p && n < 90; ++p) buf[n++] = *p;
    for (p = tag; *p && n < 90; ++p) buf[n++] = *p;
    buf[n++] = L' ';
    for (i = 28; i >= 0; i -= 4) buf[n++] = L"0123456789ABCDEF"[(a >> i) & 0xFu];
    buf[n++] = L' ';
    for (i = 28; i >= 0; i -= 4) buf[n++] = L"0123456789ABCDEF"[(b >> i) & 0xFu];
    buf[n++] = L'\r';
    buf[n++] = L'\n';
    buf[n]   = 0;
    g_probe.ods(buf);
}

void Done(const WCHAR* tag, BOOL ok) {
    Say(tag, (DWORD)ok, GetLastError());
    Sleep(150);
}

BYTE PatternByte(DWORD i) {
    return (BYTE)(i * 13u + (i >> 9));
}

HBITMAP MakeDibBits(int w, int h, int bpp, HDC* dc, BYTE** out_bits) {
    ProbeBmi bi;
    BYTE*    bits = NULL;
    BYTE*    raw  = (BYTE*)&bi;
    HBITMAP  bmp;
    DWORD    i, stride, size;
    for (i = 0; i < sizeof(bi); ++i) raw[i] = 0;
    bi.h.biSize     = sizeof(BITMAPINFOHEADER);
    bi.h.biWidth    = w;
    bi.h.biHeight   = h;
    bi.h.biPlanes   = 1;
    bi.h.biBitCount = (WORD)bpp;
    if (bpp == 16) {
        DWORD* masks = (DWORD*)bi.c;
        bi.h.biCompression = BI_BITFIELDS;
        masks[0] = 0xF800u;
        masks[1] = 0x07E0u;
        masks[2] = 0x001Fu;
    }
    if (bpp <= 8) {
        const DWORD n = 1u << bpp;
        bi.h.biClrUsed = n;
        for (i = 0; i < n; ++i) {
            bi.c[i].rgbRed   = (BYTE)(i * 37u);
            bi.c[i].rgbGreen = (BYTE)(i * 91u);
            bi.c[i].rgbBlue  = (BYTE)(255u - i);
        }
    }
    bmp = g_probe.cdib(g_probe.screen, (BITMAPINFO*)&bi, DIB_RGB_COLORS, (void**)&bits, NULL, 0);
    if (bmp == NULL || bits == NULL) {
        Say(L"dib failed w/err", (DWORD)w, GetLastError());
        *dc = NULL;
        return NULL;
    }
    stride = (((DWORD)w * (DWORD)bpp + 31u) / 32u) * 4u;
    size   = stride * (DWORD)(h < 0 ? -h : h);
    for (i = 0; i < size; ++i) bits[i] = PatternByte(i);
    *dc = g_probe.ccdc(g_probe.screen);
    g_probe.sel(*dc, bmp);
    if (out_bits) *out_bits = bits;
    return bmp;
}

HBITMAP MakeDib(int w, int h, int bpp, HDC* dc) {
    return MakeDibBits(w, h, bpp, dc, NULL);
}

void FreeDib(HBITMAP bmp, HDC dc) {
    if (dc) g_probe.deldc(dc);
    if (bmp) g_probe.delobj(bmp);
}

ProbeLinear LinearOf(BYTE* bits, int w, int h, int bpp) {
    ProbeLinear l;
    const DWORD abs_stride = (((DWORD)w * (DWORD)bpp + 31u) / 32u) * 4u;
    const DWORD rows       = (DWORD)(h < 0 ? -h : h);
    l.base   = bits;
    l.size   = abs_stride * rows;
    l.stride = (h < 0) ? (LONG)abs_stride : -(LONG)abs_stride;
    l.row0   = (h < 0) ? bits : bits + (rows - 1u) * abs_stride;
    return l;
}
