#include "probe.h"

static DWORD CountShiftMismatches(const BYTE* bits, DWORD stride, int bpp, int y, int dst_x,
                                  int src_x, int n) {
    const DWORD px = (DWORD)bpp / 8u;
    DWORD bad = 0u;
    int   x, k;
    for (x = 0; x < n; ++x) {
        const DWORD at   = (DWORD)y * stride + (DWORD)(dst_x + x) * px;
        const DWORD from = (DWORD)y * stride + (DWORD)(src_x + x) * px;
        for (k = 0; k < (int)px; ++k)
            if (bits[at + (DWORD)k] != PatternByte(from + (DWORD)k)) { ++bad; break; }
    }
    return bad;
}

void WideSameSurface(void) {
    HDC     dc   = NULL;
    HBITMAP bmp  = NULL;
    BYTE*   bits = NULL;
    int     k, w = 32000, bpp = 32;
    DWORD   stride;
    const int shift = 1000;
    for (k = 0; k < 2 && !bmp; ++k) {
        bpp = (k == 0) ? 32 : 24;
        bmp = MakeDibBits(w, -2, bpp, &dc, &bits);
    }
    if (!bmp) return;
    stride = (((DWORD)w * (DWORD)bpp + 31u) / 32u) * 4u;
    Say(L"same-surface wide width/bpp", (DWORD)w, (DWORD)bpp);
    Done(L"same-surface shift right", g_probe.blt(dc, shift, 0, w - shift, 1, dc, 0, 0, SRCCOPY));
    Say(L"shift right mismatches", CountShiftMismatches(bits, stride, bpp, 0, shift, 0,
                                                        w - shift), (DWORD)(w - shift));
    Done(L"same-surface shift left", g_probe.blt(dc, 0, 1, w - shift, 1, dc, shift, 1, SRCCOPY));
    Say(L"shift left mismatches", CountShiftMismatches(bits, stride, bpp, 1, 0, shift,
                                                       w - shift), (DWORD)(w - shift));
    FreeDib(bmp, dc);
}

void IndexedDestinations(void) {
    static const int kBpp[3] = { 8, 4, 1 };
    ProbeGdi& g = g_probe;
    HDC       src;
    HBITMAP   sbmp = MakeDib(100, 100, 24, &src);
    int       k;
    for (k = 0; k < 3; ++k) {
        HDC     dst;
        HBITMAP dbmp = MakeDib(100, 100, kBpp[k], &dst);
        if (!dbmp) continue;
        Say(L"indexed dst bpp", (DWORD)kBpp[k], 0);
        if (sbmp) Done(L"24 to indexed", g.blt(dst, 0, 0, 100, 100, src, 0, 0, SRCCOPY));
        if (g.grad) {
            ProbeVertex   v[2];
            ProbeGradRect r;
            v[0].x = 0;   v[0].y = 0;   v[0].r = 0xFF00; v[0].g = 0;      v[0].b = 0;
            v[0].a = 0;
            v[1].x = 100; v[1].y = 100; v[1].r = 0;      v[1].g = 0x8000; v[1].b = 0xFF00;
            v[1].a = 0;
            r.ul = 0; r.lr = 1;
            Done(L"gradient indexed", g.grad(dst, v, 2, &r, 1, 0));
        }
        if (g.alpha && sbmp) {
            ProbeBlend bf;
            bf.op = 0; bf.flags = 0; bf.alpha = 0x80; bf.format = 0;
            Done(L"alpha indexed", g.alpha(dst, 0, 0, 100, 100, src, 0, 0, 100, 100, bf));
        }
        g.blt(g.target, 520, k * 104, 100, 100, dst, 0, 0, SRCCOPY);
        FreeDib(dbmp, dst);
    }
    FreeDib(sbmp, src);
}

void WideRows(void) {
    static const int kWidths[6] = { 140000, 131072, 100000, 65536, 40000, 32767 };
    ProbeGdi& g = g_probe;
    HDC       wide = NULL;
    HBITMAP   bmp  = NULL;
    int       k, w = 0, bpp = 32;
    for (k = 0; k < 12 && !bmp; ++k) {
        w   = kWidths[k % 6];
        bpp = (k < 6) ? 32 : 24;
        bmp = MakeDib(w, 2, bpp, &wide);
    }
    if (!bmp) return;
    Say(L"wide dib width/bpp", (DWORD)w, (DWORD)bpp);
    Done(L"wide patblt", g.pblt(wide, 0, 0, w, 2, WHITENESS));
    if (g.sblt)
        Done(L"wide stretch src", g.sblt(g.target, 0, 220, 100, 2, wide, 0, 0, w, 2, SRCCOPY));
    {
        POINT pts[2];
        pts[0].x = 0;     pts[0].y = 0;
        pts[1].x = w - 1; pts[1].y = 1;
        Done(L"wide line", g.poly(wide, pts, 2));
    }
    if (g.grad) {
        ProbeVertex   v[2];
        ProbeGradRect r;
        v[0].x = 0; v[0].y = 0; v[0].r = 0xFF00; v[0].g = 0; v[0].b = 0; v[0].a = 0;
        v[1].x = w; v[1].y = 2; v[1].r = 0; v[1].g = 0; v[1].b = 0xFF00; v[1].a = 0;
        r.ul = 0; r.lr = 1;
        Done(L"wide gradient", g.grad(wide, v, 2, &r, 1, 0));
    }
    if (g.pbrush) {
        HBRUSH  br = g.pbrush(bmp);
        HGDIOBJ old;
        if (br) {
            old = g.sel(g.target, br);
            Done(L"wide brush", g.pblt(g.target, 0, 224, 100, 2, PATCOPY));
            g.sel(g.target, old);
            g.delobj(br);
        }
    }
    FreeDib(bmp, wide);
}
