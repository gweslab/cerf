#include "probe.h"

static void VerifyOverhangCase(const WCHAR* tag, HDC dst, const ProbeLinear& d, HDC src,
                               const ProbeLinear& s, int dx, int dy, int w, int h, int sx,
                               int sy) {
    DWORD untouched = 0u, other = 0u, unknown = 0u, first_other = 0u;
    int   x, y;
    Done(tag, g_probe.blt(dst, dx, dy, w, h, src, sx, sy, SRCCOPY));
    for (y = 0; y < h; ++y) {
        for (x = 0; x < w; ++x) {
            const BYTE* sp = s.row0 + (LONG)(sy + y) * s.stride + (LONG)(sx + x);
            const BYTE* dp = d.row0 + (LONG)(dy + y) * d.stride + (LONG)(dx + x);
            if (sp < s.base || sp >= s.base + s.size) { ++unknown; continue; }
            if (*dp == *sp) continue;
            if (*dp == PatternByte((DWORD)(dp - d.base))) {
                ++untouched;
            } else {
                if (other == 0u) first_other = ((DWORD)x << 16) | (DWORD)y;
                ++other;
            }
        }
    }
    Say(L"  mismatch untouched/other", untouched, other);
    Say(L"  unknown/first other xy", unknown, first_other);
}

void VerifyOverhang(int height_sign) {
    HDC     src, dst;
    BYTE    *sb = NULL, *db = NULL;
    HBITMAP sbmp = MakeDibBits(239, 239 * height_sign, 8, &src, &sb);
    HBITMAP dbmp = MakeDibBits(200, -200, 8, &dst, &db);
    if (sbmp && dbmp) {
        const ProbeLinear s = LinearOf(sb, 239, 239 * height_sign, 8);
        const ProbeLinear d = LinearOf(db, 200, -200, 8);
        Say(L"verify overhang src sign", (DWORD)height_sign, 0);
        VerifyOverhangCase(L" inside control", dst, d, src, s, 0, 0, 100, 20, 10, 10);
        VerifyOverhangCase(L" left -159", dst, d, src, s, 41, 0, 159, 32, -159, 0);
        VerifyOverhangCase(L" right", dst, d, src, s, 0, 40, 159, 32, 200, 0);
        VerifyOverhangCase(L" bottom", dst, d, src, s, 0, 80, 100, 40, 0, 220);
        VerifyOverhangCase(L" top", dst, d, src, s, 0, 130, 100, 40, 0, -20);
        VerifyOverhangCase(L" left-up", dst, d, src, s, 120, 130, 60, 60, -30, -30);
    }
    FreeDib(dbmp, dst);
    FreeDib(sbmp, src);
}

static BOOL FitsTarget(int dx, int dy, int w, int h) {
    if (dx + w <= g_probe.target_w && dy + h <= g_probe.target_h) return TRUE;
    Say(L"  off-window skip w/h", (DWORD)(dx + w), (DWORD)(dy + h));
    return FALSE;
}

static void VerifyScreenCase(const WCHAR* tag, HDC src, const ProbeLinear& s, int dx, int dy,
                             int w, int h, int sx, int sy) {
    HDC         rd;
    BYTE*       rb = NULL;
    HBITMAP     rbmp;
    const DWORD stride = (((DWORD)w * 24u + 31u) / 32u) * 4u;
    DWORD       match = 0u, bad = 0u, unknown = 0u, first_bad = 0u;
    int         x, y;
    if (!FitsTarget(dx, dy, w, h)) return;
    rbmp = MakeDibBits(w, -h, 24, &rd, &rb);
    if (!rbmp) return;
    g_probe.pblt(g_probe.target, dx, dy, w, h, BLACKNESS);
    Done(tag, g_probe.blt(g_probe.target, dx, dy, w, h, src, sx, sy, SRCCOPY));
    g_probe.blt(rd, 0, 0, w, h, g_probe.target, dx, dy, SRCCOPY);
    for (y = 0; y < h; ++y) {
        for (x = 0; x < w; ++x) {
            const BYTE* sp = s.row0 + (LONG)(sy + y) * s.stride + (LONG)(sx + x);
            if (sp < s.base || sp >= s.base + s.size) { ++unknown; continue; }
            const BYTE* px = rb + (DWORD)y * stride + (DWORD)x * 3u;
            if (px[0] == (BYTE)(255u - *sp)) {
                ++match;
            } else {
                if (bad == 0u) {
                    first_bad = ((DWORD)x << 16) | (DWORD)y;
                    Say(L"  first bad bgr/expected idx",
                        ((DWORD)px[0] << 16) | ((DWORD)px[1] << 8) | (DWORD)px[2], (DWORD)*sp);
                }
                ++bad;
            }
        }
    }
    Say(L"  screen match/bad", match, bad);
    Say(L"  unknown/first bad xy", unknown, first_bad);
    FreeDib(rbmp, rd);
}

void VerifyOverhangScreen(int height_sign) {
    HDC     src;
    BYTE*   sb = NULL;
    HBITMAP sbmp = MakeDibBits(239, 239 * height_sign, 8, &src, &sb);
    if (sbmp) {
        const ProbeLinear s = LinearOf(sb, 239, 239 * height_sign, 8);
        Say(L"verify screen overhang src sign/bpp", (DWORD)height_sign,
            g_probe.caps ? (DWORD)g_probe.caps(g_probe.target, BITSPIXEL) : 0u);
        VerifyScreenCase(L" screen inside control", src, s, 0, 0, 100, 20, 10, 10);
        VerifyScreenCase(L" screen left -159", src, s, 0, 0, 159, 32, -159, 0);
        VerifyScreenCase(L" screen right", src, s, 0, 0, 159, 32, 200, 0);
        VerifyScreenCase(L" screen bottom", src, s, 0, 0, 100, 40, 0, 220);
        VerifyScreenCase(L" screen top", src, s, 0, 0, 100, 40, 0, -20);
        VerifyScreenCase(L" screen left-up", src, s, 0, 0, 60, 60, -30, -30);
    }
    FreeDib(sbmp, src);
}

static void CountDrawnColumns(const WCHAR* tag, HDC src, int dx, int w, int h, int sx,
                              int first_col, int last_col) {
    HDC         rd;
    BYTE*       rb = NULL;
    HBITMAP     rbmp;
    const DWORD stride = (((DWORD)w * 24u + 31u) / 32u) * 4u;
    DWORD       drawn = 0u, black = 0u;
    int         x, y;
    if (!FitsTarget(dx, 0, w, h)) return;
    rbmp = MakeDibBits(w, -h, 24, &rd, &rb);
    if (!rbmp) return;
    g_probe.pblt(g_probe.target, dx, 0, w, h, BLACKNESS);
    Done(tag, g_probe.blt(g_probe.target, dx, 0, w, h, src, sx, 0, SRCCOPY));
    g_probe.blt(rd, 0, 0, w, h, g_probe.target, dx, 0, SRCCOPY);
    for (y = 0; y < h; ++y) {
        for (x = first_col; x < last_col; ++x) {
            const BYTE* px = rb + (DWORD)y * stride + (DWORD)x * 3u;
            if ((px[0] | px[1] | px[2]) != 0u) ++drawn; else ++black;
        }
    }
    Say(L"  overhang drawn/black", drawn, black);
    FreeDib(rbmp, rd);
}

void OverhangBySourceKind(void) {
    static BYTE ddb_bits[718 * 239];
    HDC         dib_dc, ddb_dc;
    HBITMAP     dib = MakeDib(239, 239, 24, &dib_dc);
    HBITMAP     ddb;
    DWORD       i;
    for (i = 0; i < sizeof(ddb_bits); ++i) ddb_bits[i] = (BYTE)(PatternByte(i) | 1u);
    ddb    = g_probe.cbmp ? g_probe.cbmp(239, 239, 1, 24, ddb_bits) : NULL;
    ddb_dc = ddb ? g_probe.ccdc(g_probe.screen) : NULL;
    if (ddb_dc) g_probe.sel(ddb_dc, ddb);
    Say(L"source kind dib/ddb", (DWORD)(dib != NULL), (DWORD)(ddb != NULL));
    if (dib) {
        CountDrawnColumns(L" dib left -159", dib_dc, 0, 159, 32, -159, 0, 159);
        CountDrawnColumns(L" dib right", dib_dc, 0, 159, 32, 200, 39, 159);
    }
    if (ddb_dc) {
        CountDrawnColumns(L" ddb left -159", ddb_dc, 0, 159, 32, -159, 0, 159);
        CountDrawnColumns(L" ddb right", ddb_dc, 0, 159, 32, 200, 39, 159);
    }
    FreeDib(ddb, ddb_dc);
    FreeDib(dib, dib_dc);
}

void SourceOverhang(int bpp, int height_sign) {
    ProbeGdi& g = g_probe;
    HDC       src;
    HBITMAP   bmp = MakeDib(239, 239 * height_sign, bpp, &src);
    if (!bmp) return;
    Say(L"overhang bpp/sign", (DWORD)bpp, (DWORD)height_sign);
    Done(L"src left -159", g.blt(g.target, 41, 0, 159, 32, src, -159, 0, SRCCOPY));
    Done(L"src right", g.blt(g.target, 41, 40, 159, 32, src, 200, 0, SRCCOPY));
    Done(L"src bottom", g.blt(g.target, 41, 80, 100, 40, src, 0, 220, SRCCOPY));
    Done(L"src top", g.blt(g.target, 41, 130, 100, 40, src, 0, -20, SRCCOPY));
    Done(L"src outside", g.blt(g.target, 41, 180, 50, 20, src, 300, 300, SRCCOPY));
    Done(L"src left-up", g.blt(g.target, 300, 0, 60, 60, src, -30, -30, SRCCOPY));
    if (g.sblt)
        Done(L"stretch overhang", g.sblt(g.target, 300, 80, 120, 120, src, -50, -50, 300, 300,
                                         SRCCOPY));
    if (g.timg)
        Done(L"transparent overhang", g.timg(g.target, 430, 80, 80, 80, src, -20, -20, 80, 80,
                                             RGB(0, 0, 0)));
    FreeDib(bmp, src);
}

static void MaskOverhangWith(HBITMAP mask, HDC src) {
    ProbeGdi& g = g_probe;
    Done(L"mask left-up", g.mblt(g.target, 10, 10, 80, 80, src, 0, 0, mask, -20, -5,
                                 0xAACC0020u));
    Done(L"mask right", g.mblt(g.target, 100, 10, 80, 80, src, 0, 0, mask, 40, 0,
                               0xAACC0020u));
}

void MaskOverhang(void) {
    static BYTE mono[64 * 8];
    HDC     src, mdc;
    HBITMAP bmp  = MakeDib(120, 120, 24, &src);
    HBITMAP mask = MakeDib(64, 64, 1, &mdc);
    int     i;
    if (bmp && mask && g_probe.mblt) {
        g_probe.deldc(mdc);
        mdc = NULL;
        Say(L"mask kind dib", 1, 0);
        MaskOverhangWith(mask, src);
    }
    FreeDib(mask, mdc);
    for (i = 0; i < (int)sizeof(mono); ++i) mono[i] = PatternByte((DWORD)i);
    mask = g_probe.cbmp ? g_probe.cbmp(64, 64, 1, 1, mono) : NULL;
    if (bmp && mask && g_probe.mblt) {
        Say(L"mask kind createbitmap", 2, 0);
        MaskOverhangWith(mask, src);
    }
    if (mask) g_probe.delobj(mask);
    FreeDib(bmp, src);
}

void ScreenOverhang(void) {
    ProbeGdi& g = g_probe;
    const int sw = g.caps ? g.caps(g.screen, HORZRES) : 0;
    const int sh = g.caps ? g.caps(g.screen, VERTRES) : 0;
    Say(L"screen w/h", (DWORD)sw, (DWORD)sh);
    Done(L"screen src left-up", g.blt(g.target, 100, 60, 60, 60, g.screen, -30, -30, SRCCOPY));
    Done(L"screen src left", g.blt(g.target, 170, 60, 60, 20, g.screen, -50, 10, SRCCOPY));
    if (sw > 0 && sh > 0)
        Done(L"screen src right-down", g.blt(g.target, 240, 60, 60, 60, g.screen, sw - 30,
                                             sh - 30, SRCCOPY));
    if (g.sblt)
        Done(L"screen stretch overhang", g.sblt(g.target, 310, 60, 80, 80, g.screen, -40, -40,
                                                120, 120, SRCCOPY));
}
