/* CerfDemo desktop: a fade-in field of dimmed purple/blue bokeh discs
   drifting up the screen, composited in a quarter-res DIB and stretched
   onto the fullscreen background window. Pure Win32/GDI. */

#include "cerf_demo.h"

#define NDISC   28
#define FADE_MS 5000

/* per-frame bokeh state — this compositor owns all of it */
static int           g_bw, g_bh;
static HDC           g_fxdc;
static HBITMAP       g_fxbmp;
static unsigned int* g_fxbits;
static int           g_fxw, g_fxh;

/* dimmed purple/blue bokeh discs drifting up, concentrated at the bottom */
typedef struct { int xf, rf, col, div, off; } Disc;
static Disc g_disc[NDISC];
static const COLORREF g_dcol[5] = {
    RGB(118, 58, 198), RGB(54, 86, 214), RGB(92, 48, 182),
    RGB(44, 74, 200),  RGB(138, 66, 206)
};
static unsigned int g_lcg = 0x2545F491u;
static unsigned int Lcg(void) {
    g_lcg = g_lcg * 1103515245u + 12345u;
    return g_lcg >> 8;
}
void InitDiscs(void) {
    int i;
    for (i = 0; i < NDISC; i++) {
        g_disc[i].xf  = (int)(Lcg() % 1000);
        g_disc[i].rf  = 90 + (int)(Lcg() % 210);
        g_disc[i].col = (int)(Lcg() % 5);
        g_disc[i].div = 28 + (int)(Lcg() % 70);
        g_disc[i].off = (int)(Lcg() % 4000);
    }
}

static void EnsureFx(HWND h) {
    RECT rc; HDC dc; HBITMAP nb; int w, ht, fw, fh;
    GetClientRect(h, &rc);
    w = rc.right; ht = rc.bottom;
    if (w < 1) w = 1;
    if (ht < 1) ht = 1;
    g_bw = w; g_bh = ht;
    fw = w / 4; if (fw < 200) fw = 200; if (fw > 480) fw = 480;
    fh = ht / 4; if (fh < 120) fh = 120; if (fh > 300) fh = 300;
    if (g_fxbmp && fw == g_fxw && fh == g_fxh) return;
    dc = GetDC(h);
    if (!g_fxdc) g_fxdc = CreateCompatibleDC(dc);
    nb = MakeDib32(fw, fh, &g_fxbits);
    SelectObject(g_fxdc, nb);
    if (g_fxbmp) DeleteObject(g_fxbmp);
    g_fxbmp = nb; g_fxw = fw; g_fxh = fh;
    ReleaseDC(h, dc);
}

void PresentBg(HWND h) {
    DWORD tk; int el, f, i, py, px;
    EnsureFx(h);
    tk = GetTickCount();
    el = (int)(tk - g_start);
    f = (el >= FADE_MS || el < 0) ? 256 : el * 256 / FADE_MS;

    ZeroMemory(g_fxbits, (size_t)g_fxw * g_fxh * 4);
    for (i = 0; i < NDISC; i++) {
        int R   = g_disc[i].rf * g_fxh / 1000;
        int cx  = g_disc[i].xf * g_fxw / 1000;
        int span, travel, cy, R2, vf, amp, x0, x1, y0, y1, cr, cg, cb;
        COLORREF c;
        if (R < 4) R = 4;
        span   = g_fxh + 2 * R;
        travel = (int)((tk / g_disc[i].div + g_disc[i].off) % span);
        cy = g_fxh + R - travel;                 /* drifts up, wraps */
        R2 = R * R;
        vf = cy * 256 / g_fxh;                    /* bright at bottom */
        if (vf < 0) vf = 0; if (vf > 256) vf = 256;
        amp = vf * f / 256;
        if (amp <= 0) continue;
        c = g_dcol[g_disc[i].col];
        cr = GetRValue(c); cg = GetGValue(c); cb = GetBValue(c);
        x0 = cx - R; x1 = cx + R; y0 = cy - R; y1 = cy + R;
        if (x0 < 0) x0 = 0; if (x1 > g_fxw) x1 = g_fxw;
        if (y0 < 0) y0 = 0; if (y1 > g_fxh) y1 = g_fxh;
        for (py = y0; py < y1; py++) {
            int dy = py - cy;
            unsigned int* row = g_fxbits + (size_t)py * g_fxw;
            for (px = x0; px < x1; px++) {
                int dx = px - cx, d2 = dx * dx + dy * dy;
                if (d2 < R2) {
                    int it = (R2 - d2) * amp / R2;     /* soft falloff */
                    unsigned int p = row[px];
                    int pr = (int)((p >> 16) & 255) + cr * it / 256;
                    int pg = (int)((p >> 8) & 255)  + cg * it / 256;
                    int pb = (int)(p & 255)         + cb * it / 256;
                    if (pr > 255) pr = 255;
                    if (pg > 255) pg = 255;
                    if (pb > 255) pb = 255;
                    row[px] = ((unsigned)pr << 16) | ((unsigned)pg << 8)
                            | (unsigned)pb;
                }
            }
        }
    }
    {
        HDC wdc = GetDC(h);
        StretchBlt(wdc, 0, 0, g_bw, g_bh, g_fxdc, 0, 0, g_fxw, g_fxh, SRCCOPY);
        ReleaseDC(h, wdc);
    }
}

LRESULT CALLBACK BgProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: EnsureFx(h); return 0;
    case WM_SIZE:   EnsureFx(h); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        if (g_fxdc)
            StretchBlt(dc, 0, 0, g_bw, g_bh, g_fxdc, 0, 0,
                       g_fxw, g_fxh, SRCCOPY);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DESTROY:
        if (g_dlg) DestroyWindow(g_dlg);
        if (g_fxbmp) DeleteObject(g_fxbmp);
        if (g_fxdc) DeleteDC(g_fxdc);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(h, m, wp, lp);
}
