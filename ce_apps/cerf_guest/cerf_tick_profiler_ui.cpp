#include <windows.h>

#include "cerf_tick_profiler_ui.h"
#include "cerf_tick_profiler.h"

#define CERF_TPUI_W            100
#define CERF_TPUI_H            40
#define CERF_TPUI_BOTTOM_GAP   24
#define CERF_TPUI_RIGHT_MARGIN 8

#define CERF_TPUI_PLOT_X 2
#define CERF_TPUI_PLOT_Y 2
#define CERF_TPUI_PLOT_W CERF_TP_SAMPLES
#define CERF_TPUI_PLOT_H 36

#define CERF_TPUI_TOLERANCE 50u

#define CERF_TPUI_TIMER_ID 1

static const WCHAR kCerfTpUiClass[] = L"CerfTickProfiler";

static void CerfTpUiFill(HDC dc, int l, int t, int r, int b, HBRUSH br) {
    RECT rc;
    rc.left = l; rc.top = t; rc.right = r; rc.bottom = b;
    FillRect(dc, &rc, br);
}

static int CerfTpUiRatioToY(DWORD ratio) {
    DWORD span = CERF_TPUI_PLOT_H - 1;
    if (ratio > CERF_TP_FULL_SCALE) ratio = CERF_TP_FULL_SCALE;
    return CERF_TPUI_PLOT_Y + (int)span - (int)((ratio * span) / CERF_TP_FULL_SCALE);
}

static void CerfTpUiPaintChart(HDC dc) {
    DWORD  samples[CERF_TP_SAMPLES];
    HBRUSH bg     = CreateSolidBrush(RGB(0, 0, 0));
    HBRUSH border = CreateSolidBrush(RGB(72, 72, 72));
    HBRUSH base   = CreateSolidBrush(RGB(112, 112, 112));
    HBRUSH good   = CreateSolidBrush(RGB(0, 224, 0));
    HBRUSH bad    = CreateSolidBrush(RGB(232, 48, 48));
    int    y_base = CerfTpUiRatioToY(CERF_TP_UNITY);
    int    count, i;

    CerfTpUiFill(dc, 0, 0, CERF_TPUI_W, CERF_TPUI_H, bg);

    CerfTpUiFill(dc, 0, 0, CERF_TPUI_W, 1, border);
    CerfTpUiFill(dc, 0, CERF_TPUI_H - 1, CERF_TPUI_W, CERF_TPUI_H, border);
    CerfTpUiFill(dc, 0, 0, 1, CERF_TPUI_H, border);
    CerfTpUiFill(dc, CERF_TPUI_W - 1, 0, CERF_TPUI_W, CERF_TPUI_H, border);

    CerfTpUiFill(dc, CERF_TPUI_PLOT_X, y_base,
                 CERF_TPUI_PLOT_X + CERF_TPUI_PLOT_W, y_base + 1, base);

    count = CerfTickProfilerSnapshot(samples, CERF_TP_SAMPLES);
    for (i = 0; i < count; ++i) {
        DWORD ratio = samples[i];
        DWORD dev   = (ratio > CERF_TP_UNITY) ? (ratio - CERF_TP_UNITY)
                                              : (CERF_TP_UNITY - ratio);
        int   x     = CERF_TPUI_PLOT_X + (CERF_TPUI_PLOT_W - count) + i;
        int   y     = CerfTpUiRatioToY(ratio);
        int   top   = (y < y_base) ? y : y_base;
        int   bot   = ((y > y_base) ? y : y_base) + 1;
        CerfTpUiFill(dc, x, top, x + 1, bot,
                     (dev > CERF_TPUI_TOLERANCE) ? bad : good);
    }

    DeleteObject(bad);
    DeleteObject(good);
    DeleteObject(base);
    DeleteObject(border);
    DeleteObject(bg);
}

static void CerfTpUiPaint(HWND w) {
    PAINTSTRUCT ps;
    HDC     dc  = BeginPaint(w, &ps);
    HDC     mem = CreateCompatibleDC(dc);
    HBITMAP bmp = mem ? CreateCompatibleBitmap(dc, CERF_TPUI_W, CERF_TPUI_H) : NULL;
    if (bmp) {
        HBITMAP old = (HBITMAP)SelectObject(mem, bmp);
        CerfTpUiPaintChart(mem);
        BitBlt(dc, 0, 0, CERF_TPUI_W, CERF_TPUI_H, mem, 0, 0, SRCCOPY);
        SelectObject(mem, old);
        DeleteObject(bmp);
    } else {
        CerfTpUiPaintChart(dc);
    }
    if (mem) DeleteDC(mem);
    EndPaint(w, &ps);
}

static LRESULT CALLBACK CerfTpUiWndProc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT:
        CerfTpUiPaint(w);
        return 0;
    case WM_TIMER:
        SetWindowPos(w, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        InvalidateRect(w, NULL, FALSE);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        KillTimer(w, CERF_TPUI_TIMER_ID);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(w, msg, wp, lp);
}

static HWND CerfTpUiCreateWindow(void) {
    HINSTANCE inst = (HINSTANCE)CerfTickProfilerModule();
    WNDCLASSW wc;
    HWND      w;
    int       x = GetSystemMetrics(SM_CXSCREEN) - CERF_TPUI_W - CERF_TPUI_RIGHT_MARGIN;
    int       y = GetSystemMetrics(SM_CYSCREEN) - CERF_TPUI_BOTTOM_GAP - CERF_TPUI_H;

    if (x < 0) x = 0;
    if (y < 0) y = 0;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = CerfTpUiWndProc;
    wc.hInstance     = inst;
    wc.lpszClassName = kCerfTpUiClass;
    RegisterClassW(&wc);

    w = CreateWindowExW(WS_EX_TOPMOST, kCerfTpUiClass, L"", WS_POPUP,
                        x, y, CERF_TPUI_W, CERF_TPUI_H,
                        NULL, NULL, inst, NULL);
    if (!w) {
        CERF_LOG("cerf_guest: tickprof ui CreateWindow FAILED");
        return NULL;
    }

    SetWindowPos(w, HWND_TOPMOST, x, y, CERF_TPUI_W, CERF_TPUI_H,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
    SetTimer(w, CERF_TPUI_TIMER_ID, CERF_TP_SAMPLE_MS, NULL);
    {
        RECT rc;
        rc.left = rc.top = rc.right = rc.bottom = 0;
        GetWindowRect(w, &rc);
        CERF_LOG_X("cerf_guest: tickprof ui visible", (DWORD)IsWindowVisible(w));
        CERF_LOG_X("cerf_guest: tickprof ui left", (DWORD)rc.left);
        CERF_LOG_X("cerf_guest: tickprof ui top", (DWORD)rc.top);
    }
    return w;
}

static DWORD WINAPI CerfTpUiThread(LPVOID) {
    MSG  msg;
    HWND w = CerfTpUiCreateWindow();
    if (!w) return 0;
    CERF_LOG("cerf_guest: tickprof ui up");
    while (GetMessageW(&msg, NULL, 0, 0)) {
        DispatchMessageW(&msg);
    }
    return 0;
}

extern "C" void CerfTickProfilerOnShellIsUp(void) {
    static BOOL started = FALSE;
    HANDLE t;
    if (started) return;
    started = TRUE;
    t = CreateThread(NULL, 0, CerfTpUiThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
