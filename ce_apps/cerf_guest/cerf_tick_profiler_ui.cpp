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

static int CerfTpUiRatioToY(DWORD ratio) {
    DWORD span = CERF_TPUI_PLOT_H - 1;
    if (ratio > CERF_TP_FULL_SCALE) ratio = CERF_TP_FULL_SCALE;
    return CERF_TPUI_PLOT_Y + (int)span - (int)((ratio * span) / CERF_TP_FULL_SCALE);
}

static void CerfTpUiPaintChart(HDC dc) {
    DWORD  samples[CERF_TP_SAMPLES];
    RECT   rc;
    HBRUSH bg     = CreateSolidBrush(RGB(0, 0, 0));
    HPEN   border = CreatePen(PS_SOLID, 1, RGB(72, 72, 72));
    HPEN   base   = CreatePen(PS_SOLID, 1, RGB(112, 112, 112));
    HPEN   good   = CreatePen(PS_SOLID, 1, RGB(0, 224, 0));
    HPEN   bad    = CreatePen(PS_SOLID, 1, RGB(232, 48, 48));
    HPEN   old    = (HPEN)SelectObject(dc, border);
    int    y_base = CerfTpUiRatioToY(CERF_TP_UNITY);
    int    count, i;

    rc.left = 0; rc.top = 0; rc.right = CERF_TPUI_W; rc.bottom = CERF_TPUI_H;
    FillRect(dc, &rc, bg);

    MoveToEx(dc, 0, 0, NULL);
    LineTo(dc, CERF_TPUI_W - 1, 0);
    LineTo(dc, CERF_TPUI_W - 1, CERF_TPUI_H - 1);
    LineTo(dc, 0, CERF_TPUI_H - 1);
    LineTo(dc, 0, 0);

    SelectObject(dc, base);
    MoveToEx(dc, CERF_TPUI_PLOT_X, y_base, NULL);
    LineTo(dc, CERF_TPUI_PLOT_X + CERF_TPUI_PLOT_W, y_base);

    count = CerfTickProfilerSnapshot(samples, CERF_TP_SAMPLES);
    for (i = 0; i < count; ++i) {
        DWORD ratio = samples[i];
        DWORD dev   = (ratio > CERF_TP_UNITY) ? (ratio - CERF_TP_UNITY)
                                              : (CERF_TP_UNITY - ratio);
        int   x     = CERF_TPUI_PLOT_X + (CERF_TPUI_PLOT_W - count) + i;
        int   y     = CerfTpUiRatioToY(ratio);
        SelectObject(dc, (dev > CERF_TPUI_TOLERANCE) ? bad : good);
        MoveToEx(dc, x, y_base, NULL);
        LineTo(dc, x, (y < y_base) ? y - 1 : y + 1);
    }

    SelectObject(dc, old);
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
    HBITMAP bmp = CreateCompatibleBitmap(dc, CERF_TPUI_W, CERF_TPUI_H);
    HBITMAP old;
    if (mem && bmp) {
        old = (HBITMAP)SelectObject(mem, bmp);
        CerfTpUiPaintChart(mem);
        BitBlt(dc, 0, 0, CERF_TPUI_W, CERF_TPUI_H, mem, 0, 0, SRCCOPY);
        SelectObject(mem, old);
    } else {
        CerfTpUiPaintChart(dc);
    }
    if (bmp) DeleteObject(bmp);
    if (mem) DeleteDC(mem);
    EndPaint(w, &ps);
}

static LRESULT CALLBACK CerfTpUiWndProc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT:
        CerfTpUiPaint(w);
        return 0;
    case WM_TIMER:
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
    HINSTANCE inst = GetModuleHandleW(NULL);
    WNDCLASSW wc;
    HWND      w;
    int       x = GetSystemMetrics(SM_CXSCREEN) - CERF_TPUI_W - CERF_TPUI_RIGHT_MARGIN;
    int       y = GetSystemMetrics(SM_CYSCREEN) - CERF_TPUI_BOTTOM_GAP - CERF_TPUI_H;

    if (x < 0) x = 0;
    if (y < 0) y = 0;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = CerfTpUiWndProc;
    wc.hInstance     = inst;
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
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
    return w;
}

static DWORD WINAPI CerfTpUiThread(LPVOID) {
    MSG  msg;
    HWND w = CerfTpUiCreateWindow();
    if (!w) return 0;
    CERF_LOG("cerf_guest: tickprof ui up");
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
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
