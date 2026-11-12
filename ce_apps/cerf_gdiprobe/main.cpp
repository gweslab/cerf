#include "probe.h"

typedef ATOM (WINAPI *PFN_RegisterClassW)(const WNDCLASSW*);
typedef HWND (WINAPI *PFN_CreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int,
                                           HWND, HMENU, HINSTANCE, LPVOID);
typedef BOOL (WINAPI *PFN_DestroyWindow)(HWND);
typedef int  (WINAPI *PFN_ReleaseDC)(HWND, HDC);

static HWND OpenProbeWindow(HINSTANCE inst, int w, int h) {
    PFN_RegisterClassW  reg = (PFN_RegisterClassW)ProbeSym(L"RegisterClassW");
    PFN_CreateWindowExW cwx = (PFN_CreateWindowExW)ProbeSym(L"CreateWindowExW");
    WNDCLASSW           wc;
    BYTE*               raw = (BYTE*)&wc;
    DWORD               i;
    if (!reg || !cwx) return NULL;
    for (i = 0; i < sizeof(wc); ++i) raw[i] = 0;
    wc.lpfnWndProc   = (WNDPROC)ProbeSym(L"DefWindowProcW");
    wc.hInstance     = inst;
    wc.lpszClassName = L"CerfGdiProbe";
    if (!wc.lpfnWndProc || !reg(&wc)) return NULL;
    return cwx(WS_EX_TOPMOST, L"CerfGdiProbe", L"CerfGdiProbe", WS_POPUP | WS_VISIBLE, 0, 0,
               w, h, NULL, NULL, inst, NULL);
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE, LPWSTR cmd, int) {
    int               first = 1, w = 640, h = 240;
    HWND              window;
    PFN_DestroyWindow destroy;
    PFN_ReleaseDC     release;
    if (!ProbeLoadGdi()) {
        Say(L"missing gdi export", 0, 0);
        return 1;
    }
    Say(L"optional sblt/mblt", (DWORD)(g_probe.sblt != NULL), (DWORD)(g_probe.mblt != NULL));
    Say(L"optional timg/grad", (DWORD)(g_probe.timg != NULL), (DWORD)(g_probe.grad != NULL));
    Say(L"optional alpha/pbrush", (DWORD)(g_probe.alpha != NULL),
        (DWORD)(g_probe.pbrush != NULL));
    if (cmd && cmd[0] >= L'1' && cmd[0] <= L'9') first = cmd[0] - L'0';
    destroy = (PFN_DestroyWindow)ProbeSym(L"DestroyWindow");
    release = (PFN_ReleaseDC)ProbeSym(L"ReleaseDC");
    g_probe.screen = g_probe.getdc(NULL);
    if (g_probe.caps) {
        const int sw = g_probe.caps(g_probe.screen, HORZRES);
        const int sh = g_probe.caps(g_probe.screen, VERTRES);
        if (sw > 0 && sw < w) w = sw;
        if (sh > 0 && sh < h) h = sh;
    }
    Say(L"probe window w/h", (DWORD)w, (DWORD)h);
    window = OpenProbeWindow(inst, w, h);
    if (!window || !destroy || !release) {
        Say(L"probe window failed", GetLastError(), 0);
        if (release) release(NULL, g_probe.screen);
        return 1;
    }
    g_probe.target   = g_probe.getdc(window);
    g_probe.target_w = w;
    g_probe.target_h = h;
    Sleep(1000);
    if (first <= 1) { VerifyOverhang(1); VerifyOverhang(-1); }
    if (first <= 1) { VerifyOverhangScreen(1); VerifyOverhangScreen(-1); }
    if (first <= 1) OverhangBySourceKind();
    if (first <= 1) { SourceOverhang(8, 1);  SourceOverhang(8, -1); }
    if (first <= 2) { SourceOverhang(1, 1);  SourceOverhang(4, 1); }
    if (first <= 3) { SourceOverhang(24, 1); SourceOverhang(16, -1); }
    if (first <= 4) MaskOverhang();
    if (first <= 5) IndexedDestinations();
    if (first <= 6) ScreenOverhang();
    if (first <= 7) WideSameSurface();
    if (first <= 8) WideRows();
    Say(L"all done", (DWORD)first, 0);
    release(window, g_probe.target);
    release(NULL, g_probe.screen);
    destroy(window);
    return 0;
}
