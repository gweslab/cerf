/* CerfDemo - shell for the bundled demo ROM: fade-in bokeh desktop + a
   topmost Win2000-style About dialog (banner, version, expandable system
   stats, cmd link). Pure Win32/GDI, links coredll.
   Build: tools/build_ce_app.ps1 -> CerfDemo.exe. */

#include "cerf_demo.h"
#include "band_data.h"
#include "cmdicon_data.h"

#ifndef ANTIALIASED_QUALITY
#define ANTIALIASED_QUALITY 4
#endif

#define BG_CLASS   TEXT("CerfBg")
#define DLG_CLASS  TEXT("CerfDlg")
#define ID_DETAILS 1001
#define ID_EDIT    1002
#define BANNER_H   CERF_BAND_RGB_H
#define DLG_W      412
#define DLG_COL_H  244
#define DLG_EXP_H  452
#define STARTUP_MS 650    /* hero reveal: clipped band -> full collapsed */
#define TOGGLE_MS  220    /* details expand / collapse, near-native feel */

/* IOCTL_HAL_REBOOT = CTL_CODE(FILE_DEVICE_HAL 0x101, 15, METHOD_BUFFERED,
   FILE_ANY_ACCESS) = 0x0101003C (pkfuncs.h); KernelIoControl: coredll export. */
#define IOCTL_HAL_REBOOT 0x0101003Cu
extern BOOL KernelIoControl(DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD);

static const TCHAR* DLG_TITLE = TEXT("CERF");
static const TCHAR* LINK_TEXT = TEXT("Run command line prompt");

static HINSTANCE g_inst;
static int      g_sw, g_sh;
HWND            g_dlg;     /* non-static on purpose: desktop.c links to it */
static HWND     g_btn, g_edit;
static int      g_expanded;
static RECT     g_linkrect;
static HFONT    g_ui, g_ui_bold, g_link;
static HDC      g_banddc, g_cmddc;
static HBITMAP  g_bandbmp, g_cmdbmp;
DWORD           g_start;   /* non-static on purpose: desktop.c links to it */
static int      g_anim_active, g_anim_centered, g_anim_target_exp;
static int      g_anim_h0, g_anim_h1, g_anim_top, g_anim_dur;
static DWORD    g_anim_start;

HBITMAP MakeDib32(int w, int h, unsigned int** bits) {
    BITMAPINFO bi;
    HDC dc = GetDC(NULL);
    HBITMAP bmp;
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = w;
    bi.bmiHeader.biHeight      = -h;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void**)bits, NULL, 0);
    ReleaseDC(NULL, dc);
    return bmp;
}

/* --- embedded image DCs ----------------------------------------------- */
static void BuildAssets(void) {
    unsigned int* bits;
    HDC mem = GetDC(NULL);
    COLORREF face = GetSysColor(COLOR_BTNFACE);
    int fr = GetRValue(face), fg = GetGValue(face), fb = GetBValue(face);
    int i, n;

    g_banddc  = CreateCompatibleDC(mem);
    g_bandbmp = MakeDib32(CERF_BAND_RGB_W, CERF_BAND_RGB_H, &bits);
    SelectObject(g_banddc, g_bandbmp);
    n = CERF_BAND_RGB_W * CERF_BAND_RGB_H;
    for (i = 0; i < n; i++) {
        const unsigned char* s = &cerf_band_rgb[i * 3];
        bits[i] = ((unsigned)s[0] << 16) | ((unsigned)s[1] << 8) | s[2];
    }

    g_cmddc  = CreateCompatibleDC(mem);
    g_cmdbmp = MakeDib32(CERF_CMD_RGBA_W, CERF_CMD_RGBA_H, &bits);
    SelectObject(g_cmddc, g_cmdbmp);
    n = CERF_CMD_RGBA_W * CERF_CMD_RGBA_H;
    for (i = 0; i < n; i++) {
        const unsigned char* s = &cerf_cmd_rgba[i * 4];
        int a = s[3];
        int r = (s[0] * a + fr * (255 - a)) / 255;
        int g = (s[1] * a + fg * (255 - a)) / 255;
        int b = (s[2] * a + fb * (255 - a)) / 255;
        bits[i] = ((unsigned)r << 16) | ((unsigned)g << 8) | (unsigned)b;
    }
    ReleaseDC(NULL, mem);
}

/* --- dialog ----------------------------------------------------------- */
static void LaunchCmd(HWND h) {
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcess(TEXT("cmd.exe"), NULL, NULL, NULL, FALSE, 0,
                      NULL, NULL, NULL, &pi)) {
        if (pi.hThread)  CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
    } else {
        MessageBox(h, TEXT("cmd.exe is not present in this ROM. Add the ")
                      TEXT("Console / Command Shell component and rebuild."),
                   TEXT("CERF"), MB_OK | MB_ICONINFORMATION);
    }
}

static void BuildStats(TCHAR* buf) {
    OSVERSIONINFO osv;
    MEMORYSTATUS ms;
    SYSTEM_INFO si;
    osv.dwOSVersionInfoSize = sizeof(osv); GetVersionEx(&osv);
    ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);
    GetSystemInfo(&si);
    wsprintf(buf,
        TEXT("CE Runtime Foundation - guest diagnostics\r\n\r\n")
        TEXT("OS:        Windows CE %u.%u  (build %u)\r\n")
        TEXT("Screen:    %d x %d px\r\n")
        TEXT("Memory:    %u KB total / %u KB free\r\n")
        TEXT("CPUs:      %u\r\n")
        TEXT("Page size: %u bytes\r\n")
        TEXT("Platform:  CERF virtual ARM"),
        osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber,
        GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        (unsigned)(ms.dwTotalPhys / 1024), (unsigned)(ms.dwAvailPhys / 1024),
        si.dwNumberOfProcessors, si.dwPageSize);
}

/* Position children + repaint against the window's CURRENT client size.
   Caller guarantees the window is already at its final height. */
static void LayoutDlg(HWND h, int exp) {
    RECT rc;
    g_expanded = exp;
    GetClientRect(h, &rc);
    if (g_edit) {
        if (exp) {
            MoveWindow(g_edit, 16, BANNER_H + 14, rc.right - 32,
                       rc.bottom - (BANNER_H + 14) - 104, TRUE);
            ShowWindow(g_edit, SW_SHOW);
        } else {
            ShowWindow(g_edit, SW_HIDE);
        }
    }
    if (g_btn) {
        MoveWindow(g_btn, 22, rc.bottom - 42, 116, 30, TRUE);
        ShowWindow(g_btn, SW_SHOW);
    }
    InvalidateRect(h, NULL, TRUE);
}

/* easeOutCubic on a 0..256 parameter: quick start, gentle settle. */
static int EaseOut(int t) {
    int inv = 256 - t;
    int cube = (inv * inv / 256) * inv / 256;
    return 256 - cube;
}

/* Begin a height animation. centered != 0: recompute centred Y each tick
   (startup reveal grows from screen centre); else hold top fixed
   (expand/collapse). Children stay hidden and WM_PAINT shows the band
   alone until the final tick lays the target content out. */
static void StartDlgAnim(int h0, int h1, int centered, int top,
                         int dur, int target_exp) {
    g_anim_h0 = h0; g_anim_h1 = h1;
    g_anim_centered = centered; g_anim_top = top;
    g_anim_dur = dur; g_anim_target_exp = target_exp;
    g_anim_start = GetTickCount();
    g_anim_active = 1;
    if (g_btn)  ShowWindow(g_btn, SW_HIDE);
    if (g_edit) ShowWindow(g_edit, SW_HIDE);
}

static void TickDlgAnim(HWND h) {
    DWORD now; int el, hh, x, y;
    if (!g_anim_active || !h) return;
    now = GetTickCount();
    el = (int)(now - g_anim_start);
    if (el < 0) el = 0;
    x = (g_sw - DLG_W) / 2;
    if (el >= g_anim_dur) {
        hh = g_anim_h1;
        y = g_anim_centered ? (g_sh - hh) / 2 : g_anim_top;
        SetWindowPos(h, HWND_TOPMOST, x, y, DLG_W, hh,
                     SWP_NOACTIVATE | SWP_SHOWWINDOW);
        g_anim_active = 0;
        LayoutDlg(h, g_anim_target_exp);
        return;
    }
    hh = g_anim_h0 + (g_anim_h1 - g_anim_h0)
         * EaseOut(el * 256 / g_anim_dur) / 256;
    y = g_anim_centered ? (g_sh - hh) / 2 : g_anim_top;
    SetWindowPos(h, HWND_TOPMOST, x, y, DLG_W, hh,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
    InvalidateRect(h, NULL, TRUE);
}

static void DrawWelcome(HDC dc, int x, int y) {
    SIZE sz;
    const TCHAR* a = TEXT("Welcome to ");
    const TCHAR* b = TEXT("CE Runtime Foundation");
    const TCHAR* c = TEXT("!");
    SetTextColor(dc, GetSysColor(COLOR_BTNTEXT));
    SelectObject(dc, g_ui);
    ExtTextOut(dc, x, y, 0, NULL, a, lstrlen(a), NULL);
    GetTextExtentPoint32(dc, a, lstrlen(a), &sz); x += sz.cx;
    SelectObject(dc, g_ui_bold);
    ExtTextOut(dc, x, y, 0, NULL, b, lstrlen(b), NULL);
    GetTextExtentPoint32(dc, b, lstrlen(b), &sz); x += sz.cx;
    SelectObject(dc, g_ui);
    ExtTextOut(dc, x, y, 0, NULL, c, lstrlen(c), NULL);
}

static LRESULT CALLBACK DlgProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: {
        TCHAR stats[512];
        RECT rc;
        GetClientRect(h, &rc);
        BuildStats(stats);
        g_edit = CreateWindowEx(0, TEXT("EDIT"), stats,
            WS_CHILD | ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_BORDER,
            0, 0, 10, 10, h, (HMENU)ID_EDIT, g_inst, NULL);
        if (g_edit && g_ui)
            SendMessage(g_edit, WM_SETFONT, (WPARAM)g_ui, TRUE);
        g_btn = CreateWindow(TEXT("BUTTON"), TEXT("Details"),
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            22, rc.bottom - 42, 116, 30, h, (HMENU)ID_DETAILS, g_inst, NULL);
        return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT d = (LPDRAWITEMSTRUCT)lp;
        if (d->CtlID == ID_DETAILS) {
            RECT cr, tr;
            UINT cst = (g_expanded ? DFCS_SCROLLUP : DFCS_SCROLLDOWN) |
                       ((d->itemState & ODS_SELECTED) ? DFCS_PUSHED : 0);
            FillRect(d->hDC, &d->rcItem, GetSysColorBrush(COLOR_BTNFACE));
            cr.left = d->rcItem.left + 4;
            cr.top  = (d->rcItem.top + d->rcItem.bottom) / 2 - 8;
            cr.right = cr.left + 16; cr.bottom = cr.top + 16;
            DrawFrameControl(d->hDC, &cr, DFC_SCROLL, cst);
            tr = d->rcItem; tr.left = cr.right + 8;
            SetBkMode(d->hDC, TRANSPARENT);
            SelectObject(d->hDC, g_ui);
            SetTextColor(d->hDC, GetSysColor(COLOR_BTNTEXT));
            DrawText(d->hDC, TEXT("Details"), -1, &tr,
                     DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == ID_DETAILS && !g_anim_active) {
            RECT wr;
            int cur;
            GetWindowRect(h, &wr);
            cur = wr.bottom - wr.top;       /* hold top fixed, grow/shrink */
            if (!g_expanded)
                StartDlgAnim(cur, DLG_EXP_H, 0, wr.top, TOGGLE_MS, 1);
            else
                StartDlgAnim(cur, DLG_COL_H, 0, wr.top, TOGGLE_MS, 0);
        }
        return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC edc = (HDC)wp;
        SetBkColor(edc, GetSysColor(COLOR_WINDOW));
        SetTextColor(edc, GetSysColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
    }
    case WM_LBUTTONDOWN: {
        POINT pt; pt.x = LOWORD(lp); pt.y = HIWORD(lp);
        if (g_expanded && PtInRect(&g_linkrect, pt)) LaunchCmd(h);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc;
        GetClientRect(h, &rc);
        if (g_banddc)
            StretchBlt(dc, 0, 0, rc.right, BANNER_H, g_banddc,
                       0, 0, CERF_BAND_RGB_W, CERF_BAND_RGB_H, SRCCOPY);
        SetBkMode(dc, TRANSPARENT);
        if (g_anim_active) {
            /* mid-animation: band only; children hidden, content not yet laid out */
        } else if (!g_expanded) {
            DrawWelcome(dc, 22, BANNER_H + 24);
        } else {
            int iy = rc.bottom - 90;
            SIZE sz;
            if (g_cmddc)
                BitBlt(dc, 22, iy, CERF_CMD_RGBA_W, CERF_CMD_RGBA_H,
                       g_cmddc, 0, 0, SRCCOPY);
            SelectObject(dc, g_link);
            SetTextColor(dc, RGB(20, 60, 180));
            ExtTextOut(dc, 22 + CERF_CMD_RGBA_W + 12, iy + 8, 0, NULL,
                       LINK_TEXT, lstrlen(LINK_TEXT), NULL);
            GetTextExtentPoint32(dc, LINK_TEXT, lstrlen(LINK_TEXT), &sz);
            g_linkrect.left   = 22 + CERF_CMD_RGBA_W + 12;
            g_linkrect.top    = iy + 8;
            g_linkrect.right  = g_linkrect.left + sz.cx;
            g_linkrect.bottom = g_linkrect.top + sz.cy;
        }
        EndPaint(h, &ps);
        return 0;
    }
    case WM_CLOSE:
        if (MessageBox(h, TEXT("Reset the device?"), TEXT("CERF"),
                       MB_YESNO | MB_ICONQUESTION) == IDYES)
            KernelIoControl(IOCTL_HAL_REBOOT, NULL, 0, NULL, 0, NULL);
        return 0;
    }
    return DefWindowProc(h, m, wp, lp);
}

/* --- startup ---------------------------------------------------------- */
static HFONT MakeFont(int height, int weight, int underline) {
    LOGFONT lf;
    ZeroMemory(&lf, sizeof(lf));
    lf.lfHeight = height;
    lf.lfWeight = weight;
    lf.lfUnderline = (BYTE)underline;
    lf.lfQuality = ANTIALIASED_QUALITY;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
    lstrcpy(lf.lfFaceName, TEXT("Tahoma"));
    return CreateFontIndirect(&lf);
}

/* Full Windows 2000 "Windows Standard" classic scheme: warm 212/208/200
   face across every classic system index 0..24, so nothing the OS draws
   (menus, tooltips, borders, highlight, scrollbars) keeps a cold default. */
static void ApplyClassicTheme(void) {
    static const int idx[] = {
        COLOR_SCROLLBAR, COLOR_BACKGROUND, COLOR_ACTIVECAPTION,
        COLOR_INACTIVECAPTION, COLOR_MENU, COLOR_WINDOW, COLOR_WINDOWFRAME,
        COLOR_MENUTEXT, COLOR_WINDOWTEXT, COLOR_CAPTIONTEXT, COLOR_ACTIVEBORDER,
        COLOR_INACTIVEBORDER, COLOR_APPWORKSPACE, COLOR_HIGHLIGHT,
        COLOR_HIGHLIGHTTEXT, COLOR_BTNFACE, COLOR_BTNSHADOW, COLOR_GRAYTEXT,
        COLOR_BTNTEXT, COLOR_INACTIVECAPTIONTEXT, COLOR_BTNHIGHLIGHT,
        COLOR_3DDKSHADOW, COLOR_3DLIGHT, COLOR_INFOTEXT, COLOR_INFOBK,
    };
    static const COLORREF clr[] = {
        RGB(212,208,200), RGB( 58,110,165), RGB( 10, 36,106),
        RGB(128,128,128), RGB(212,208,200), RGB(255,255,255), RGB(  0,  0,  0),
        RGB(  0,  0,  0), RGB(  0,  0,  0), RGB(255,255,255), RGB(212,208,200),
        RGB(212,208,200), RGB(128,128,128), RGB( 10, 36,106),
        RGB(255,255,255), RGB(212,208,200), RGB(128,128,128), RGB(128,128,128),
        RGB(  0,  0,  0), RGB(212,208,200), RGB(255,255,255),
        RGB( 64, 64, 64), RGB(212,208,200), RGB(  0,  0,  0), RGB(255,255,225),
    };
    SetSysColors(sizeof(idx) / sizeof(idx[0]), idx, clr);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPTSTR cmd, int show) {
    WNDCLASS bc, dc;
    HWND bg;
    MSG msg;

    g_inst = hInst;
    g_sw = GetSystemMetrics(SM_CXSCREEN);
    g_sh = GetSystemMetrics(SM_CYSCREEN);

    ApplyClassicTheme();
    InitDiscs();
    BuildAssets();
    g_ui      = MakeFont(17, FW_NORMAL, 0);
    g_ui_bold = MakeFont(17, FW_BOLD,   0);
    g_link    = MakeFont(16, FW_NORMAL, 1);

    ZeroMemory(&bc, sizeof(bc));
    bc.lpfnWndProc   = BgProc;
    bc.hInstance     = hInst;
    bc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    bc.lpszClassName = BG_CLASS;
    RegisterClass(&bc);

    ZeroMemory(&dc, sizeof(dc));
    dc.lpfnWndProc   = DlgProc;
    dc.hInstance     = hInst;
    dc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    dc.lpszClassName = DLG_CLASS;
    RegisterClass(&dc);

    bg = CreateWindow(BG_CLASS, TEXT("CERF"), WS_POPUP | WS_VISIBLE,
                      0, 0, g_sw, g_sh, NULL, NULL, hInst, NULL);
    if (!bg) return 1;

    /* Created hidden at full collapsed size so WM_CREATE lays children out
       against the final client metrics; then shrunk to a band-only height
       and shown, and the main loop animates the reveal back up to DLG_COL_H. */
    g_dlg = CreateWindowEx(WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
                           DLG_CLASS, DLG_TITLE,
                           WS_POPUP | WS_CAPTION | WS_SYSMENU,
                           (g_sw - DLG_W) / 2, (g_sh - DLG_COL_H) / 2,
                           DLG_W, DLG_COL_H, NULL, NULL, hInst, NULL);

    ShowWindow(bg, show);
    UpdateWindow(bg);

    if (g_dlg) {
        RECT wr, cr;
        int ncv, hband;
        GetWindowRect(g_dlg, &wr);
        GetClientRect(g_dlg, &cr);
        ncv = (wr.bottom - wr.top) - (cr.bottom - cr.top);  /* caption+frame */
        hband = ncv + BANNER_H;                             /* client == band */
        SetWindowPos(g_dlg, HWND_TOPMOST, (g_sw - DLG_W) / 2,
                     (g_sh - hband) / 2, DLG_W, hband,
                     SWP_NOACTIVATE | SWP_SHOWWINDOW);
        ShowWindow(g_dlg, SW_SHOWNA);
        SetForegroundWindow(g_dlg);     /* active (blue) caption, not bg */
        StartDlgAnim(hband, DLG_COL_H, 1, 0, STARTUP_MS, 0);
    }
    g_start = GetTickCount();

    for (;;) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) goto done;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        TickDlgAnim(g_dlg);
        PresentBg(bg);
    }
done:
    if (g_ui)      DeleteObject(g_ui);
    if (g_ui_bold) DeleteObject(g_ui_bold);
    if (g_link)    DeleteObject(g_link);
    if (g_banddc)  DeleteDC(g_banddc);
    if (g_cmddc)   DeleteDC(g_cmddc);
    if (g_bandbmp) DeleteObject(g_bandbmp);
    if (g_cmdbmp)  DeleteObject(g_cmdbmp);
    return (int)msg.wParam;
}
