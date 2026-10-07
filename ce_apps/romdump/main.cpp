/* romdump wizard shell: work-area window, opaque bottom nav panel, step
   switching, vertical scroll, custom progress bar. Steps live in step_*.cpp. */

#include "romdump.h"

/* Preset table is CPU-arch specific (build_ce_app.ps1 defines MIPS for -Arch
   mips, ARM/_ARM_ for -Arch arm). Custom (base/size by hand) is common. */
const Preset kPresets[] = {
#if defined(MIPS)
    /* MP790 ROM, ROMHDR VA 0x9F6FC504: physfirst 0x9E000000, physlast 0x9F70017C. */
    { L"VR41xx",
      L"NEC MP790",
      0x1E000000u, 24, 0 },
    /* Universal MIPS boot-ROM band PA 0x1F000000-0x1FFFFFFF, 16 MB, contains
       reset vector 0x1FC00000. Covers VR41xx (Vr4102-um.pdf Table 5-6/5-8:
       ROMCS0+ROMCS1) and TX3912/PR31xxx kseg0 (PA = VA & 0x1FFFFFFF). */
    { L"VR41xx/TX3912",
      L"NEC MP700, Toricomail/Cassiopeia EM500, Velo1/Nino300, Sharp HC-4100",
      0x1F000000u, 16, 0 },
    /* Velo 1 physfirst = PA 0x1F400000 (its ROMHDR); tighter 8 MB read. */
    { L"TX3912 Philips Velo 1", L"", 0x1F400000u, 8, 0 },
#else
    /* base = PA 0 (reset vector) for all. PXA255 stalls the bus on an
       unpopulated static chip-select, so it is sized to nCS0 (64 MB) only. */
    { L"SA-11x0",     L"", 0x00000000u, 512, 0 },
    { L"PXA25x/27x",  L"", 0x00000000u, 64,  0 },
    { L"S3C2410",     L"", 0x00000000u, 768, 0 },
    { L"ARM720",      L"", 0x00000000u, 256, 0 },
#endif
    { L"Custom",      L"", 0x00000000u, 0, 1 },
};
const int kNumPresets = (int)(sizeof(kPresets) / sizeof(kPresets[0]));

RECT ContentRect(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    rc.bottom -= PANEL_H;
    return rc;
}

FARPROC CoreProc(LPCWSTR name) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    FARPROC p    = core ? GetProcAddressW(core, name) : NULL;
    if (core) FreeLibrary(core);
    return p;
}

void AppLog(AppState* st, LPCWSTR text) {
    HWND log = GetDlgItem(st->hwnd, ID_LOG);
    int  len;
    if (!log) return;
    len = GetWindowTextLengthW(log);
    SendMessageW(log, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(log, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageW(log, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    SendMessageW(log, EM_SCROLLCARET, 0, 0);
}

static void LayoutCurrent(AppState* st) {
    RECT area = ContentRect(st->hwnd);
    int  h = 0;
    switch (st->step) {
    case STEP_PRESET: h = StepPresetLayout(st, area); break;
    case STEP_CONFIG: h = StepConfigLayout(st, area); break;
    case STEP_DUMP:   h = StepDumpLayout(st, area);   break;
    }
    st->content_h = h;
    st->view_h    = area.bottom - area.top;
}

static void SyncScrollbar(AppState* st) {
    SCROLLINFO si;
    int maxy = st->content_h - st->view_h;
    if (maxy < 0) maxy = 0;
    if (st->scroll_y > maxy) st->scroll_y = maxy;
    if (st->scroll_y < 0)    st->scroll_y = 0;
    memset(&si, 0, sizeof(si));
    si.cbSize = sizeof(si);
    si.fMask  = SIF_RANGE | SIF_PAGE | SIF_POS;   /* no DISABLENOSCROLL: auto-hide */
    si.nMin   = 0;
    si.nMax   = (st->content_h > 0) ? st->content_h - 1 : 0;
    si.nPage  = (UINT)(st->view_h > 0 ? st->view_h : 1);
    si.nPos   = st->scroll_y;
    SetScrollInfo(st->hwnd, SB_VERT, &si, TRUE);
}

static void RefreshNav(AppState* st) {
    LPCWSTR t = (st->step == STEP_PRESET) ? L"Next"
              : (st->step == STEP_CONFIG) ? L"Start Dump"
              : (st->running ? L"Stop" : L"Exit");
    SetWindowTextW(GetDlgItem(st->hwnd, ID_NAV), t);
    ShowWindow(GetDlgItem(st->hwnd, ID_CANCEL),
               st->step == STEP_DUMP ? SW_HIDE : SW_SHOW);
}

static void PositionPanel(AppState* st) {
    RECT rc;
    int  py, by;
    GetClientRect(st->hwnd, &rc);
    py = rc.bottom - PANEL_H;
    by = py + (PANEL_H - NAV_H) / 2;
    MoveWindow(st->panel, 0, py, rc.right, PANEL_H, TRUE);
    MoveWindow(GetDlgItem(st->hwnd, ID_NAV),
               rc.right - NAV_W - BTN_MARGIN, by, NAV_W, NAV_H, TRUE);
    MoveWindow(GetDlgItem(st->hwnd, ID_CANCEL), BTN_MARGIN, by, NAV_W, NAV_H, TRUE);
}

static void ShowStep(AppState* st, int step, BOOL show) {
    switch (step) {
    case STEP_PRESET: StepPresetShow(st, show); break;
    case STEP_CONFIG: StepConfigShow(st, show); break;
    case STEP_DUMP:   StepDumpShow(st, show);   break;
    }
}

static void GoToStep(AppState* st, int step) {
    ShowStep(st, st->step, FALSE);
    st->step     = step;
    st->scroll_y = 0;
    if (step == STEP_CONFIG) StepConfigEnter(st);
    ShowStep(st, step, TRUE);
    RefreshNav(st);
    LayoutCurrent(st);
    SyncScrollbar(st);
    InvalidateRect(st->hwnd, NULL, TRUE);
    if (step == STEP_DUMP) { StepDumpEnter(st); RefreshNav(st); }
}

static void OnNav(AppState* st) {
    if (st->step == STEP_PRESET) {
        if (StepPresetOnNext(st)) GoToStep(st, STEP_CONFIG);
    } else if (st->step == STEP_CONFIG) {
        if (StepConfigOnNext(st)) GoToStep(st, STEP_DUMP);
    } else if (st->running) {
        if (MessageBoxW(st->hwnd,
                        L"Stop the dump? You can still read the log afterwards.",
                        L"CERF ROM dumper", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            st->cancel = 1;
            if (st->seg_event) SetEvent(st->seg_event);  /* wake a segment wait */
        }                                                /* WM_APP_DONE finishes */
    } else {
        DestroyWindow(st->hwnd);
    }
}

/* Opaque bottom strip: covers content scrolled into the panel band and paints
   the progress bar on the dump step. Reads AppState from its parent. */
static LRESULT CALLBACK PanelProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_ERASEBKGND) return 1;
    if (msg == WM_PAINT) {
        AppState*   st = (AppState*)GetWindowLongW(GetParent(hwnd), WNDX_STATE);
        PAINTSTRUCT ps;
        HDC         dc = BeginPaint(hwnd, &ps);
        RECT        rc;
        GetClientRect(hwnd, &rc);
        FillRect(dc, &rc, (HBRUSH)GetStockObject(LTGRAY_BRUSH));
        if (st && st->step == STEP_DUMP) StepDumpPaintProgress(st, dc, rc);
        EndPaint(hwnd, &ps);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    AppState* st = (AppState*)GetWindowLongW(hwnd, WNDX_STATE);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lp;
        AppState* s = (AppState*)cs->lpCreateParams;
        HINSTANCE hi = cs->hInstance;
        HWND c;
        SetWindowLongW(hwnd, WNDX_STATE, (LONG)s);
        s->hwnd = hwnd;
        StepPresetCreate(s, hi);
        StepConfigCreate(s, hi);
        StepDumpCreate(s, hi);
        s->panel = CreateWindowExW(0, L"CerfPanel", NULL,
                                   WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                   0, 0, 0, 0, hwnd, NULL, hi, NULL);
        CreateWindowExW(0, L"BUTTON", L"Cancel",
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_PUSHBUTTON,
                        0, 0, 0, 0, hwnd, (HMENU)ID_CANCEL, hi, NULL);
        CreateWindowExW(0, L"BUTTON", L"Next",
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | BS_DEFPUSHBUTTON,
                        0, 0, 0, 0, hwnd, (HMENU)ID_NAV, hi, NULL);
        /* Panel, buttons and step controls overlap in the bottom band;
           WS_CLIPSIBLINGS makes each child paint only its own rect. */
        for (c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
            SetWindowLongW(c, GWL_STYLE, GetWindowLongW(c, GWL_STYLE) | WS_CLIPSIBLINGS);
            SetWindowPos(c, NULL, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        }
        /* Explicit z-order: panel above the step controls, buttons above the panel. */
        SetWindowPos(s->panel, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        SetWindowPos(GetDlgItem(hwnd, ID_CANCEL), HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        SetWindowPos(GetDlgItem(hwnd, ID_NAV), HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        StepConfigShow(s, FALSE);
        StepDumpShow(s, FALSE);
        s->step = STEP_PRESET;
        PositionPanel(s);
        RefreshNav(s);
        LayoutCurrent(s);
        SyncScrollbar(s);
        SetFocus(GetDlgItem(hwnd, ID_PRESETLIST));
        return 0;
    }

    case WM_SIZE:
        PositionPanel(st);
        LayoutCurrent(st);
        SyncScrollbar(st);
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;

    case WM_VSCROLL: {
        int y = st->scroll_y, page = st->view_h, maxy = st->content_h - st->view_h;
        if (maxy < 0) maxy = 0;
        switch (LOWORD(wp)) {
        case SB_LINEUP:        y -= 16;   break;
        case SB_LINEDOWN:      y += 16;   break;
        case SB_PAGEUP:        y -= page; break;
        case SB_PAGEDOWN:      y += page; break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: y = HIWORD(wp); break;
        }
        if (y < 0) y = 0;
        if (y > maxy) y = maxy;
        if (y != st->scroll_y) {
            st->scroll_y = y;
            SetScrollPos(hwnd, SB_VERT, y, TRUE);
            LayoutCurrent(st);
        }
        return 0;
    }

    case WM_COMMAND:
        if (!st) return 0;
        if (LOWORD(wp) == ID_NAV    && HIWORD(wp) == BN_CLICKED) { OnNav(st); return 0; }
        if (LOWORD(wp) == ID_CANCEL && HIWORD(wp) == BN_CLICKED) { DestroyWindow(hwnd); return 0; }
        if (st->step == STEP_CONFIG && StepConfigCommand(st, wp, lp)) return 0;
        if (st->step == STEP_DUMP   && StepDumpCommand(st, wp, lp))   return 0;
        return 0;

    case WM_CTLCOLORSTATIC: {                 /* labels + checkbox: white on white */
        HDC dc = (HDC)wp;
        SetBkColor(dc, RGB(255, 255, 255));
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }

    case WM_TIMER:
        if (st && st->step == STEP_DUMP && st->panel)
            InvalidateRect(st->panel, NULL, FALSE);
        return 0;

    case WM_APP_LOG:
    case WM_APP_SEGMENT:
    case WM_APP_STORAGE:
    case WM_APP_DONE:
        if (st) StepDumpOnMessage(st, msg, wp, lp);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static BOOL IsTabbable(HWND h) {
    LONG s = GetWindowLongW(h, GWL_STYLE);
    return (s & WS_TABSTOP) && (s & WS_VISIBLE) && !(s & WS_DISABLED);
}

static HWND NextTabstop(HWND parent, HWND cur, BOOL prev) {
    UINT dir = prev ? GW_HWNDPREV : GW_HWNDNEXT;
    HWND h = cur ? GetWindow(cur, dir) : NULL;
    int  guard = 0;
    while (guard++ < 256) {
        if (!h) {
            h = GetWindow(parent, GW_CHILD);
            if (prev && h) {
                HWND last;
                while ((last = GetWindow(h, GW_HWNDNEXT)) != NULL) h = last;
            }
            if (!h) return NULL;
        }
        if (h == cur) return cur;
        if (IsTabbable(h)) return h;
        h = GetWindow(h, dir);
    }
    return NULL;
}

/* extern "C": /entry:WinMain needs an unmangled symbol; this file is C++. */
extern "C" int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev,
                              LPWSTR cmd, int show) {
    typedef HCURSOR (*LoadCursorFn)(HINSTANCE, LPCWSTR);
    static AppState st;
    WNDCLASSW    wc, pc;
    HWND         hwnd;
    MSG          m;
    LoadCursorFn loadCursor;

    (void)hPrev; (void)cmd;
    memset(&st, 0, sizeof(st));
    st.seg_event = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset, off */
    if (!st.seg_event) return 1;

    memset(&pc, 0, sizeof(pc));
    pc.lpfnWndProc   = PanelProc;
    pc.hInstance     = hInstance;
    pc.hbrBackground = NULL;                 /* PanelProc paints */
    pc.lpszClassName = L"CerfPanel";
    if (!RegisterClassW(&pc)) return 1;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.cbWndExtra    = sizeof(LONG);         /* WNDX_STATE slot */
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    loadCursor       = (LoadCursorFn)CoreProc(L"LoadCursorW");
    wc.hCursor       = loadCursor ? loadCursor(NULL, IDC_ARROW) : NULL;
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"CerfRomDump";
    if (!RegisterClassW(&wc)) return 1;

    /* CW_USEDEFAULT lets the CE shell size the window to the work area, so the
       taskbar stays clear. */
    hwnd = CreateWindowExW(0, L"CerfRomDump", L"CERF ROM dumper",
                           WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_CLIPCHILDREN,
                           CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                           NULL, NULL, hInstance, &st);
    if (!hwnd) return 1;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    while (GetMessageW(&m, NULL, 0, 0)) {
        if (m.message == WM_KEYDOWN &&
            (m.hwnd == hwnd || IsChild(hwnd, m.hwnd))) {
            if (m.wParam == VK_TAB) {
                BOOL back = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                HWND nxt = NextTabstop(hwnd, GetFocus(), back);
                if (nxt) SetFocus(nxt);
                continue;
            }
            if (m.wParam == VK_RETURN) {
                int fid = GetDlgCtrlID(GetFocus());
                if (fid != ID_LOG) {
                    SendMessageW(hwnd, WM_COMMAND,
                                 MAKEWPARAM(ID_NAV, BN_CLICKED),
                                 (LPARAM)GetDlgItem(hwnd, ID_NAV));
                    continue;
                }
            }
        }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}
