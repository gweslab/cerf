/* Wizard step 3: the dump. A read-only log the user can follow (each part logs
   its Start / Success / Failed address), a progress bar in the bottom panel, and
   the segmented pause prompt. On finish the user stays here and reads the log. */

#include "romdump.h"

void StepDumpCreate(AppState* st, HINSTANCE hi) {
    CreateWindowExW(0, L"EDIT", L"",
                    WS_CHILD | WS_BORDER | WS_VSCROLL | WS_TABSTOP |
                    ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                    0, 0, 0, 0, st->hwnd, (HMENU)ID_LOG, hi, NULL);
}

void StepDumpShow(AppState* st, BOOL show) {
    ShowWindow(GetDlgItem(st->hwnd, ID_LOG), show ? SW_SHOW : SW_HIDE);
}

/* The log fills the content area and scrolls its own text, so the outer wizard
   scrollbar is not needed: return the view height. */
int StepDumpLayout(AppState* st, RECT area) {
    int m = 6;
    MoveWindow(GetDlgItem(st->hwnd, ID_LOG),
               area.left + m, area.top + m,
               area.right - area.left - 2 * m,
               area.bottom - area.top - 2 * m, TRUE);
    return area.bottom - area.top;
}

BOOL StepDumpCommand(AppState* st, WPARAM wp, LPARAM lp) {
    (void)st; (void)wp; (void)lp;
    return FALSE;
}

void StepDumpEnter(AppState* st) {
    DWORD tid;
    st->cancel = 0; st->finished = 0; st->ok = 0; st->running = 1;
    st->bytes_done = 0; st->fault_pages = 0; st->cur_pa = st->base;
    st->err[0] = L'\0';
    st->seg_index = 0; st->segs_written = 0; st->seg_continue = 0;
    if (st->seg_event) ResetEvent(st->seg_event);
    SetWindowText(GetDlgItem(st->hwnd, ID_LOG), L"");

    st->thread = CreateThread(NULL, 0, DumpThread, st, 0, &tid);
    if (!st->thread) {
        st->running = 0;
        AppLog(st, L"Failed to start the dump thread.");
        return;
    }
    SetTimer(st->hwnd, 1, 250, NULL);   /* repaint the progress bar */
}

void StepDumpOnMessage(AppState* st, UINT msg, WPARAM wp, LPARAM lp) {
    (void)wp;
    if (msg == WM_APP_LOG) {
        WCHAR* s = (WCHAR*)lp;
        if (s) { AppLog(st, s); LocalFree(s); }
        return;
    }
    if (msg == WM_APP_SEGMENT) {
        WCHAR m[MAX_PATH + 160];
        DWORD n = st->seg_index;
        wsprintfW(m,
                  L"Written 0x%08X - 0x%08X into\n%s.%03u\n\n"
                  L"Copy it off the device if you need to, then continue.\n\n"
                  L"Write the next part (.%03u)?",
                  st->seg_start_pa, st->seg_end_pa, st->outpath,
                  (unsigned)n, (unsigned)(n + 1));
        /* No stops the dump but keeps the app: the worker unwinds and
           WM_APP_DONE shows the stopped notice so the log stays readable. */
        st->seg_continue = (MessageBoxW(st->hwnd, m, L"CERF ROM dumper - segmented",
                                        MB_YESNO | MB_ICONQUESTION) == IDYES) ? 1 : 0;
        SetEvent(st->seg_event);
        return;
    }
    if (msg == WM_APP_STORAGE) {
        WCHAR m[192];
        wsprintfW(m,
                  L"Storage full writing 0x%08X.\n\n"
                  L"Free space or swap the card, then Retry - or Cancel the dump.",
                  st->fail_pa);
        st->storage_retry = (MessageBoxW(st->hwnd, m, L"CERF ROM dumper",
                                         MB_RETRYCANCEL | MB_ICONEXCLAMATION) == IDRETRY)
                            ? 1 : 0;
        SetEvent(st->seg_event);
        return;
    }
    if (msg == WM_APP_DONE) {
        KillTimer(st->hwnd, 1);
        if (st->thread) { CloseHandle(st->thread); st->thread = NULL; }
        st->running = 0;
        SetWindowText(GetDlgItem(st->hwnd, ID_NAV), L"Exit");  /* Stop -> Exit */
        InvalidateRect(st->panel, NULL, FALSE);
        if (st->ok)
            MessageBoxW(st->hwnd,
                        L"Dump complete. Read the log; press Exit when you are done.",
                        L"CERF ROM dumper", MB_OK | MB_ICONINFORMATION);
        else if (st->err[0])
            MessageBoxW(st->hwnd, st->err, L"CERF ROM dumper",
                        MB_OK | MB_ICONEXCLAMATION);
        else
            MessageBoxW(st->hwnd,
                        L"Dump stopped. Read the log; press Exit when you are done.",
                        L"CERF ROM dumper", MB_OK | MB_ICONINFORMATION);
        return;
    }
}

/* Progress bar in the bottom panel, left of the Exit button. CE 2.11 GDI has no
   FrameRect (hollow Rectangle) and FillRect needs a real HBRUSH, not a
   COLOR_xxx pseudo-brush. */
void StepDumpPaintProgress(AppState* st, HDC dc, RECT panel) {
    DWORD pct = st->length
                ? (DWORD)(((__int64)st->bytes_done * 100) / st->length) : 0;
    RECT   fill;
    WCHAR  t[8];
    int    bl = panel.left + 40, br = panel.right - (NAV_W + 2 * BTN_MARGIN);
    int    bt = panel.top + 8,   bb = panel.bottom - 8, inner;
    HGDIOBJ old;
    HBRUSH  green;

    if (br < bl + 10) br = bl + 10;
    SetBkMode(dc, TRANSPARENT);
    wsprintfW(t, L"%u%%", (unsigned)pct);
    ExtTextOutW(dc, panel.left + 6, panel.top + 9, 0, NULL, t, lstrlenW(t), NULL);

    old = SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
    Rectangle(dc, bl, bt, br, bb);
    SelectObject(dc, old);
    inner = br - bl - 2;
    if (inner < 0) inner = 0;
    fill.left   = bl + 1;
    fill.top    = bt + 1;
    fill.bottom = bb - 1;
    fill.right  = fill.left + (LONG)(((__int64)inner * pct) / 100);
    green = CreateSolidBrush(RGB(0, 150, 0));
    FillRect(dc, &fill, green);
    DeleteObject(green);
}
