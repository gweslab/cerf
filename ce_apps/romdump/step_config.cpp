/* Wizard step 2: dump configuration. */

#include "romdump.h"
#include <commdlg.h>

#define DEFAULT_PATH  L"\\Storage Card\\dump.bin"
#define ID_SEGSIZELBL 232
#define ID_SEGSIZE    233
#define ONE_MB        0x00100000u
#define MB_MASK       0xFFF00000u   /* clears the low 20 bits (1 MB) */

static DWORD ParseHex(LPCWSTR s) {
    DWORD v = 0;
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
    for (; *s; ++s) {
        WCHAR c = *s; DWORD d;
        if      (c >= L'0' && c <= L'9') d = (DWORD)(c - L'0');
        else if (c >= L'a' && c <= L'f') d = (DWORD)(10 + c - L'a');
        else if (c >= L'A' && c <= L'F') d = (DWORD)(10 + c - L'A');
        else break;
        v = (v << 4) | d;
    }
    return v;
}

static DWORD ParseDec(LPCWSTR s) {
    DWORD v = 0;
    for (; *s >= L'0' && *s <= L'9'; ++s) v = v * 10 + (DWORD)(*s - L'0');
    return v;
}

static void SetHexField(AppState* st, int id, DWORD v) {
    WCHAR b[16];
    wsprintfW(b, L"0x%08X", v);
    SetWindowTextW(GetDlgItem(st->hwnd, id), b);
}

static void SetDecField(AppState* st, int id, DWORD v) {
    WCHAR b[16];
    wsprintfW(b, L"%u", v);
    SetWindowTextW(GetDlgItem(st->hwnd, id), b);
}

static void SyncSegEnable(AppState* st) {
    BOOL on = SendMessageW(GetDlgItem(st->hwnd, ID_SEG), BM_GETCHECK, 0, 0)
              == BST_CHECKED;
    EnableWindow(GetDlgItem(st->hwnd, ID_SEGSIZE), on);
}

void StepConfigCreate(AppState* st, HINSTANCE hi) {
    HWND h = st->hwnd;
    CreateWindowExW(0, L"STATIC", L"Output file:", WS_CHILD | SS_LEFT,
                    0, 0, 0, 0, h, (HMENU)ID_FILELBL, hi, NULL);
    CreateWindowExW(0, L"EDIT", DEFAULT_PATH,
                    WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                    0, 0, 0, 0, h, (HMENU)ID_FILE, hi, NULL);
    CreateWindowExW(0, L"BUTTON", L"Browse", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                    0, 0, 0, 0, h, (HMENU)ID_BROWSE, hi, NULL);

    CreateWindowExW(0, L"STATIC", L"Base address (hex):", WS_CHILD | SS_LEFT,
                    0, 0, 0, 0, h, (HMENU)ID_BASELBL, hi, NULL);
    CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                    0, 0, 0, 0, h, (HMENU)ID_BASE, hi, NULL);

    CreateWindowExW(0, L"STATIC", L"End address (hex):", WS_CHILD | SS_LEFT,
                    0, 0, 0, 0, h, (HMENU)ID_ENDLBL, hi, NULL);
    CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                    0, 0, 0, 0, h, (HMENU)ID_END, hi, NULL);

    CreateWindowExW(0, L"STATIC", L"Size (MB):", WS_CHILD | SS_LEFT,
                    0, 0, 0, 0, h, (HMENU)ID_SIZELBL, hi, NULL);
    CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_BORDER | WS_TABSTOP |
                    ES_NUMBER | ES_AUTOHSCROLL,
                    0, 0, 0, 0, h, (HMENU)ID_SIZE, hi, NULL);

    CreateWindowExW(0, L"BUTTON", L"Segmented (pause per part)",
                    WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX,
                    0, 0, 0, 0, h, (HMENU)ID_SEG, hi, NULL);
    CreateWindowExW(0, L"BUTTON", L"?", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                    0, 0, 0, 0, h, (HMENU)ID_SEGHELP, hi, NULL);
    CreateWindowExW(0, L"STATIC", L"Part size (MB):", WS_CHILD | SS_LEFT,
                    0, 0, 0, 0, h, (HMENU)ID_SEGSIZELBL, hi, NULL);
    CreateWindowExW(0, L"EDIT", L"1", WS_CHILD | WS_BORDER | WS_TABSTOP |
                    ES_NUMBER | ES_AUTOHSCROLL,
                    0, 0, 0, 0, h, (HMENU)ID_SEGSIZE, hi, NULL);
}

static const int kConfigIds[] = {
    ID_FILELBL, ID_FILE, ID_BROWSE, ID_BASELBL, ID_BASE, ID_ENDLBL, ID_END,
    ID_SIZELBL, ID_SIZE, ID_SEG, ID_SEGHELP, ID_SEGSIZELBL, ID_SEGSIZE,
};

void StepConfigShow(AppState* st, BOOL show) {
    int i, cmd = show ? SW_SHOW : SW_HIDE;
    for (i = 0; i < (int)(sizeof(kConfigIds) / sizeof(kConfigIds[0])); ++i)
        ShowWindow(GetDlgItem(st->hwnd, kConfigIds[i]), cmd);
}

void StepConfigEnter(AppState* st) {
    const Preset* p = &kPresets[st->preset_index];
    if (st->outpath[0] == L'\0') SetWindowTextW(GetDlgItem(st->hwnd, ID_FILE), DEFAULT_PATH);
    st->base   = p->base & MB_MASK;
    st->length = (DWORD)p->size_mb << 20;
    SetHexField(st, ID_BASE, st->base);
    SetHexField(st, ID_END,  st->base + st->length);
    SetDecField(st, ID_SIZE, st->length >> 20);
    SyncSegEnable(st);
}

int StepConfigLayout(AppState* st, RECT area) {
    HWND h = st->hwnd;
    int  m = 6, x = area.left + m, w = area.right - area.left - 2 * m, y = m;
    int  top = area.top;
    if (w < 60) w = 60;
    #define ROW(id, ry, rh, rx, rw) \
        MoveWindow(GetDlgItem(h, id), (rx), top + (ry) - st->scroll_y, (rw), (rh), TRUE)

    ROW(ID_FILELBL, y, 16, x, w);                 y += 18;
    ROW(ID_FILE,   y, 22, x, w - 58);
    ROW(ID_BROWSE, y, 24, x + w - 54, 54);        y += 30;
    ROW(ID_BASELBL, y, 16, x, w);                 y += 18;
    ROW(ID_BASE,   y, 22, x, w);                  y += 30;
    ROW(ID_ENDLBL, y, 16, x, w);                  y += 18;
    ROW(ID_END,    y, 22, x, w);                  y += 30;
    ROW(ID_SIZELBL, y, 16, x, w);                 y += 18;
    ROW(ID_SIZE,   y, 22, x, w);                  y += 30;
    ROW(ID_SEG,    y, 22, x, w - 28);
    ROW(ID_SEGHELP, y, 22, x + w - 24, 24);       y += 28;
    ROW(ID_SEGSIZELBL, y, 16, x, w);              y += 18;
    ROW(ID_SEGSIZE, y, 22, x, w);                 y += 30;
    #undef ROW
    return y + m;
}

static void SyncFromBase(AppState* st) {
    WCHAR b[32];
    GetWindowTextW(GetDlgItem(st->hwnd, ID_BASE), b, 32);
    st->base = ParseHex(b) & MB_MASK;
    SetHexField(st, ID_BASE, st->base);
    SetHexField(st, ID_END,  st->base + st->length);
}

static void SyncFromSize(AppState* st) {
    WCHAR b[32];
    GetWindowTextW(GetDlgItem(st->hwnd, ID_SIZE), b, 32);
    st->length = (DWORD)ParseDec(b) << 20;
    SetHexField(st, ID_END, st->base + st->length);
}

static void SyncFromEnd(AppState* st) {
    WCHAR b[32];
    DWORD ne;
    GetWindowTextW(GetDlgItem(st->hwnd, ID_END), b, 32);
    ne = ParseHex(b) & MB_MASK;            /* round down: never read past End */
    SetHexField(st, ID_END, ne);
    if (ne > st->base) {
        st->length = ne - st->base;
        SetDecField(st, ID_SIZE, st->length >> 20);
    }
}

static void DoBrowse(AppState* st) {
    typedef BOOL (*GetSaveFn)(LPOPENFILENAMEW);
    GetSaveFn fn = (GetSaveFn)CoreProc(L"GetSaveFileNameW");
    OPENFILENAMEW ofn;
    WCHAR path[MAX_PATH];
    if (!fn) {
        MessageBoxW(st->hwnd,
                    L"No file dialog on this device. Type the output path by hand.",
                    L"CERF ROM dumper", MB_OK | MB_ICONINFORMATION);
        return;
    }
    GetWindowTextW(GetDlgItem(st->hwnd, ID_FILE), path, MAX_PATH);
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = st->hwnd;
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrFilter = L"Dump (*.bin)\0*.bin\0All files\0*.*\0";
    ofn.lpstrDefExt = L"bin";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (fn(&ofn)) SetWindowTextW(GetDlgItem(st->hwnd, ID_FILE), path);
}

static void ShowSegHelp(HWND h) {
    MessageBoxW(h,
        L"Segmented mode splits the dump into parts of the Part size "
        L"(dump.bin.001, .002, ...). After each part the dumper pauses so you "
        L"can copy that file off the device or swap the storage card, then "
        L"continue. Use it when the target storage is smaller than the whole "
        L"dump. The last part may be smaller - that is fine.",
        L"Segmented mode", MB_OK | MB_ICONINFORMATION);
}

BOOL StepConfigCommand(AppState* st, WPARAM wp, LPARAM lp) {
    (void)lp;
    switch (LOWORD(wp)) {
    case ID_BASE: if (HIWORD(wp) == EN_KILLFOCUS) { SyncFromBase(st); return TRUE; } break;
    case ID_END:  if (HIWORD(wp) == EN_KILLFOCUS) { SyncFromEnd(st);  return TRUE; } break;
    case ID_SIZE: if (HIWORD(wp) == EN_KILLFOCUS) { SyncFromSize(st); return TRUE; } break;
    case ID_SEG:    if (HIWORD(wp) == BN_CLICKED) { SyncSegEnable(st); return TRUE; } break;
    case ID_BROWSE: if (HIWORD(wp) == BN_CLICKED) { DoBrowse(st);   return TRUE; } break;
    case ID_SEGHELP:if (HIWORD(wp) == BN_CLICKED) { ShowSegHelp(st->hwnd); return TRUE; } break;
    }
    return FALSE;
}

BOOL StepConfigOnNext(AppState* st) {
    WCHAR b[32];
    GetWindowTextW(GetDlgItem(st->hwnd, ID_FILE), st->outpath, MAX_PATH);
    if (st->outpath[0] == L'\0') {
        MessageBoxW(st->hwnd, L"Enter an output file path.",
                    L"CERF ROM dumper", MB_OK | MB_ICONEXCLAMATION);
        return FALSE;
    }
    GetWindowTextW(GetDlgItem(st->hwnd, ID_BASE), b, 32);
    st->base = ParseHex(b) & MB_MASK;
    GetWindowTextW(GetDlgItem(st->hwnd, ID_SIZE), b, 32);
    if (ParseDec(b) == 0) {
        MessageBoxW(st->hwnd, L"Size must be at least 1 MB.",
                    L"CERF ROM dumper", MB_OK | MB_ICONEXCLAMATION);
        return FALSE;
    }
    st->length = ParseDec(b) << 20;

    st->segmented = SendMessageW(GetDlgItem(st->hwnd, ID_SEG), BM_GETCHECK, 0, 0)
                    == BST_CHECKED;
    if (st->segmented) {
        DWORD seg_mb;
        GetWindowTextW(GetDlgItem(st->hwnd, ID_SEGSIZE), b, 32);
        seg_mb = ParseDec(b);
        if (seg_mb == 0) {
            MessageBoxW(st->hwnd, L"Part size must be at least 1 MB.",
                        L"CERF ROM dumper", MB_OK | MB_ICONEXCLAMATION);
            return FALSE;
        }
        st->seg_bytes = seg_mb << 20;
    } else {
        st->seg_bytes = 0;
    }
    return TRUE;
}
