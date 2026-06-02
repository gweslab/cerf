/* CERF Sample App - comprehensive CE5 control & subsystem exerciser.
   Eight tabs covering basic gwes controls, commctrl widgets, GDI custom
   paint, owner-draw, modal dialogs, file/clipboard I/O, threads, and
   toolbars. Compiled with CE5 Platform Builder ARM compiler. */

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

/* CE5 Platform Builder SDK is missing some CBS_* constants - define locally. */
#ifndef CBS_SIMPLE
#define CBS_SIMPLE          0x0001L
#define CBS_DROPDOWN        0x0002L
#define CBS_DROPDOWNLIST    0x0003L
#define CBS_AUTOHSCROLL     0x0040L
#define CBS_HASSTRINGS      0x0200L
#endif

/* ===== Control IDs (per tab band) ===== */
/* Tab 1 - Basic */
#define ID_TB1_EDIT            102
#define ID_TB1_EDIT_3D         103
#define ID_TB1_EDIT_MULTI      104
#define ID_TB1_LISTBOX         105
#define ID_TB1_CHECKBOX        106
#define ID_TB1_BTN_POPUP       107
#define ID_TB1_OPT_GROUP       108
#define ID_TB1_RADIO1          109
#define ID_TB1_RADIO2          110
#define ID_TB1_OPT_C           111
#define ID_TB1_OPT_D           112

/* Tab 2 - Lists */
#define ID_TB2_LV              200
#define ID_TB2_TV              201
#define ID_TB2_LB_MULTI        202

/* Tab 3 - Sliders */
#define ID_TB3_TRACK_H         300
#define ID_TB3_TRACK_V         301
#define ID_TB3_PROGRESS        302
#define ID_TB3_UPDOWN          303
#define ID_TB3_UPDOWN_BUDDY    304
#define ID_TB3_HOTKEY          305

/* Tab 4 - GDI */
#define ID_TB4_PAINT_CHILD     400
#define ID_TB4_BTN_REDRAW      401

/* Tab 5 - Combos & owner-draw */
#define ID_TB5_CMB_LIST        500
#define ID_TB5_CMB_DROP        501
#define ID_TB5_CMB_SIMPLE      502
#define ID_TB5_OD_LB           503
#define ID_TB5_OD_BTN          504

/* Tab 6 - Dialogs & I/O */
#define ID_TB6_GRP             600
#define ID_TB6_CMB_BTNS        601
#define ID_TB6_CMB_ICON        602
#define ID_TB6_BTN_MSGBOX      603
#define ID_TB6_BTN_DIALOG      604
#define ID_TB6_BTN_OPENFILE    605
#define ID_TB6_BTN_WRITE       606
#define ID_TB6_BTN_READ        607
#define ID_TB6_BTN_COPY        608
#define ID_TB6_BTN_PASTE       609
#define ID_TB6_RESULT_EDIT     610

/* Tab 7 - Async */
#define ID_TB7_BTN_TIMER_START 700
#define ID_TB7_BTN_TIMER_STOP  701
#define ID_TB7_TIMER_LBL       702
#define ID_TB7_BTN_THR_START   703
#define ID_TB7_BTN_THR_STOP    704
#define ID_TB7_THR_LBL         705

/* Tab 8 - Toolbar */
#define ID_TB8_TOOLBAR         800
#define ID_TB8_HEADER          801
#define ID_TB8_ANIMATE         802

/* Common */
#define ID_TAB_CONTROL         900
#define ID_STATUS_BAR          901
#define ID_TIMER_TICK          1
#define WM_APP_THREAD_TICK     (WM_APP + 1)

/* Menu commands */
#define IDM_FILE_NEW           4001
#define IDM_FILE_OPEN          4002
#define IDM_FILE_SAVE          4003
#define IDM_FILE_EXIT          4004
#define IDM_EDIT_CUT           4101
#define IDM_EDIT_COPY          4102
#define IDM_EDIT_PASTE         4103
#define IDM_EDIT_SELECTALL     4104
#define IDM_VIEW_TAB1          4201
#define IDM_VIEW_TAB8          4208
#define IDM_HELP_ABOUT         4301
#define IDM_CTX_ABOUT          4401
#define IDM_CTX_REFRESH        4402
#define IDM_CTX_EXIT           4403

#define TAB_COUNT              8

/* ===== MessageBox flavor + result tables ===== */
struct MsgBoxFlavor { UINT flags; LPCTSTR label; };
struct MsgBoxResult { int code; LPCTSTR name; };

static const struct MsgBoxFlavor kMbButtonFlavors[] = {
    { MB_OK,               TEXT("MB_OK") },
    { MB_OKCANCEL,         TEXT("MB_OKCANCEL") },
    { MB_YESNO,            TEXT("MB_YESNO") },
    { MB_YESNOCANCEL,      TEXT("MB_YESNOCANCEL") },
    { MB_RETRYCANCEL,      TEXT("MB_RETRYCANCEL") },
    { MB_ABORTRETRYIGNORE, TEXT("MB_ABORTRETRYIGNORE") },
};
#define NUM_MB_BTN_FLAVORS (sizeof(kMbButtonFlavors) / sizeof(kMbButtonFlavors[0]))

static const struct MsgBoxFlavor kMbIconFlavors[] = {
    { 0,                   TEXT("(none)") },
    { MB_ICONINFORMATION,  TEXT("MB_ICONINFORMATION") },
    { MB_ICONWARNING,      TEXT("MB_ICONWARNING") },
    { MB_ICONERROR,        TEXT("MB_ICONERROR") },
    { MB_ICONQUESTION,     TEXT("MB_ICONQUESTION") },
};
#define NUM_MB_ICON_FLAVORS (sizeof(kMbIconFlavors) / sizeof(kMbIconFlavors[0]))

static const struct MsgBoxResult kMbResults[] = {
    { IDOK,     TEXT("IDOK") },
    { IDCANCEL, TEXT("IDCANCEL") },
    { IDABORT,  TEXT("IDABORT") },
    { IDRETRY,  TEXT("IDRETRY") },
    { IDIGNORE, TEXT("IDIGNORE") },
    { IDYES,    TEXT("IDYES") },
    { IDNO,     TEXT("IDNO") },
};
#define NUM_MB_RESULTS (sizeof(kMbResults) / sizeof(kMbResults[0]))

static LPCTSTR MbResultName(int code) {
    int i;
    for (i = 0; i < (int)NUM_MB_RESULTS; i++)
        if (kMbResults[i].code == code) return kMbResults[i].name;
    return TEXT("(unknown)");
}

/* ===== Globals ===== */
static HINSTANCE g_hInstance = NULL;
static HWND      g_hMainWnd = NULL;
static HWND      g_hTabCtrl = NULL;
static HWND      g_hStatusBar = NULL;
static HMENU     g_hMenu = NULL;
static HMENU     g_hCtxMenu = NULL;
static HWND      g_hTabPanes[TAB_COUNT] = {0};
static HWND      g_hTimerLabel = NULL;
static HWND      g_hThreadLabel = NULL;
static HWND      g_hProgress = NULL;
static UINT_PTR  g_timerId = 0;
static int       g_timerCounter = 0;
static int       g_progressVal = 0;
static HANDLE    g_hWorkerThread = NULL;
static HANDLE    g_hWorkerStop = NULL;
static WNDPROC   g_origGrpWndProc = NULL;
static int       g_paintSeed = 1;

/* Forward declarations */
static LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK TabPaneProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK GroupBoxForwardProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK CustomPaintChildProc(HWND, UINT, WPARAM, LPARAM);
static BOOL    CALLBACK SampleDialogProc(HWND, UINT, WPARAM, LPARAM);
static DWORD   WINAPI   WorkerThreadProc(LPVOID);
static void BuildTabBasic   (HWND pane);
static void BuildTabLists   (HWND pane);
static void BuildTabSliders (HWND pane);
static void BuildTabGdi     (HWND pane);
static void BuildTabCombos  (HWND pane);
static void BuildTabDialogs (HWND pane);
static void BuildTabAsync   (HWND pane);
static void BuildTabToolbar (HWND pane);
static void SwitchTab(int idx);
static void SetStatusText(int pane, LPCTSTR text);
static void HandleMessageBoxButton(HWND parent);
static void HandleDialogButton(HWND parent);
static void HandleOpenFileButton(HWND parent);
static void HandleWriteFileButton(HWND parent);
static void HandleReadFileButton(HWND parent);
static void HandleCopyButton(HWND parent);
static void HandlePasteButton(HWND parent);
static void HandleTimerStart(void);
static void HandleTimerStop(void);
static void HandleThreadStart(void);
static void HandleThreadStop(void);

static const TCHAR kPaneClass[]  = TEXT("CerfSampleAppPane");
static const TCHAR kPaintClass[] = TEXT("CerfSampleAppPaint");

/* ===== WM_CTLCOLOR* helper ===== */
static LRESULT SampleHandleCtlColor(HDC hdc) {
    SetBkColor(hdc, GetSysColor(COLOR_BTNFACE));
    SetTextColor(hdc, GetSysColor(COLOR_BTNTEXT));
    return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
}

/* ===== GroupBox subclass: forward WM_COMMAND + WM_CTLCOLOR* to parent ===== */
static LRESULT CALLBACK GroupBoxForwardProc(HWND hwnd, UINT msg,
                                             WPARAM wp, LPARAM lp) {
    if (msg == WM_COMMAND ||
        msg == WM_CTLCOLORSTATIC ||
        msg == WM_CTLCOLORBTN) {
        HWND parent = GetParent(hwnd);
        if (parent) return SendMessage(parent, msg, wp, lp);
    }
    return CallWindowProc(g_origGrpWndProc, hwnd, msg, wp, lp);
}

/* ===== Tab pane container ===== */
static LRESULT CALLBACK TabPaneProc(HWND hwnd, UINT msg,
                                     WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_COMMAND:
    case WM_NOTIFY:
    case WM_DRAWITEM:
    case WM_MEASUREITEM:
    case WM_VSCROLL:
    case WM_HSCROLL:
        if (g_hMainWnd) return SendMessage(g_hMainWnd, msg, wp, lp);
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORDLG:
        return SampleHandleCtlColor((HDC)wp);
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ===== Custom-paint child (Tab 4) =====
   Exercises CreatePen / CreateSolidBrush / CreateFont / SelectObject /
   FillRect / Rectangle / Ellipse / Polygon / TextOut on a child DC. */
static LRESULT CALLBACK CustomPaintChildProc(HWND hwnd, UINT msg,
                                              WPARAM wp, LPARAM lp) {
    PAINTSTRUCT ps;
    HDC hdc;
    RECT rc;
    HBRUSH hbrBg, hbrShape, hbrOld;
    HPEN hpen, hpenOld;
    HFONT hfont, hfontOld;
    POINT poly[5];
    int i, x, y, w, h, r, g, b;

    if (msg == WM_PAINT) {
        HDC hMemDC;
        HBITMAP hMemBmp, hOldBmp;
        int cw, ch;

        hdc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rc);
        cw = rc.right - rc.left;
        ch = rc.bottom - rc.top;

        /* Render off-screen into a memory DC, then BitBlt - flicker-free
           and exercises CreateCompatibleDC + CreateCompatibleBitmap. */
        hMemDC = CreateCompatibleDC(hdc);
        hMemBmp = CreateCompatibleBitmap(hdc, cw, ch);
        hOldBmp = (HBITMAP)SelectObject(hMemDC, hMemBmp);

        hbrBg = CreateSolidBrush(RGB(248, 248, 252));
        FillRect(hMemDC, &rc, hbrBg);
        DeleteObject(hbrBg);

        hpen = CreatePen(PS_SOLID, 2, RGB(20, 40, 100));
        hpenOld = (HPEN)SelectObject(hMemDC, hpen);
        hbrOld = (HBRUSH)SelectObject(hMemDC, GetStockObject(NULL_BRUSH));
        Rectangle(hMemDC, rc.left + 2, rc.top + 2,
                  rc.right - 2, rc.bottom - 2);
        SelectObject(hMemDC, hbrOld);
        SelectObject(hMemDC, hpenOld);
        DeleteObject(hpen);

        for (i = 0; i < 7; i++) {
            g_paintSeed = g_paintSeed * 1103515245 + 12345;
            r = (g_paintSeed >> 16) & 0xFF;
            g_paintSeed = g_paintSeed * 1103515245 + 12345;
            g = (g_paintSeed >> 16) & 0xFF;
            g_paintSeed = g_paintSeed * 1103515245 + 12345;
            b = (g_paintSeed >> 16) & 0xFF;
            g_paintSeed = g_paintSeed * 1103515245 + 12345;
            x = ((g_paintSeed >> 16) & 0x7FFF) % (cw - 80) + 20;
            g_paintSeed = g_paintSeed * 1103515245 + 12345;
            y = ((g_paintSeed >> 16) & 0x7FFF) % (ch - 80) + 20;
            w = 50 + i * 4;
            h = 35 + i * 3;

            hbrShape = CreateSolidBrush(RGB(r, g, b));
            hbrOld = (HBRUSH)SelectObject(hMemDC, hbrShape);
            if (i % 3 == 0) {
                Ellipse(hMemDC, x, y, x + w, y + h);
            } else if (i % 3 == 1) {
                Rectangle(hMemDC, x, y, x + w, y + h);
            } else {
                poly[0].x = x + w/2; poly[0].y = y;
                poly[1].x = x + w;   poly[1].y = y + h/2;
                poly[2].x = x + w/2; poly[2].y = y + h;
                poly[3].x = x;       poly[3].y = y + h/2;
                poly[4].x = x + w/2; poly[4].y = y;
                Polygon(hMemDC, poly, 5);
            }
            SelectObject(hMemDC, hbrOld);
            DeleteObject(hbrShape);
        }

        /* Text - CE5 uses CreateFontIndirect + ExtTextOut. */
        {
            LOGFONT lf;
            memset(&lf, 0, sizeof(lf));
            lf.lfHeight = 18;
            lf.lfWeight = FW_BOLD;
            lf.lfCharSet = DEFAULT_CHARSET;
            lf.lfQuality = DEFAULT_QUALITY;
            lf.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
            lstrcpy(lf.lfFaceName, TEXT("Tahoma"));
            hfont = CreateFontIndirect(&lf);
        }
        hfontOld = (HFONT)SelectObject(hMemDC, hfont);
        SetBkMode(hMemDC, TRANSPARENT);
        SetTextColor(hMemDC, RGB(20, 40, 100));
        ExtTextOut(hMemDC, 14, 12, 0, NULL,
                   TEXT("CERF GDI demo (BitBlt from memory DC)"), 38, NULL);
        SelectObject(hMemDC, hfontOld);
        DeleteObject(hfont);

        BitBlt(hdc, 0, 0, cw, ch, hMemDC, 0, 0, SRCCOPY);

        SelectObject(hMemDC, hOldBmp);
        DeleteObject(hMemBmp);
        DeleteDC(hMemDC);

        EndPaint(hwnd, &ps);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

/* ===== Tab 1 - Basic controls (pane ~685x290) ===== */
static void BuildTabBasic(HWND pane) {
    HWND hLB, hGrp;
    WNDPROC prev;

    CreateWindow(TEXT("STATIC"), TEXT("Basic CE5 controls:"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 4, 320, 14, pane, NULL, g_hInstance, NULL);

    CreateWindow(TEXT("EDIT"), TEXT("WS_BORDER edit"),
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        8, 22, 330, 20, pane, (HMENU)ID_TB1_EDIT, g_hInstance, NULL);

    CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("3D sunken edit"),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        8, 46, 330, 20, pane, (HMENU)ID_TB1_EDIT_3D, g_hInstance, NULL);

    CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"),
        TEXT("Line 1: Hello\r\nLine 2: Multi-line\r\n")
        TEXT("Line 3: Scroll\r\nLine 4: More\r\nLine 5: Even more"),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL,
        8, 70, 330, 60, pane, (HMENU)ID_TB1_EDIT_MULTI,
        g_hInstance, NULL);

    hLB = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("LISTBOX"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        LBS_NOTIFY | LBS_SORT | LBS_NOINTEGRALHEIGHT,
        8, 134, 330, 90, pane, (HMENU)ID_TB1_LISTBOX,
        g_hInstance, NULL);
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Apple"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Banana"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Cherry"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Date"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Elderberry"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Fig"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Grape"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Honeydew"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Kiwi"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Lemon"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Mango"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Orange"));
    SendMessage(hLB, LB_SETCURSEL, 0, 0);

    CreateWindow(TEXT("BUTTON"), TEXT("Show popup LB"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        8, 230, 120, 22, pane, (HMENU)ID_TB1_BTN_POPUP,
        g_hInstance, NULL);

    CreateWindow(TEXT("BUTTON"), TEXT("Check me"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        134, 230, 120, 22, pane, (HMENU)ID_TB1_CHECKBOX,
        g_hInstance, NULL);

    /* Options groupbox with radio + checkbox children. */
    hGrp = CreateWindow(TEXT("BUTTON"), TEXT("Options"),
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | BS_GROUPBOX,
        348, 22, 332, 110, pane, (HMENU)ID_TB1_OPT_GROUP,
        g_hInstance, NULL);
    prev = (WNDPROC)SetWindowLong(hGrp, GWL_WNDPROC,
                                   (LONG)GroupBoxForwardProc);
    if (!g_origGrpWndProc) g_origGrpWndProc = prev;

    CreateWindow(TEXT("BUTTON"), TEXT("Option A"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP |
        BS_AUTORADIOBUTTON | WS_GROUP,
        10, 18, 150, 20, hGrp, (HMENU)ID_TB1_RADIO1,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Option B"),
        WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
        170, 18, 150, 20, hGrp, (HMENU)ID_TB1_RADIO2,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Option C"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 44, 150, 20, hGrp, (HMENU)ID_TB1_OPT_C,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Option D"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        170, 44, 150, 20, hGrp, (HMENU)ID_TB1_OPT_D,
        g_hInstance, NULL);
}

/* ===== Tab 2 - Lists (ListView, TreeView, multi-select listbox) ===== */
static void BuildTabLists(HWND pane) {
    HWND hLV, hTV, hLB;
    LVCOLUMN lvc;
    LVITEM lvi;
    TVINSERTSTRUCT tvis;
    HTREEITEM hRoot, hChildA;
    int i;
    static const TCHAR* kFiles[] = {
        TEXT("readme.txt"), TEXT("setup.exe"), TEXT("config.ini"),
        TEXT("data.bin"),   TEXT("notes.doc"), TEXT("photo.jpg"),
        TEXT("music.wav"),  TEXT("video.avi")
    };
    static const TCHAR* kSizes[] = {
        TEXT("1.2 KB"), TEXT("420 KB"), TEXT("256 B"),  TEXT("8.4 MB"),
        TEXT("64 KB"),  TEXT("3.1 MB"), TEXT("12 MB"),  TEXT("48 MB")
    };
    static const TCHAR* kTypes[] = {
        TEXT("Text"),     TEXT("Application"), TEXT("Config"),
        TEXT("Data"),     TEXT("Document"),    TEXT("Image"),
        TEXT("Audio"),    TEXT("Video")
    };

    CreateWindow(TEXT("STATIC"), TEXT("SysListView32 (LVS_REPORT):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 2, 280, 14, pane, NULL, g_hInstance, NULL);

    hLV = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
        8, 18, 330, 270, pane, (HMENU)ID_TB2_LV,
        g_hInstance, NULL);
    if (hLV) {
        static const COLORREF kIconColors[] = {
            RGB(0x44, 0x88, 0xCC),  /* text     */
            RGB(0x88, 0xCC, 0x44),  /* exe      */
            RGB(0xCC, 0xCC, 0x44),  /* config   */
            RGB(0x88, 0x88, 0xAA),  /* data     */
            RGB(0xCC, 0x88, 0xCC),  /* doc      */
            RGB(0xCC, 0x44, 0x44),  /* image    */
            RGB(0x44, 0xCC, 0xCC),  /* audio    */
            RGB(0x88, 0x44, 0xCC),  /* video    */
        };
        HIMAGELIST hImg = ImageList_Create(16, 16, ILC_COLOR, 8, 0);
        HDC hScreen = GetDC(NULL);
        HDC hMemDC = CreateCompatibleDC(hScreen);
        for (i = 0; i < 8; i++) {
            HBITMAP hBmp = CreateCompatibleBitmap(hScreen, 16, 16);
            HBITMAP hOld = (HBITMAP)SelectObject(hMemDC, hBmp);
            HBRUSH hbr = CreateSolidBrush(kIconColors[i]);
            HBRUSH hbrBlack = (HBRUSH)GetStockObject(BLACK_BRUSH);
            RECT rcAll = {0, 0, 16, 16};
            RECT rcEdge;
            FillRect(hMemDC, &rcAll, hbr);
            DeleteObject(hbr);
            /* 1px border */
            rcEdge = rcAll; rcEdge.bottom = 1;
            FillRect(hMemDC, &rcEdge, hbrBlack);
            rcEdge = rcAll; rcEdge.top = 15;
            FillRect(hMemDC, &rcEdge, hbrBlack);
            rcEdge = rcAll; rcEdge.right = 1;
            FillRect(hMemDC, &rcEdge, hbrBlack);
            rcEdge = rcAll; rcEdge.left = 15;
            FillRect(hMemDC, &rcEdge, hbrBlack);
            SelectObject(hMemDC, hOld);
            ImageList_Add(hImg, hBmp, NULL);
            DeleteObject(hBmp);
        }
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreen);
        SendMessage(hLV, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hImg);

        SendMessage(hLV, LVM_SETEXTENDEDLISTVIEWSTYLE,
                    LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES,
                    LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        lvc.iSubItem = 0; lvc.cx = 160; lvc.pszText = TEXT("Name");
        SendMessage(hLV, LVM_INSERTCOLUMN, 0, (LPARAM)&lvc);
        lvc.iSubItem = 1; lvc.cx = 80;  lvc.pszText = TEXT("Size");
        SendMessage(hLV, LVM_INSERTCOLUMN, 1, (LPARAM)&lvc);
        lvc.iSubItem = 2; lvc.cx = 100; lvc.pszText = TEXT("Type");
        SendMessage(hLV, LVM_INSERTCOLUMN, 2, (LPARAM)&lvc);
        for (i = 0; i < 8; i++) {
            lvi.mask = LVIF_TEXT | LVIF_IMAGE;
            lvi.iItem = i; lvi.iSubItem = 0;
            lvi.iImage = i;
            lvi.pszText = (LPTSTR)kFiles[i];
            SendMessage(hLV, LVM_INSERTITEM, 0, (LPARAM)&lvi);
            lvi.mask = LVIF_TEXT;
            lvi.iSubItem = 1; lvi.pszText = (LPTSTR)kSizes[i];
            SendMessage(hLV, LVM_SETITEM, 0, (LPARAM)&lvi);
            lvi.iSubItem = 2; lvi.pszText = (LPTSTR)kTypes[i];
            SendMessage(hLV, LVM_SETITEM, 0, (LPARAM)&lvi);
        }
    }

    CreateWindow(TEXT("STATIC"), TEXT("SysTreeView32 (TVS_CHECKBOXES):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        348, 2, 320, 14, pane, NULL, g_hInstance, NULL);

    hTV = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREEVIEW, NULL,
        WS_CHILD | WS_VISIBLE | TVS_HASBUTTONS | TVS_HASLINES |
        TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_CHECKBOXES,
        348, 18, 332, 150, pane, (HMENU)ID_TB2_TV,
        g_hInstance, NULL);
    if (hTV) {
        memset(&tvis, 0, sizeof(tvis));
        tvis.hParent = TVI_ROOT;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT;
        tvis.item.pszText = TEXT("Root");
        hRoot = (HTREEITEM)SendMessage(hTV, TVM_INSERTITEM, 0, (LPARAM)&tvis);

        tvis.hParent = hRoot;
        tvis.item.pszText = TEXT("Child A");
        hChildA = (HTREEITEM)SendMessage(hTV, TVM_INSERTITEM, 0, (LPARAM)&tvis);

        tvis.hParent = hChildA;
        tvis.item.pszText = TEXT("Grandchild 1");
        SendMessage(hTV, TVM_INSERTITEM, 0, (LPARAM)&tvis);
        tvis.item.pszText = TEXT("Grandchild 2");
        SendMessage(hTV, TVM_INSERTITEM, 0, (LPARAM)&tvis);

        tvis.hParent = hRoot;
        tvis.item.pszText = TEXT("Child B");
        SendMessage(hTV, TVM_INSERTITEM, 0, (LPARAM)&tvis);
        tvis.item.pszText = TEXT("Child C");
        SendMessage(hTV, TVM_INSERTITEM, 0, (LPARAM)&tvis);

        SendMessage(hTV, TVM_EXPAND, TVE_EXPAND, (LPARAM)hRoot);
    }

    CreateWindow(TEXT("STATIC"), TEXT("Multi-select LISTBOX:"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        348, 174, 280, 14, pane, NULL, g_hInstance, NULL);
    hLB = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("LISTBOX"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        LBS_NOTIFY | LBS_MULTIPLESEL | LBS_NOINTEGRALHEIGHT,
        348, 190, 332, 100, pane, (HMENU)ID_TB2_LB_MULTI,
        g_hInstance, NULL);
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Red"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Green"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Blue"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Yellow"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Purple"));
}

/* ===== Tab 3 - Sliders (trackbar, progress, updown) ===== */
static void BuildTabSliders(HWND pane) {
    HWND hUpdownBuddy, hUpdown;

    CreateWindow(TEXT("STATIC"), TEXT("Trackbar (horizontal, ticks every 10):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 2, 380, 14, pane, NULL, g_hInstance, NULL);
    {
        HWND h = CreateWindow(TRACKBAR_CLASS, NULL,
            WS_CHILD | WS_VISIBLE | TBS_AUTOTICKS | TBS_HORZ,
            8, 18, 330, 30, pane, (HMENU)ID_TB3_TRACK_H,
            g_hInstance, NULL);
        if (h) {
            SendMessage(h, TBM_SETRANGE, TRUE, MAKELONG(0, 100));
            SendMessage(h, TBM_SETPOS, TRUE, 50);
            SendMessage(h, TBM_SETTICFREQ, 10, 0);
        }
    }

    CreateWindow(TEXT("STATIC"), TEXT("Vertical:"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 54, 90, 14, pane, NULL, g_hInstance, NULL);
    {
        HWND h = CreateWindow(TRACKBAR_CLASS, NULL,
            WS_CHILD | WS_VISIBLE | TBS_AUTOTICKS | TBS_VERT,
            8, 70, 32, 200, pane, (HMENU)ID_TB3_TRACK_V,
            g_hInstance, NULL);
        if (h) {
            SendMessage(h, TBM_SETRANGE, TRUE, MAKELONG(0, 100));
            SendMessage(h, TBM_SETPOS, TRUE, 30);
            SendMessage(h, TBM_SETTICFREQ, 10, 0);
        }
    }

    CreateWindow(TEXT("STATIC"),
        TEXT("Progress bar (driven by Tab 7 timer):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        50, 70, 380, 14, pane, NULL, g_hInstance, NULL);
    g_hProgress = CreateWindow(PROGRESS_CLASS, NULL,
        WS_CHILD | WS_VISIBLE,
        50, 86, 280, 22, pane, (HMENU)ID_TB3_PROGRESS,
        g_hInstance, NULL);
    if (g_hProgress) {
        SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
    }

    CreateWindow(TEXT("STATIC"),
        TEXT("Updown spinner (UDS_AUTOBUDDY -> buddy edit):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        50, 116, 380, 14, pane, NULL, g_hInstance, NULL);
    hUpdownBuddy = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("50"),
        WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_RIGHT,
        50, 132, 70, 22, pane, (HMENU)ID_TB3_UPDOWN_BUDDY,
        g_hInstance, NULL);
    hUpdown = CreateWindow(UPDOWN_CLASS, NULL,
        WS_CHILD | WS_VISIBLE | UDS_AUTOBUDDY | UDS_SETBUDDYINT |
        UDS_ALIGNRIGHT | UDS_ARROWKEYS | UDS_NOTHOUSANDS,
        0, 0, 0, 0, pane, (HMENU)ID_TB3_UPDOWN, g_hInstance, NULL);
    if (hUpdown) {
        SendMessage(hUpdown, UDM_SETBUDDY, (WPARAM)hUpdownBuddy, 0);
        SendMessage(hUpdown, UDM_SETRANGE, 0, MAKELONG(100, 0));
        SendMessage(hUpdown, UDM_SETPOS, 0, MAKELONG(50, 0));
    }

    /* CE5 commctrl is built without hotkey support (NOHOTKEY in commctrl.h). */
    CreateWindow(TEXT("STATIC"),
        TEXT("Hotkey control is excluded from CE5 commctrl (NOHOTKEY)."),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        50, 168, 620, 14, pane, NULL, g_hInstance, NULL);
    CreateWindow(TEXT("STATIC"),
        TEXT("The progress bar above ticks while the Tab 7 timer is running."),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        50, 208, 620, 14, pane, NULL, g_hInstance, NULL);
}

/* ===== Tab 4 - GDI custom paint (paints to memory DC, BitBlts to screen) ===== */
static void BuildTabGdi(HWND pane) {
    CreateWindow(TEXT("STATIC"),
        TEXT("Custom WM_PAINT (line/rect/ellipse/polygon/text via BitBlt):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 2, 600, 14, pane, NULL, g_hInstance, NULL);

    CreateWindow(kPaintClass, NULL,
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        8, 18, 670, 230, pane, (HMENU)ID_TB4_PAINT_CHILD,
        g_hInstance, NULL);

    CreateWindow(TEXT("BUTTON"), TEXT("Redraw with random colors"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        8, 254, 200, 22, pane, (HMENU)ID_TB4_BTN_REDRAW,
        g_hInstance, NULL);
}

/* ===== Tab 5 - Combos & owner-draw listbox ===== */
static void BuildTabCombos(HWND pane) {
    HWND hC, hLB;
    static LPCTSTR kColors[] = {
        TEXT("Red"),       TEXT("Green"),    TEXT("Blue"),
        TEXT("Yellow"),    TEXT("Orange"),   TEXT("Purple"),
        TEXT("Pink"),      TEXT("Brown"),    TEXT("Black"),
        TEXT("White"),     TEXT("Gray"),     TEXT("Cyan"),
        TEXT("Magenta"),   TEXT("Maroon"),   TEXT("Navy"),
        TEXT("Teal"),      TEXT("Olive"),    TEXT("Lime"),
        TEXT("Aqua"),      TEXT("Silver"),   TEXT("Gold"),
        TEXT("Beige"),     TEXT("Coral"),    TEXT("Salmon"),
        TEXT("Indigo"),    TEXT("Violet"),   TEXT("Turquoise"),
        TEXT("Crimson"),   TEXT("Khaki"),    TEXT("Lavender"),
    };
    int n;

    CreateWindow(TEXT("STATIC"),
        TEXT("CBS_DROPDOWNLIST (30 items):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 2, 200, 14, pane, NULL, g_hInstance, NULL);
    hC = CreateWindow(TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        8, 18, 200, 180, pane, (HMENU)ID_TB5_CMB_LIST,
        g_hInstance, NULL);
    for (n = 0; n < (int)(sizeof(kColors)/sizeof(kColors[0])); n++)
        SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)kColors[n]);
    SendMessage(hC, CB_SETCURSEL, 0, 0);

    CreateWindow(TEXT("STATIC"), TEXT("CBS_DROPDOWN (editable):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 46, 200, 14, pane, NULL, g_hInstance, NULL);
    hC = CreateWindow(TEXT("COMBOBOX"), TEXT("type..."),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        CBS_DROPDOWN | CBS_HASSTRINGS | CBS_AUTOHSCROLL,
        8, 62, 200, 180, pane, (HMENU)ID_TB5_CMB_DROP,
        g_hInstance, NULL);
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("Alpha"));
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("Beta"));
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("Gamma"));
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("Delta"));

    CreateWindow(TEXT("STATIC"),
        TEXT("CBS_SIMPLE (edit + LB):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 90, 200, 14, pane, NULL, g_hInstance, NULL);
    hC = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        CBS_SIMPLE | CBS_HASSTRINGS | CBS_AUTOHSCROLL,
        8, 106, 200, 80, pane, (HMENU)ID_TB5_CMB_SIMPLE,
        g_hInstance, NULL);
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("One"));
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("Two"));
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("Three"));
    SendMessage(hC, CB_ADDSTRING, 0, (LPARAM)TEXT("Four"));

    /* BS_OWNERDRAW button - paints itself in WM_DRAWITEM. */
    CreateWindow(TEXT("STATIC"),
        TEXT("BS_OWNERDRAW button:"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 192, 200, 14, pane, NULL, g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Owner-Draw Me"),
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        8, 208, 200, 30, pane, (HMENU)ID_TB5_OD_BTN,
        g_hInstance, NULL);

    CreateWindow(TEXT("STATIC"),
        TEXT("Listbox:"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        216, 2, 460, 14, pane, NULL, g_hInstance, NULL);
    hLB = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("LISTBOX"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        LBS_NOTIFY | LBS_HASSTRINGS,
        216, 18, 464, 250, pane, (HMENU)ID_TB5_OD_LB,
        g_hInstance, NULL);
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Red"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Green"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Blue"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Yellow"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Magenta"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Cyan"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Orange"));
    SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)TEXT("Violet"));
}

/* ===== Tab 6 - Dialogs & I/O ===== */
static void BuildTabDialogs(HWND pane) {
    HWND hGrp, hCombo;
    WNDPROC prev;
    int i;

    hGrp = CreateWindow(TEXT("BUTTON"), TEXT("MessageBox flavors"),
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | BS_GROUPBOX,
        8, 2, 340, 90, pane, (HMENU)ID_TB6_GRP,
        g_hInstance, NULL);
    prev = (WNDPROC)SetWindowLong(hGrp, GWL_WNDPROC,
                                   (LONG)GroupBoxForwardProc);
    if (!g_origGrpWndProc) g_origGrpWndProc = prev;

    CreateWindow(TEXT("STATIC"), TEXT("Buttons:"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 18, 60, 14, hGrp, NULL, g_hInstance, NULL);
    hCombo = CreateWindow(TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        72, 16, 256, 140, hGrp, (HMENU)ID_TB6_CMB_BTNS,
        g_hInstance, NULL);
    for (i = 0; i < (int)NUM_MB_BTN_FLAVORS; i++)
        SendMessage(hCombo, CB_ADDSTRING, 0,
                    (LPARAM)kMbButtonFlavors[i].label);
    SendMessage(hCombo, CB_SETCURSEL, 0, 0);

    CreateWindow(TEXT("STATIC"), TEXT("Icon:"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 40, 60, 14, hGrp, NULL, g_hInstance, NULL);
    hCombo = CreateWindow(TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        72, 38, 256, 140, hGrp, (HMENU)ID_TB6_CMB_ICON,
        g_hInstance, NULL);
    for (i = 0; i < (int)NUM_MB_ICON_FLAVORS; i++)
        SendMessage(hCombo, CB_ADDSTRING, 0,
                    (LPARAM)kMbIconFlavors[i].label);
    SendMessage(hCombo, CB_SETCURSEL, 0, 0);

    CreateWindow(TEXT("BUTTON"), TEXT("Show MsgBox"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        108, 62, 130, 22, hGrp, (HMENU)ID_TB6_BTN_MSGBOX,
        g_hInstance, NULL);

    /* Action buttons row */
    CreateWindow(TEXT("BUTTON"), TEXT("Show Dialog..."),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        8, 100, 110, 22, pane, (HMENU)ID_TB6_BTN_DIALOG,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Open File..."),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        122, 100, 110, 22, pane, (HMENU)ID_TB6_BTN_OPENFILE,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Write Tmp"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        236, 100, 90, 22, pane, (HMENU)ID_TB6_BTN_WRITE,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Read Tmp"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        330, 100, 90, 22, pane, (HMENU)ID_TB6_BTN_READ,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Copy"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        424, 100, 60, 22, pane, (HMENU)ID_TB6_BTN_COPY,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Paste"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        488, 100, 60, 22, pane, (HMENU)ID_TB6_BTN_PASTE,
        g_hInstance, NULL);

    CreateWindow(TEXT("STATIC"), TEXT("Result log (latest action):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 130, 300, 14, pane, NULL, g_hInstance, NULL);
    CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"),
        TEXT("(click any button above)"),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        8, 146, 670, 140, pane, (HMENU)ID_TB6_RESULT_EDIT,
        g_hInstance, NULL);
}

/* ===== Tab 7 - Async (timer + worker thread) ===== */
static void BuildTabAsync(HWND pane) {
    CreateWindow(TEXT("STATIC"), TEXT("SetTimer (500 ms tick):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 6, 260, 14, pane, NULL, g_hInstance, NULL);
    g_hTimerLabel = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"),
        TEXT("Timer 00:00"),
        WS_CHILD | WS_VISIBLE | ES_READONLY | ES_CENTER,
        8, 22, 180, 22, pane, (HMENU)ID_TB7_TIMER_LBL,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Start timer"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        8, 48, 85, 22, pane, (HMENU)ID_TB7_BTN_TIMER_START,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Stop timer"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        100, 48, 85, 22, pane, (HMENU)ID_TB7_BTN_TIMER_STOP,
        g_hInstance, NULL);

    CreateWindow(TEXT("STATIC"),
        TEXT("Worker thread (250 ms PostMessage):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        220, 6, 320, 14, pane, NULL, g_hInstance, NULL);
    g_hThreadLabel = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"),
        TEXT("Thread 0"),
        WS_CHILD | WS_VISIBLE | ES_READONLY | ES_CENTER,
        220, 22, 180, 22, pane, (HMENU)ID_TB7_THR_LBL,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Start thread"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        220, 48, 85, 22, pane, (HMENU)ID_TB7_BTN_THR_START,
        g_hInstance, NULL);
    CreateWindow(TEXT("BUTTON"), TEXT("Stop thread"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        310, 48, 85, 22, pane, (HMENU)ID_TB7_BTN_THR_STOP,
        g_hInstance, NULL);

    CreateWindow(TEXT("STATIC"),
        TEXT("The timer above also drives the progress bar on tab 3."),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 90, 670, 14, pane, NULL, g_hInstance, NULL);
    CreateWindow(TEXT("STATIC"),
        TEXT("Stop is synchronous: SetEvent + WaitForSingleObject(5s)."),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 108, 670, 14, pane, NULL, g_hInstance, NULL);
    CreateWindow(TEXT("STATIC"),
        TEXT("Status-bar panes (bottom) update live: Timer | Thread | last action."),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 126, 670, 14, pane, NULL, g_hInstance, NULL);
}

/* ===== Tab 8 - Toolbar + header + animate ===== */
static void BuildTabToolbar(HWND pane) {
    HWND hTb, hHdr;
    TBBUTTON tbb[6];
    HDITEM hdi;
    int i;

    CreateWindow(TEXT("STATIC"),
        TEXT("ToolbarWindow32 (system bitmaps + per-button tooltips):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 2, 500, 14, pane, NULL, g_hInstance, NULL);

    hTb = CreateWindow(TOOLBARCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS |
        CCS_NOPARENTALIGN | CCS_NORESIZE | CCS_NODIVIDER,
        8, 18, 600, 32, pane, (HMENU)ID_TB8_TOOLBAR,
        g_hInstance, NULL);
    if (hTb) {
        SendMessage(hTb, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
        SendMessage(hTb, TB_LOADIMAGES, IDB_STD_SMALL_COLOR,
                    (LPARAM)HINST_COMMCTRL);

        for (i = 0; i < 6; i++) memset(&tbb[i], 0, sizeof(TBBUTTON));
        tbb[0].iBitmap = STD_FILENEW;
        tbb[0].idCommand = IDM_FILE_NEW;
        tbb[0].fsState = TBSTATE_ENABLED;
        tbb[0].fsStyle = TBSTYLE_BUTTON;
        tbb[1].iBitmap = STD_FILEOPEN;
        tbb[1].idCommand = IDM_FILE_OPEN;
        tbb[1].fsState = TBSTATE_ENABLED;
        tbb[1].fsStyle = TBSTYLE_BUTTON;
        tbb[2].iBitmap = STD_FILESAVE;
        tbb[2].idCommand = IDM_FILE_SAVE;
        tbb[2].fsState = TBSTATE_ENABLED;
        tbb[2].fsStyle = TBSTYLE_BUTTON;
        tbb[3].fsStyle = TBSTYLE_SEP;
        tbb[4].iBitmap = STD_CUT;
        tbb[4].idCommand = IDM_EDIT_CUT;
        tbb[4].fsState = TBSTATE_ENABLED;
        tbb[4].fsStyle = TBSTYLE_BUTTON;
        tbb[5].iBitmap = STD_COPY;
        tbb[5].idCommand = IDM_EDIT_COPY;
        tbb[5].fsState = TBSTATE_ENABLED;
        tbb[5].fsStyle = TBSTYLE_BUTTON;
        SendMessage(hTb, TB_ADDBUTTONS, 6, (LPARAM)tbb);
        /* Tooltip text comes from the parent's TTN_GETDISPINFO handler in
           MainWndProc - TBSTYLE_TOOLTIPS makes the toolbar create its own
           tooltip control and ask the parent for each button's text. */
    }

    CreateWindow(TEXT("STATIC"), TEXT("SysHeader32 (standalone):"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 56, 400, 14, pane, NULL, g_hInstance, NULL);

    hHdr = CreateWindow(WC_HEADER, NULL,
        WS_CHILD | WS_VISIBLE | WS_BORDER |
        HDS_HORZ | HDS_BUTTONS,
        8, 72, 670, 22, pane, (HMENU)ID_TB8_HEADER,
        g_hInstance, NULL);
    if (hHdr) {
        memset(&hdi, 0, sizeof(hdi));
        hdi.mask = HDI_TEXT | HDI_WIDTH | HDI_FORMAT;
        hdi.fmt = HDF_LEFT | HDF_STRING;
        hdi.cxy = 200; hdi.pszText = (LPTSTR)TEXT("Column 1");
        SendMessage(hHdr, HDM_INSERTITEM, 0, (LPARAM)&hdi);
        hdi.cxy = 160; hdi.pszText = (LPTSTR)TEXT("Column 2");
        SendMessage(hHdr, HDM_INSERTITEM, 1, (LPARAM)&hdi);
        hdi.cxy = 130; hdi.pszText = (LPTSTR)TEXT("Column 3");
        SendMessage(hHdr, HDM_INSERTITEM, 2, (LPARAM)&hdi);
        hdi.cxy = 180; hdi.pszText = (LPTSTR)TEXT("Column 4");
        SendMessage(hHdr, HDM_INSERTITEM, 3, (LPARAM)&hdi);
    }

    CreateWindow(TEXT("STATIC"),
        TEXT("Toolbar buttons fire the same IDM_FILE_*/IDM_EDIT_* commands"),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 178, 670, 14, pane, NULL, g_hInstance, NULL);
    CreateWindow(TEXT("STATIC"),
        TEXT("as the menu bar. Hover for tooltips (TBSTYLE_TOOLTIPS)."),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        8, 196, 670, 14, pane, NULL, g_hInstance, NULL);
}

/* ===== Helpers ===== */
static void SwitchTab(int idx) {
    int i;
    if (idx < 0 || idx >= TAB_COUNT) return;
    for (i = 0; i < TAB_COUNT; i++) {
        if (g_hTabPanes[i])
            ShowWindow(g_hTabPanes[i], (i == idx) ? SW_SHOW : SW_HIDE);
    }
}

static void SetStatusText(int pane, LPCTSTR text) {
    if (g_hStatusBar)
        SendMessage(g_hStatusBar, SB_SETTEXT, pane, (LPARAM)text);
}

/* ===== Action handlers ===== */
static void HandleMessageBoxButton(HWND parent) {
    HWND hPane = g_hTabPanes[5];
    HWND hGrp = GetDlgItem(hPane, ID_TB6_GRP);
    HWND hBtnsCb = GetDlgItem(hGrp, ID_TB6_CMB_BTNS);
    HWND hIconCb = GetDlgItem(hGrp, ID_TB6_CMB_ICON);
    int bi = (int)SendMessage(hBtnsCb, CB_GETCURSEL, 0, 0);
    int ii = (int)SendMessage(hIconCb, CB_GETCURSEL, 0, 0);
    int result;
    TCHAR resultText[160];
    if (bi < 0) bi = 0;
    if (ii < 0) ii = 0;
    result = MessageBox(parent, TEXT("MessageBox test"),
                        TEXT("Sample App"),
                        kMbButtonFlavors[bi].flags |
                        kMbIconFlavors[ii].flags);
    wsprintf(resultText, TEXT("MessageBox returned %s (%d)"),
             MbResultName(result), result);
    SetWindowText(GetDlgItem(hPane, ID_TB6_RESULT_EDIT), resultText);
    SetStatusText(2, resultText);
    MessageBox(parent, resultText, TEXT("Sample App - Result"),
               MB_OK | MB_ICONINFORMATION);
}

/* In-memory DLGTEMPLATE for the dialog test. */
static BOOL CALLBACK SampleDialogProc(HWND hDlg, UINT msg,
                                       WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG:
        SetWindowText(hDlg, TEXT("Sample Dialog"));
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wp));
            return TRUE;
        }
        break;
    case WM_CLOSE:
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

static WORD* DlgCopyString(WORD* p, const WCHAR* s) {
    while (*s) *p++ = (WORD)*s++;
    *p++ = 0;
    return p;
}

static WORD* DlgAlignDword(WORD* p, void* base) {
    UINT_PTR off = (UINT_PTR)p - (UINT_PTR)base;
    if (off & 3) p = (WORD*)((BYTE*)p + (4 - (off & 3)));
    return p;
}

static void HandleDialogButton(HWND parent) {
    static DWORD buf32[80];
    DLGTEMPLATE* dt = (DLGTEMPLATE*)buf32;
    DLGITEMTEMPLATE* item;
    WORD* p;
    INT_PTR ret;
    TCHAR txt[160];

    memset(buf32, 0, sizeof(buf32));
    dt->style = DS_MODALFRAME | DS_CENTER | DS_SETFONT |
                WS_POPUP | WS_CAPTION | WS_SYSMENU;
    dt->dwExtendedStyle = 0;
    dt->cdit = 3;
    dt->x = 0; dt->y = 0;
    dt->cx = 180; dt->cy = 70;

    p = (WORD*)(dt + 1);
    *p++ = 0;       /* no menu */
    *p++ = 0;       /* default class */
    p = DlgCopyString(p, L"Sample Dialog");
    *p++ = 8;       /* font 8 pt */
    p = DlgCopyString(p, L"Tahoma");
    p = DlgAlignDword(p, buf32);

    /* Item 1 - STATIC label */
    item = (DLGITEMTEMPLATE*)p;
    item->style = WS_CHILD | WS_VISIBLE | SS_CENTER;
    item->dwExtendedStyle = 0;
    item->x = 10; item->y = 10; item->cx = 160; item->cy = 14;
    item->id = 0;
    p = (WORD*)(item + 1);
    *p++ = 0xFFFF; *p++ = 0x0082;          /* STATIC class atom */
    p = DlgCopyString(p, L"Hello from a real CE5 dialog!");
    *p++ = 0;
    p = DlgAlignDword(p, buf32);

    /* Item 2 - OK button */
    item = (DLGITEMTEMPLATE*)p;
    item->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    item->dwExtendedStyle = 0;
    item->x = 30; item->y = 45; item->cx = 50; item->cy = 14;
    item->id = IDOK;
    p = (WORD*)(item + 1);
    *p++ = 0xFFFF; *p++ = 0x0080;          /* BUTTON class atom */
    p = DlgCopyString(p, L"OK");
    *p++ = 0;
    p = DlgAlignDword(p, buf32);

    /* Item 3 - Cancel button */
    item = (DLGITEMTEMPLATE*)p;
    item->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
    item->dwExtendedStyle = 0;
    item->x = 100; item->y = 45; item->cx = 50; item->cy = 14;
    item->id = IDCANCEL;
    p = (WORD*)(item + 1);
    *p++ = 0xFFFF; *p++ = 0x0080;
    p = DlgCopyString(p, L"Cancel");
    *p++ = 0;
    p = DlgAlignDword(p, buf32);

    ret = DialogBoxIndirect(g_hInstance, dt, parent, SampleDialogProc);
    wsprintf(txt, TEXT("DialogBox returned %d (%s)"),
             (int)ret, MbResultName((int)ret));
    SetStatusText(2, txt);
    SetWindowText(GetDlgItem(g_hTabPanes[5], ID_TB6_RESULT_EDIT), txt);
}

static void HandleOpenFileButton(HWND parent) {
    OPENFILENAME ofn;
    TCHAR path[MAX_PATH];
    TCHAR result[MAX_PATH + 64];
    path[0] = 0;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = parent;
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter =
        TEXT("All Files (*.*)\0*.*\0Text (*.txt)\0*.txt\0");
    ofn.lpstrInitialDir = TEXT("\\");
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileName(&ofn)) {
        wsprintf(result, TEXT("Picked: %s"), path);
    } else {
        wsprintf(result, TEXT("Cancelled or failed (%lu)"),
                 (unsigned long)CommDlgExtendedError());
    }
    SetStatusText(2, result);
    SetWindowText(GetDlgItem(g_hTabPanes[5], ID_TB6_RESULT_EDIT), result);
}

static void HandleWriteFileButton(HWND parent) {
    HANDLE h;
    DWORD written;
    static const char data[] =
        "Hello from CERF Sample App!\r\n"
        "Line 2 of the test file.\r\n"
        "Line 3 - written via CreateFile + WriteFile.\r\n";
    TCHAR result[256];
    h = CreateFile(TEXT("\\sampleapp.txt"),
                   GENERIC_WRITE, 0, NULL,
                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        wsprintf(result, TEXT("CreateFile FAILED: %lu"),
                 (unsigned long)GetLastError());
    } else {
        if (WriteFile(h, data, sizeof(data) - 1, &written, NULL))
            wsprintf(result, TEXT("Wrote %lu bytes to \\sampleapp.txt"),
                     (unsigned long)written);
        else
            wsprintf(result, TEXT("WriteFile FAILED: %lu"),
                     (unsigned long)GetLastError());
        CloseHandle(h);
    }
    SetStatusText(2, result);
    SetWindowText(GetDlgItem(g_hTabPanes[5], ID_TB6_RESULT_EDIT), result);
}

static void HandleReadFileButton(HWND parent) {
    HANDLE h;
    DWORD readBytes;
    char buf[512];
    TCHAR text[512];
    TCHAR result[700];
    int i;
    h = CreateFile(TEXT("\\sampleapp.txt"),
                   GENERIC_READ, 0, NULL,
                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        wsprintf(result, TEXT("CreateFile FAILED: %lu"),
                 (unsigned long)GetLastError());
    } else {
        if (ReadFile(h, buf, sizeof(buf) - 1, &readBytes, NULL)) {
            buf[readBytes] = 0;
            for (i = 0; i < (int)readBytes && i < 511; i++)
                text[i] = (TCHAR)(unsigned char)buf[i];
            text[i] = 0;
            wsprintf(result, TEXT("Read %lu bytes:\r\n%s"),
                     (unsigned long)readBytes, text);
        } else {
            wsprintf(result, TEXT("ReadFile FAILED: %lu"),
                     (unsigned long)GetLastError());
        }
        CloseHandle(h);
    }
    SetStatusText(2, TEXT("Read complete"));
    SetWindowText(GetDlgItem(g_hTabPanes[5], ID_TB6_RESULT_EDIT), result);
}

static void HandleCopyButton(HWND parent) {
    HGLOBAL hMem;
    LPVOID p;
    static const TCHAR clipText[] =
        TEXT("CERF Sample App clipboard test ");
    SIZE_T len = (lstrlen(clipText) + 1) * sizeof(TCHAR);
    if (!OpenClipboard(parent)) {
        SetStatusText(2, TEXT("OpenClipboard failed"));
        return;
    }
    EmptyClipboard();
    hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if (hMem) {
        p = GlobalLock(hMem);
        if (p) {
            memcpy(p, clipText, len);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
            SetStatusText(2, TEXT("Copied to clipboard"));
        }
    }
    CloseClipboard();
}

static void HandlePasteButton(HWND parent) {
    HANDLE hData;
    LPCTSTR p;
    TCHAR buf[300];
    if (!OpenClipboard(parent)) {
        SetStatusText(2, TEXT("OpenClipboard failed"));
        return;
    }
    hData = GetClipboardData(CF_UNICODETEXT);
    if (hData) {
        p = (LPCTSTR)GlobalLock(hData);
        if (p) {
            wsprintf(buf, TEXT("Pasted: %s"), p);
            GlobalUnlock(hData);
            SetStatusText(2, buf);
            SetWindowText(GetDlgItem(g_hTabPanes[5], ID_TB6_RESULT_EDIT), buf);
        }
    } else {
        SetStatusText(2, TEXT("No CF_UNICODETEXT on clipboard"));
    }
    CloseClipboard();
}

static void HandleTimerStart(void) {
    if (g_timerId == 0) {
        g_timerId = SetTimer(g_hMainWnd, ID_TIMER_TICK, 500, NULL);
        if (g_timerId) SetStatusText(2, TEXT("Timer started"));
    }
}

static void HandleTimerStop(void) {
    if (g_timerId != 0) {
        KillTimer(g_hMainWnd, ID_TIMER_TICK);
        g_timerId = 0;
        SetStatusText(2, TEXT("Timer stopped"));
    }
}

static DWORD WINAPI WorkerThreadProc(LPVOID param) {
    int counter = 0;
    while (WaitForSingleObject(g_hWorkerStop, 250) == WAIT_TIMEOUT) {
        counter++;
        PostMessage(g_hMainWnd, WM_APP_THREAD_TICK, counter, 0);
    }
    return 0;
}

static void HandleThreadStart(void) {
    if (g_hWorkerThread) return;
    g_hWorkerStop = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_hWorkerStop) return;
    g_hWorkerThread = CreateThread(NULL, 0, WorkerThreadProc,
                                    NULL, 0, NULL);
    if (!g_hWorkerThread) {
        CloseHandle(g_hWorkerStop);
        g_hWorkerStop = NULL;
        return;
    }
    SetStatusText(2, TEXT("Worker thread started"));
}

static void HandleThreadStop(void) {
    if (!g_hWorkerThread) return;
    SetEvent(g_hWorkerStop);
    WaitForSingleObject(g_hWorkerThread, 5000);
    CloseHandle(g_hWorkerThread);
    CloseHandle(g_hWorkerStop);
    g_hWorkerThread = NULL;
    g_hWorkerStop = NULL;
    SetStatusText(2, TEXT("Worker thread stopped"));
}

/* ===== Main window ===== */
static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg,
                                     WPARAM wp, LPARAM lp) {
    int i;

    switch (msg) {
    case WM_CREATE: {
        RECT rcClient, rcSb, rcTab;
        TCITEM tie;
        int statusParts[3];
        int sbH;
        const TCHAR* tabNames[TAB_COUNT] = {
            TEXT("Basic"),   TEXT("Lists"),   TEXT("Sliders"), TEXT("GDI"),
            TEXT("Combos"),  TEXT("Dialogs"), TEXT("Async"),   TEXT("Toolbar")
        };

        GetClientRect(hwnd, &rcClient);

        g_hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
            WS_CHILD | WS_VISIBLE,
            0, 0, 0, 0, hwnd, (HMENU)ID_STATUS_BAR,
            g_hInstance, NULL);
        if (g_hStatusBar) {
            statusParts[0] = 200;
            statusParts[1] = 380;
            statusParts[2] = -1;
            SendMessage(g_hStatusBar, SB_SETPARTS, 3, (LPARAM)statusParts);
            SendMessage(g_hStatusBar, SB_SETTEXT, 0,
                        (LPARAM)TEXT("Timer 00:00"));
            SendMessage(g_hStatusBar, SB_SETTEXT, 1,
                        (LPARAM)TEXT("Thread 0"));
            SendMessage(g_hStatusBar, SB_SETTEXT, 2, (LPARAM)TEXT("Ready"));
            GetWindowRect(g_hStatusBar, &rcSb);
            sbH = rcSb.bottom - rcSb.top;
        } else {
            sbH = 0;
        }

        g_hTabCtrl = CreateWindow(WC_TABCONTROL, NULL,
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
            0, 0, rcClient.right, rcClient.bottom - sbH,
            hwnd, (HMENU)ID_TAB_CONTROL, g_hInstance, NULL);

        if (g_hTabCtrl) {
            for (i = 0; i < TAB_COUNT; i++) {
                tie.mask = TCIF_TEXT;
                tie.pszText = (LPTSTR)tabNames[i];
                SendMessage(g_hTabCtrl, TCM_INSERTITEM, i, (LPARAM)&tie);
            }
            GetClientRect(g_hTabCtrl, &rcTab);
            SendMessage(g_hTabCtrl, TCM_ADJUSTRECT, FALSE, (LPARAM)&rcTab);

            for (i = 0; i < TAB_COUNT; i++) {
                g_hTabPanes[i] = CreateWindow(kPaneClass, NULL,
                    WS_CHILD | WS_CLIPCHILDREN |
                    (i == 0 ? WS_VISIBLE : 0),
                    rcTab.left, rcTab.top,
                    rcTab.right - rcTab.left,
                    rcTab.bottom - rcTab.top,
                    g_hTabCtrl, NULL, g_hInstance, NULL);
            }

            BuildTabBasic  (g_hTabPanes[0]);
            BuildTabLists  (g_hTabPanes[1]);
            BuildTabSliders(g_hTabPanes[2]);
            BuildTabGdi    (g_hTabPanes[3]);
            BuildTabCombos (g_hTabPanes[4]);
            BuildTabDialogs(g_hTabPanes[5]);
            BuildTabAsync  (g_hTabPanes[6]);
            BuildTabToolbar(g_hTabPanes[7]);
        }
        return 0;
    }

    case WM_SIZE:
        if (g_hStatusBar) SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
        if (g_hTabCtrl && g_hStatusBar) {
            RECT rcClient, rcSb;
            int sbH;
            GetClientRect(hwnd, &rcClient);
            GetWindowRect(g_hStatusBar, &rcSb);
            sbH = rcSb.bottom - rcSb.top;
            MoveWindow(g_hTabCtrl, 0, 0,
                       rcClient.right, rcClient.bottom - sbH, TRUE);
        }
        return 0;

    case WM_NOTIFY: {
        LPNMHDR hdr = (LPNMHDR)lp;
        if (!hdr) return 0;
        if (hdr->idFrom == ID_TAB_CONTROL && hdr->code == TCN_SELCHANGE) {
            int idx = (int)SendMessage(g_hTabCtrl, TCM_GETCURSEL, 0, 0);
            SwitchTab(idx);
            return 0;
        }
        return 0;
    }

    case WM_TIMER:
        if (wp == ID_TIMER_TICK) {
            TCHAR buf[64];
            g_timerCounter++;
            wsprintf(buf, TEXT("Timer %02d:%02d"),
                     g_timerCounter / 60, g_timerCounter % 60);
            SetStatusText(0, buf);
            if (g_hTimerLabel) SetWindowText(g_hTimerLabel, buf);
            if (g_hProgress) {
                g_progressVal = (g_progressVal + 5) % 105;
                SendMessage(g_hProgress, PBM_SETPOS, g_progressVal, 0);
            }
        }
        return 0;

    case WM_APP_THREAD_TICK: {
        TCHAR buf[64];
        wsprintf(buf, TEXT("Thread %d"), (int)wp);
        SetStatusText(1, buf);
        if (g_hThreadLabel) SetWindowText(g_hThreadLabel, buf);
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORDLG:
        return SampleHandleCtlColor((HDC)wp);

    case WM_COMMAND: {
        int wmId = LOWORD(wp);
        int wmEvt = HIWORD(wp);

        /* Menu / context-menu / toolbar / button commands. */
        switch (wmId) {
        case IDM_FILE_NEW:
            MessageBox(hwnd, TEXT("New: not implemented"),
                       TEXT("Sample App"), MB_OK | MB_ICONINFORMATION);
            return 0;
        case IDM_FILE_OPEN:
            HandleOpenFileButton(hwnd);
            return 0;
        case IDM_FILE_SAVE:
            MessageBox(hwnd, TEXT("Save: not implemented"),
                       TEXT("Sample App"), MB_OK | MB_ICONINFORMATION);
            return 0;
        case IDM_FILE_EXIT:
        case IDM_CTX_EXIT:
            DestroyWindow(hwnd);
            return 0;
        case IDM_EDIT_CUT:
        case IDM_EDIT_COPY:
            HandleCopyButton(hwnd);
            return 0;
        case IDM_EDIT_PASTE:
            HandlePasteButton(hwnd);
            return 0;
        case IDM_EDIT_SELECTALL:
            SetStatusText(2, TEXT("Select All clicked"));
            return 0;
        case IDM_HELP_ABOUT:
        case IDM_CTX_ABOUT:
            MessageBox(hwnd,
                TEXT("CERF Comprehensive Sample App\r\n\r\n")
                TEXT("Exercises CE5 commctrl + gwes + coredll surfaces."),
                TEXT("About"), MB_OK | MB_ICONINFORMATION);
            return 0;
        case IDM_CTX_REFRESH:
            InvalidateRect(hwnd, NULL, TRUE);
            SetStatusText(2, TEXT("Window invalidated"));
            return 0;
        }

        if (wmId >= IDM_VIEW_TAB1 && wmId <= IDM_VIEW_TAB8) {
            int idx = wmId - IDM_VIEW_TAB1;
            SendMessage(g_hTabCtrl, TCM_SETCURSEL, idx, 0);
            SwitchTab(idx);
            return 0;
        }

        if (wmEvt == BN_CLICKED) {
            switch (wmId) {
            case ID_TB6_BTN_MSGBOX:
                HandleMessageBoxButton(hwnd);
                return 0;
            case ID_TB6_BTN_DIALOG:
                HandleDialogButton(hwnd);
                return 0;
            case ID_TB6_BTN_OPENFILE:
                HandleOpenFileButton(hwnd);
                return 0;
            case ID_TB6_BTN_WRITE:
                HandleWriteFileButton(hwnd);
                return 0;
            case ID_TB6_BTN_READ:
                HandleReadFileButton(hwnd);
                return 0;
            case ID_TB6_BTN_COPY:
                HandleCopyButton(hwnd);
                return 0;
            case ID_TB6_BTN_PASTE:
                HandlePasteButton(hwnd);
                return 0;
            case ID_TB7_BTN_TIMER_START:
                HandleTimerStart();
                return 0;
            case ID_TB7_BTN_TIMER_STOP:
                HandleTimerStop();
                return 0;
            case ID_TB7_BTN_THR_START:
                HandleThreadStart();
                return 0;
            case ID_TB7_BTN_THR_STOP:
                HandleThreadStop();
                return 0;
            case ID_TB4_BTN_REDRAW: {
                HWND hChild = GetDlgItem(g_hTabPanes[3], ID_TB4_PAINT_CHILD);
                if (hChild) InvalidateRect(hChild, NULL, TRUE);
                return 0;
            }
            case ID_TB1_BTN_POPUP: {
                HWND hPopup = CreateWindowEx(WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                    TEXT("LISTBOX"), NULL,
                    WS_POPUP | WS_BORDER | WS_VSCROLL |
                    LBS_NOTIFY | LBS_HASSTRINGS,
                    400, 100, 120, 120, NULL, NULL, NULL, NULL);
                if (hPopup) {
                    SendMessage(hPopup, LB_ADDSTRING, 0, (LPARAM)TEXT("popup 1"));
                    SendMessage(hPopup, LB_ADDSTRING, 0, (LPARAM)TEXT("popup 2"));
                    SendMessage(hPopup, LB_ADDSTRING, 0, (LPARAM)TEXT("popup 3"));
                    SendMessage(hPopup, LB_SETCURSEL, 0, 0);
                    ShowWindow(hPopup, SW_SHOW);
                }
                return 0;
            }
            }
        }
        return 0;
    }

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lp;
        static const COLORREF kSwatch[] = {
            RGB(255, 0, 0),    RGB(0, 255, 0),    RGB(0, 0, 255),
            RGB(255, 255, 0),  RGB(255, 0, 255),  RGB(0, 255, 255),
            RGB(255, 128, 0),  RGB(128, 0, 255),
        };
        static const TCHAR* kNames[] = {
            TEXT("Red"),     TEXT("Green"),  TEXT("Blue"),
            TEXT("Yellow"),  TEXT("Magenta"),TEXT("Cyan"),
            TEXT("Orange"),  TEXT("Violet")
        };

        /* BS_OWNERDRAW button (Tab 5). */
        if (dis && dis->CtlType == ODT_BUTTON &&
            dis->CtlID == ID_TB5_OD_BTN) {
            BOOL pushed = (dis->itemState & ODS_SELECTED) != 0;
            BOOL focus  = (dis->itemState & ODS_FOCUS) != 0;
            COLORREF top = pushed ? RGB(40, 80, 160) : RGB(120, 180, 240);
            COLORREF bot = pushed ? RGB(20, 40, 100) : RGB(40, 80, 160);
            int row;
            int height = dis->rcItem.bottom - dis->rcItem.top;
            HBRUSH hbrFr = (HBRUSH)GetStockObject(BLACK_BRUSH);
            RECT r;
            /* Vertical gradient via per-row FillRect. */
            for (row = 0; row < height; row++) {
                int rr = GetRValue(top) +
                         ((GetRValue(bot) - GetRValue(top)) * row) / height;
                int gg = GetGValue(top) +
                         ((GetGValue(bot) - GetGValue(top)) * row) / height;
                int bb = GetBValue(top) +
                         ((GetBValue(bot) - GetBValue(top)) * row) / height;
                HBRUSH hb = CreateSolidBrush(RGB(rr, gg, bb));
                RECT line = dis->rcItem;
                line.top += row;
                line.bottom = line.top + 1;
                FillRect(dis->hDC, &line, hb);
                DeleteObject(hb);
            }
            /* Border */
            r = dis->rcItem; r.bottom = r.top + 1;
            FillRect(dis->hDC, &r, hbrFr);
            r = dis->rcItem; r.top = r.bottom - 1;
            FillRect(dis->hDC, &r, hbrFr);
            r = dis->rcItem; r.right = r.left + 1;
            FillRect(dis->hDC, &r, hbrFr);
            r = dis->rcItem; r.left = r.right - 1;
            FillRect(dis->hDC, &r, hbrFr);
            /* Centered label */
            {
                TCHAR txt[32];
                int len;
                SIZE sz;
                int tx, ty;
                len = GetWindowText(dis->hwndItem, txt,
                                    sizeof(txt)/sizeof(txt[0]));
                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, RGB(255, 255, 255));
                GetTextExtentPoint32(dis->hDC, txt, len, &sz);
                tx = dis->rcItem.left +
                     (dis->rcItem.right - dis->rcItem.left - sz.cx) / 2;
                ty = dis->rcItem.top +
                     (dis->rcItem.bottom - dis->rcItem.top - sz.cy) / 2;
                if (pushed) { tx += 1; ty += 1; }
                ExtTextOut(dis->hDC, tx, ty, 0, NULL, txt, len, NULL);
            }
            if (focus) {
                RECT rf = dis->rcItem;
                rf.left += 3; rf.top += 3;
                rf.right -= 3; rf.bottom -= 3;
                DrawFocusRect(dis->hDC, &rf);
            }
            return TRUE;
        }

        if (dis && dis->CtlID == ID_TB5_OD_LB &&
            dis->itemID < (UINT)(sizeof(kSwatch)/sizeof(kSwatch[0]))) {
            HBRUSH hbrBg, hbrSw;
            COLORREF txtClr;
            RECT rcSw = dis->rcItem;
            BOOL sel = (dis->itemState & ODS_SELECTED) != 0;

            if (sel) {
                /* Selected: vertical gradient blue -> magenta, 1px-row strips. */
                int height = dis->rcItem.bottom - dis->rcItem.top;
                int hd = height > 0 ? height : 1;
                int row;
                for (row = 0; row < height; row++) {
                    int rr = 40  + (210 - 40)  * row / hd;
                    int gg = 80  + (30  - 80)  * row / hd;
                    int bb = 220 + (170 - 220) * row / hd;
                    HBRUSH hb = CreateSolidBrush(RGB(rr, gg, bb));
                    RECT line = dis->rcItem;
                    line.top += row;
                    line.bottom = line.top + 1;
                    FillRect(dis->hDC, &line, hb);
                    DeleteObject(hb);
                }
            } else {
                hbrBg = CreateSolidBrush(RGB(255, 255, 255));
                FillRect(dis->hDC, &dis->rcItem, hbrBg);
                DeleteObject(hbrBg);
            }

            rcSw.left += 4;
            rcSw.right = rcSw.left + 24;
            rcSw.top += 3;
            rcSw.bottom -= 3;
            hbrSw = CreateSolidBrush(kSwatch[dis->itemID]);
            FillRect(dis->hDC, &rcSw, hbrSw);
            DeleteObject(hbrSw);

            /* CE5 has no FrameRect; outline with four 1px FillRect strips. */
            {
                HBRUSH hbrFr = (HBRUSH)GetStockObject(BLACK_BRUSH);
                RECT r;
                r = rcSw; r.bottom = r.top + 1;     FillRect(dis->hDC, &r, hbrFr);
                r = rcSw; r.top    = r.bottom - 1;  FillRect(dis->hDC, &r, hbrFr);
                r = rcSw; r.right  = r.left + 1;    FillRect(dis->hDC, &r, hbrFr);
                r = rcSw; r.left   = r.right - 1;   FillRect(dis->hDC, &r, hbrFr);
            }

            txtClr = sel ? RGB(255, 255, 255) : RGB(0, 0, 0);
            SetTextColor(dis->hDC, txtClr);
            SetBkMode(dis->hDC, TRANSPARENT);
            ExtTextOut(dis->hDC, rcSw.right + 8, dis->rcItem.top + 3,
                       0, NULL, kNames[dis->itemID],
                       lstrlen(kNames[dis->itemID]), NULL);

            if (dis->itemState & ODS_FOCUS)
                DrawFocusRect(dis->hDC, &dis->rcItem);
            return TRUE;
        }
        return FALSE;
    }

    case WM_MEASUREITEM: {
        LPMEASUREITEMSTRUCT mis = (LPMEASUREITEMSTRUCT)lp;
        if (mis && mis->CtlID == ID_TB5_OD_LB) {
            mis->itemHeight = 24;
            return TRUE;
        }
        return FALSE;
    }

    case WM_CLOSE:
        if (g_hWorkerThread) HandleThreadStop();
        if (g_timerId)       HandleTimerStop();
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                    LPTSTR lpCmd, int nShow) {
    WNDCLASS wc;
    HMENU hFile, hEdit, hView, hHelp;
    INITCOMMONCONTROLSEX icex;
    HWND hwnd;
    MSG msg;

    g_hInstance = hInst;

    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES |
                 ICC_BAR_CLASSES      | ICC_TAB_CLASSES      |
                 ICC_UPDOWN_CLASS     | ICC_PROGRESS_CLASS   |
                 ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    /* Main window class */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = TEXT("CerfSampleApp");
    RegisterClass(&wc);

    /* Tab pane container class */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = TabPaneProc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = kPaneClass;
    RegisterClass(&wc);

    /* Custom-paint child class */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = CustomPaintChildProc;
    wc.hInstance = hInst;
    wc.hbrBackground = NULL;
    wc.lpszClassName = kPaintClass;
    RegisterClass(&wc);

    /* Menu bar */
    g_hMenu = CreateMenu();
    hFile = CreateMenu();
    AppendMenu(hFile, MF_STRING, IDM_FILE_NEW,  TEXT("&New"));
    AppendMenu(hFile, MF_STRING, IDM_FILE_OPEN, TEXT("&Open..."));
    AppendMenu(hFile, MF_STRING, IDM_FILE_SAVE, TEXT("&Save..."));
    AppendMenu(hFile, MF_SEPARATOR, 0, NULL);
    AppendMenu(hFile, MF_STRING, IDM_FILE_EXIT, TEXT("E&xit"));
    AppendMenu(g_hMenu, MF_POPUP, (UINT_PTR)hFile, TEXT("&File"));

    hEdit = CreateMenu();
    AppendMenu(hEdit, MF_STRING, IDM_EDIT_CUT,       TEXT("Cu&t"));
    AppendMenu(hEdit, MF_STRING, IDM_EDIT_COPY,      TEXT("&Copy"));
    AppendMenu(hEdit, MF_STRING, IDM_EDIT_PASTE,     TEXT("&Paste"));
    AppendMenu(hEdit, MF_SEPARATOR, 0, NULL);
    AppendMenu(hEdit, MF_STRING, IDM_EDIT_SELECTALL, TEXT("Select &All"));
    AppendMenu(g_hMenu, MF_POPUP, (UINT_PTR)hEdit, TEXT("&Edit"));

    hView = CreateMenu();
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 0, TEXT("&1 Basic"));
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 1, TEXT("&2 Lists"));
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 2, TEXT("&3 Sliders"));
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 3, TEXT("&4 GDI"));
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 4, TEXT("&5 Combos"));
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 5, TEXT("&6 Dialogs"));
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 6, TEXT("&7 Async"));
    AppendMenu(hView, MF_STRING, IDM_VIEW_TAB1 + 7, TEXT("&8 Toolbar"));
    AppendMenu(g_hMenu, MF_POPUP, (UINT_PTR)hView, TEXT("&View"));

    hHelp = CreateMenu();
    AppendMenu(hHelp, MF_STRING, IDM_HELP_ABOUT, TEXT("&About"));
    AppendMenu(g_hMenu, MF_POPUP, (UINT_PTR)hHelp, TEXT("&Help"));

    /* Right-click context menu */
    g_hCtxMenu = CreatePopupMenu();
    AppendMenu(g_hCtxMenu, MF_STRING, IDM_CTX_ABOUT,   TEXT("&About"));
    AppendMenu(g_hCtxMenu, MF_STRING, IDM_CTX_REFRESH, TEXT("&Refresh"));
    AppendMenu(g_hCtxMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(g_hCtxMenu, MF_STRING, IDM_CTX_EXIT,    TEXT("E&xit"));

    /* CE5 reports 800x480 to the guest; the desktop reserves a taskbar at
       the bottom so usable area is smaller. 700x400 with a small inset
       leaves margin on every side. */
    hwnd = CreateWindow(TEXT("CerfSampleApp"),
        TEXT("CERF Comprehensive Sample"),
        WS_VISIBLE | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
        5, 5, 700, 400,
        NULL, g_hMenu, hInst, NULL);
    g_hMainWnd = hwnd;

    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
