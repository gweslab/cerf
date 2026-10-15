#define NOMINMAX
#include "task_manager_window.h"
#include "ui_language.h"

#include <windowsx.h>
#include <commctrl.h>

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../peripherals/cerf_virt/cerf_virt_task_manager.h"
#include "../peripherals/cerf_virt/cerf_virt_task_manager_regs.h"
#include "host_dark_mode.h"
#include "host_window.h"

#include "../core/string_utils.h"

#include <cstdio>

REGISTER_SERVICE(TaskManagerWindow);

namespace {

constexpr wchar_t kWndClass[] = L"CerfTaskManagerWnd";

constexpr UINT kRefreshTimerId = 1;
constexpr UINT kRefreshMs      = 500;

constexpr int kMargin     = 8;
constexpr int kBottomBarH = 76;
constexpr int kRowH       = 26;
constexpr int kBtnW       = 90;

enum : int {
    IDC_TABS    = 2000,
    IDC_LIST    = 2001,
    IDC_RUNEDIT = 2002,
    IDC_RUN     = 2003,
    IDC_SWITCH  = 2004,
    IDC_KILL    = 2005,
    IDM_ROW_SWITCH = 2101,
    IDM_ROW_KILL   = 2102,
};

constexpr int kTabWindows   = 0;
constexpr int kTabProcesses = 1;

constexpr COLORREF kClrOk   = RGB(0, 140, 0);
constexpr COLORREF kClrFail = RGB(190, 0, 0);
constexpr COLORREF kClrInfo = RGB(96, 96, 96);

/* Dark-mode tab fills (match the HostDarkMode dialog/hot palette). */
constexpr COLORREF kTabStripBg = RGB(32, 32, 32);
constexpr COLORREF kTabSelBg   = RGB(60, 60, 60);
constexpr COLORREF kTabText    = RGB(230, 230, 230);

}

const wchar_t* TaskManagerWindow::ActionName(uint32_t code) const {
    switch (code) {
        case CerfVirt::kTmCmdKill:        return emu_.Get<UiLanguage>().Text("task_manager.kill");
        case CerfVirt::kTmCmdSwitchTo:    return emu_.Get<UiLanguage>().Text("task_manager.switch_to");
        case CerfVirt::kTmCmdSwitchToWin: return emu_.Get<UiLanguage>().Text("task_manager.switch_to");
        case CerfVirt::kTmCmdRun:         return emu_.Get<UiLanguage>().Text("common.run");
        case CerfVirt::kTmCmdList:        return emu_.Get<UiLanguage>().Text("task_manager.list");
        case CerfVirt::kTmCmdListWindows: return emu_.Get<UiLanguage>().Text("task_manager.list");
        default:                          return emu_.Get<UiLanguage>().Text("task_manager.command");
    }
}


bool TaskManagerWindow::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void TaskManagerWindow::OnReady() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &TaskManagerWindow::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hIcon         = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = kWndClass;
    RegisterClassExW(&wc);   /* ERROR_CLASS_ALREADY_EXISTS is benign */
}

void TaskManagerWindow::Show() {
    if (hwnd_) {
        if (IsIconic(hwnd_)) ShowWindow(hwnd_, SW_RESTORE);
        SetForegroundWindow(hwnd_);
        return;
    }

    HWND owner = emu_.Get<HostWindow>().Hwnd();
    const DWORD style = WS_OVERLAPPEDWINDOW;
    RECT wr = { 0, 0, 560, 420 };
    AdjustWindowRectEx(&wr, style, FALSE, 0);
    hwnd_ = CreateWindowExW(0, kWndClass, emu_.Get<UiLanguage>().Text("task_manager.guest_task_manager"), style,
                            CW_USEDEFAULT, CW_USEDEFAULT,
                            wr.right - wr.left, wr.bottom - wr.top,
                            owner, nullptr, GetModuleHandleW(nullptr), this);
    if (!hwnd_) return;

    BuildControls();
    LayoutControls();

    auto& dm = emu_.Get<HostDarkMode>();
    dm.ApplyToDialog(hwnd_);
    if (dm.IsDark()) list_.ApplyDarkColors(dm.BgColor(), dm.TextColor());

    ShowWindow(hwnd_, SW_SHOW);
    SetTimer(hwnd_, kRefreshTimerId, kRefreshMs, nullptr);

    awaiting_first_ = true;
    RequestActiveList();
    SetStatus(emu_.Get<UiLanguage>().Text("task_manager.waiting_for_guest"), kClrInfo);
}

void TaskManagerWindow::BuildControls() {
    INITCOMMONCONTROLSEX icc = { sizeof(icc),
                                 ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES };
    InitCommonControlsEx(&icc);

    HINSTANCE inst = GetModuleHandleW(nullptr);
    HFONT gui = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    auto mk = [&](const wchar_t* cls, const wchar_t* text, DWORD style,
                  int id) {
        HWND h = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                                 0, 0, 0, 0, hwnd_, (HMENU)(INT_PTR)id,
                                 inst, nullptr);
        SendMessageW(h, WM_SETFONT, (WPARAM)gui, TRUE);
        return h;
    };

    /* Tab controls have no uxtheme dark class, so in dark mode we owner-draw the
       tab buttons (WM_DRAWITEM) and dark-fill the strip behind them via a
       subclass; classic comctl would otherwise paint them light. */
    const bool dark = emu_.Get<HostDarkMode>().IsDark();
    DWORD tab_style = WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS;
    if (dark) tab_style |= TCS_OWNERDRAWFIXED;
    tabs_ = CreateWindowExW(0, WC_TABCONTROLW, L"", tab_style,
                            0, 0, 0, 0, hwnd_, (HMENU)(INT_PTR)IDC_TABS,
                            inst, nullptr);
    SendMessageW(tabs_, WM_SETFONT, (WPARAM)gui, TRUE);
    TCITEMW ti = {};
    ti.mask    = TCIF_TEXT;
    ti.pszText = (LPWSTR)emu_.Get<UiLanguage>().Text("task_manager.windows");   TabCtrl_InsertItem(tabs_, kTabWindows, &ti);
    ti.pszText = (LPWSTR)emu_.Get<UiLanguage>().Text("task_manager.processes"); TabCtrl_InsertItem(tabs_, kTabProcesses, &ti);
    if (dark) {
        SetWindowLongPtrW(tabs_, GWLP_USERDATA, (LONG_PTR)this);
        tabs_base_proc_ = (WNDPROC)SetWindowLongPtrW(
            tabs_, GWLP_WNDPROC, (LONG_PTR)&TaskManagerWindow::TabProcStatic);
    }

    list_ = TaskManagerListView{};   /* default mode = Windows, matches tab 0 */
    list_.Create(hwnd_, IDC_LIST, gui, emu_.Get<UiLanguage>());

    btn_switch_ = mk(L"BUTTON", emu_.Get<UiLanguage>().Text("common.switch_to"), BS_PUSHBUTTON | WS_TABSTOP, IDC_SWITCH);
    btn_kill_   = mk(L"BUTTON", emu_.Get<UiLanguage>().Text("common.kill"),      BS_PUSHBUTTON | WS_TABSTOP, IDC_KILL);
    run_label_  = mk(L"STATIC", emu_.Get<UiLanguage>().Text("task_manager.run"), 0, 0);
    run_edit_   = mk(L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                     IDC_RUNEDIT);
    btn_run_    = mk(L"BUTTON", emu_.Get<UiLanguage>().Text("common.run"), BS_DEFPUSHBUTTON | WS_TABSTOP, IDC_RUN);
    status_     = mk(L"STATIC", L"", SS_LEFTNOWORDWRAP, 0);

    SendMessageW(run_edit_, EM_SETLIMITTEXT, CerfVirt::kTmRunMaxWchars, 0);
    SetWindowLongPtrW(run_edit_, GWLP_USERDATA, (LONG_PTR)this);
    run_edit_base_proc_ = (WNDPROC)SetWindowLongPtrW(
        run_edit_, GWLP_WNDPROC, (LONG_PTR)&TaskManagerWindow::RunEditProcStatic);
}

void TaskManagerWindow::LayoutControls() {
    RECT rc;
    GetClientRect(hwnd_, &rc);
    const int w = rc.right, h = rc.bottom;

    const int tabs_bottom = h - kBottomBarH - kMargin;
    MoveWindow(tabs_, kMargin, kMargin, w - 2 * kMargin,
               tabs_bottom - kMargin, TRUE);

    RECT tr = { kMargin, kMargin, w - kMargin, tabs_bottom };
    TabCtrl_AdjustRect(tabs_, FALSE, &tr);   /* tab window rect -> display rect */
    list_.Move(tr.left, tr.top, tr.right - tr.left, tr.bottom - tr.top);

    const int row1 = h - kBottomBarH;
    MoveWindow(btn_switch_, kMargin, row1, kBtnW, kRowH, TRUE);
    MoveWindow(btn_kill_, kMargin + kBtnW + 6, row1, kBtnW, kRowH, TRUE);

    const int row2    = row1 + kRowH + 8;
    const int label_w = 34;
    const int edit_w  = w - 2 * kMargin - label_w - kBtnW - 12 - 170;
    MoveWindow(run_label_, kMargin, row2 + 4, label_w, kRowH - 6, TRUE);
    MoveWindow(run_edit_, kMargin + label_w, row2,
               edit_w > 80 ? edit_w : 80, kRowH - 2, TRUE);
    MoveWindow(btn_run_, kMargin + label_w + (edit_w > 80 ? edit_w : 80) + 6,
               row2, kBtnW, kRowH, TRUE);
    MoveWindow(status_, kMargin + label_w + (edit_w > 80 ? edit_w : 80) +
               kBtnW + 12, row2 + 4, 164, kRowH - 6, TRUE);
}

void TaskManagerWindow::RequestActiveList() {
    auto& svc = emu_.Get<CerfVirtTaskManager>();
    if (list_.GetMode() == TaskManagerListView::Mode::Windows)
        svc.RequestWindowList();
    else
        svc.RequestProcessList();
}

void TaskManagerWindow::OnTabChanged() {
    const int sel = TabCtrl_GetCurSel(tabs_);
    list_.SetMode(sel == kTabProcesses ? TaskManagerListView::Mode::Processes
                                       : TaskManagerListView::Mode::Windows);
    awaiting_first_ = true;
    RequestActiveList();
    SetStatus(emu_.Get<UiLanguage>().Text("task_manager.waiting_for_guest"), kClrInfo);
}

void TaskManagerWindow::OnTick() {
    auto& svc = emu_.Get<CerfVirtTaskManager>();
    RequestActiveList();

    if (auto r = svc.TakeActionResult()) {
        std::wstring text;
        if (r->code == CerfVirt::kTmCmdRun) {
            if (r->ticket == run_ticket_) {
                if (r->ok) {
                    SetStatus(emu_.Get<UiLanguage>().Text("task_manager.success"), kClrOk);
                } else {
                    text = emu_.Get<UiLanguage>().Format("task_manager.failed",
                        {{"error", std::to_string(r->guest_err)}});
                    SetStatus(text, kClrFail);
                }
            }
        } else if (r->code == CerfVirt::kTmCmdList ||
                   r->code == CerfVirt::kTmCmdListWindows) {
            if (!r->ok) {
                text = emu_.Get<UiLanguage>().Format("task_manager.list_failed",
                    {{"error", std::to_string(r->guest_err)}});
                SetStatus(text, kClrFail);
            }
        } else if (r->ok) {
            text = emu_.Get<UiLanguage>().Format("task_manager.action_done",
                {{"action", WideToUtf8(ActionName(r->code))}});
            SetStatus(text, kClrOk);
        } else {
            text = emu_.Get<UiLanguage>().Format("task_manager.action_failed", {
                {"action", WideToUtf8(ActionName(r->code))},
                {"error", std::to_string(r->guest_err)},
            });
            SetStatus(text, kClrFail);
        }
    }

    auto snap = svc.GetSnapshot();
    if (list_.Update(snap)) {
        if (awaiting_first_) {
            SetStatus(L"", kClrInfo);   /* replaces "Waiting for guest…" */
            awaiting_first_ = false;
        }
        UpdateTitle(snap);
    }
}

void TaskManagerWindow::UpdateTitle(const CerfVirtTaskManager::Snapshot& snap) {
    const auto& language = emu_.Get<UiLanguage>();
    std::wstring title;
    if (list_.GetMode() == TaskManagerListView::Mode::Windows) {
        title = language.Format("task_manager.program_count",
                                {{"count", std::to_string(list_.DisplayedCount())}});
    } else if (snap.guest_total > snap.procs.size()) {
        title = language.Format("task_manager.process_count_partial", {
            {"count", std::to_string(snap.procs.size())},
            {"total", std::to_string(snap.guest_total)},
        });
    } else {
        title = language.Format("task_manager.process_count",
                                {{"count", std::to_string(snap.procs.size())}});
    }
    SetWindowTextW(hwnd_, title.c_str());
}

void TaskManagerWindow::DoSwitchTo() {
    auto& svc = emu_.Get<CerfVirtTaskManager>();
    if (list_.GetMode() == TaskManagerListView::Mode::Windows) {
        uint32_t hwnd, pid;
        if (!list_.SelectedWindow(&hwnd, &pid)) {
            SetStatus(emu_.Get<UiLanguage>().Text("task_manager.no_window_selected"), kClrFail);
            return;
        }
        svc.RequestSwitchToWindow(hwnd);
    } else {
        uint32_t pid;
        if (!list_.SelectedProc(&pid)) {
            SetStatus(emu_.Get<UiLanguage>().Text("task_manager.no_process_selected"), kClrFail);
            return;
        }
        svc.RequestSwitchTo(pid);
    }
    SetStatus(emu_.Get<UiLanguage>().Text("task_manager.switching"), kClrInfo);
}

void TaskManagerWindow::DoKill() {
    uint32_t pid;
    if (list_.GetMode() == TaskManagerListView::Mode::Windows) {
        uint32_t hwnd;
        if (!list_.SelectedWindow(&hwnd, &pid)) {
            SetStatus(emu_.Get<UiLanguage>().Text("task_manager.no_window_selected"), kClrFail);
            return;
        }
    } else if (!list_.SelectedProc(&pid)) {
        SetStatus(emu_.Get<UiLanguage>().Text("task_manager.no_process_selected"), kClrFail);
        return;
    }
    emu_.Get<CerfVirtTaskManager>().RequestKill(pid);
    SetStatus(emu_.Get<UiLanguage>().Text("task_manager.killing"), kClrInfo);
}

void TaskManagerWindow::DoRun() {
    wchar_t buf[CerfVirt::kTmRunMaxWchars + 1] = { 0 };
    GetWindowTextW(run_edit_, buf, (int)(CerfVirt::kTmRunMaxWchars + 1));
    const std::wstring cmd = buf;
    if (cmd.empty()) { SetStatus(emu_.Get<UiLanguage>().Text("task_manager.enter_a_command"), kClrFail); return; }
    run_ticket_ = emu_.Get<CerfVirtTaskManager>().RequestRun(cmd);
    if (run_ticket_ == 0) { SetStatus(emu_.Get<UiLanguage>().Text("task_manager.failure_status"), kClrFail); return; }
    SetStatus(emu_.Get<UiLanguage>().Text("task_manager.running"), kClrInfo);
}

void TaskManagerWindow::ShowRowMenu(int item, POINT screen_pt) {
    list_.SelectRow(item);
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, IDM_ROW_SWITCH, emu_.Get<UiLanguage>().Text("common.switch_to"));
    AppendMenuW(m, MF_STRING, IDM_ROW_KILL, emu_.Get<UiLanguage>().Text("common.kill"));
    TrackPopupMenu(m, TPM_RIGHTBUTTON, screen_pt.x, screen_pt.y, 0, hwnd_,
                   nullptr);
    DestroyMenu(m);
}

void TaskManagerWindow::DrawTab(const DRAWITEMSTRUCT* di) {
    const bool sel = (di->itemState & ODS_SELECTED) != 0;
    SetDCBrushColor(di->hDC, sel ? kTabSelBg : kTabStripBg);
    FillRect(di->hDC, &di->rcItem, (HBRUSH)GetStockObject(DC_BRUSH));

    wchar_t txt[32] = {};
    TCITEMW ti = {};
    ti.mask       = TCIF_TEXT;
    ti.pszText    = txt;
    ti.cchTextMax = 31;
    TabCtrl_GetItem(tabs_, di->itemID, &ti);

    SetTextColor(di->hDC, kTabText);
    SetBkMode(di->hDC, TRANSPARENT);
    RECT rc = di->rcItem;
    DrawTextW(di->hDC, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void TaskManagerWindow::SetStatus(const std::wstring& text, COLORREF clr) {
    status_clr_ = clr;
    SetWindowTextW(status_, text.c_str());
    InvalidateRect(status_, nullptr, TRUE);
}

LRESULT CALLBACK TaskManagerWindow::RunEditProcStatic(HWND hwnd, UINT msg,
                                                      WPARAM wp, LPARAM lp) {
    auto* self = reinterpret_cast<TaskManagerWindow*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_KEYDOWN && wp == VK_RETURN) {
        PostMessageW(GetParent(hwnd), WM_COMMAND,
                     MAKEWPARAM(IDC_RUN, BN_CLICKED), 0);
        return 0;
    }
    if (msg == WM_CHAR && wp == L'\r') return 0;   /* swallow the beep */
    return CallWindowProcW(self->run_edit_base_proc_, hwnd, msg, wp, lp);
}

LRESULT CALLBACK TaskManagerWindow::TabProcStatic(HWND hwnd, UINT msg,
                                                  WPARAM wp, LPARAM lp) {
    auto* self = reinterpret_cast<TaskManagerWindow*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (!self || !self->tabs_base_proc_)
        return DefWindowProcW(hwnd, msg, wp, lp);
    if (msg == WM_ERASEBKGND) {
        RECT rc;
        GetClientRect(hwnd, &rc);
        SetDCBrushColor((HDC)wp, kTabStripBg);
        FillRect((HDC)wp, &rc, (HBRUSH)GetStockObject(DC_BRUSH));
        return 1;
    }
    return CallWindowProcW(self->tabs_base_proc_, hwnd, msg, wp, lp);
}

LRESULT CALLBACK TaskManagerWindow::WndProcStatic(HWND hwnd, UINT msg,
                                                  WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    auto* self = reinterpret_cast<TaskManagerWindow*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (!self) return DefWindowProcW(hwnd, msg, wp, lp);
    return self->WndProc(hwnd, msg, wp, lp);
}

LRESULT TaskManagerWindow::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_SIZE:
            LayoutControls();
            return 0;

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize = { 480, 320 };
            return 0;
        }

        case WM_TIMER:
            if (wp == kRefreshTimerId) OnTick();
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_RUN:         DoRun();      return 0;
                case IDC_SWITCH:
                case IDM_ROW_SWITCH:  DoSwitchTo(); return 0;
                case IDC_KILL:
                case IDM_ROW_KILL:    DoKill();     return 0;
            }
            return 0;

        case WM_DRAWITEM: {
            auto* di = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
            if (di->CtlType == ODT_TAB && di->hwndItem == tabs_) {
                DrawTab(di);
                return TRUE;
            }
            break;
        }

        case WM_NOTIFY: {
            auto* hdr = reinterpret_cast<NMHDR*>(lp);
            if (hdr->hwndFrom == tabs_ && hdr->code == TCN_SELCHANGE) {
                OnTabChanged();
                return 0;
            }
            if (hdr->hwndFrom == list_.Hwnd() && hdr->code == NM_RCLICK) {
                auto* ia = reinterpret_cast<NMITEMACTIVATE*>(lp);
                POINT pt = ia->ptAction;
                ClientToScreen(list_.Hwnd(), &pt);
                ShowRowMenu(ia->iItem, pt);
                return 0;
            }
            break;
        }

        case WM_CTLCOLORSTATIC: {
            auto& dm = emu_.Get<HostDarkMode>();
            if ((HWND)lp == status_) {
                HDC dc = (HDC)wp;
                SetTextColor(dc, status_clr_);
                SetBkMode(dc, TRANSPARENT);
                if (dm.IsDark()) {
                    SetBkColor(dc, dm.BgColor());
                    return (LRESULT)dm.BgBrush();
                }
                return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
            }
            LRESULT br;
            if (dm.HandleCtlColor(msg, wp, br)) return br;
            break;
        }

        case WM_CTLCOLORDLG:
        case WM_CTLCOLORBTN:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX: {
            LRESULT br;
            if (emu_.Get<HostDarkMode>().HandleCtlColor(msg, wp, br)) return br;
            break;
        }

        case WM_ERASEBKGND:
            if (emu_.Get<HostDarkMode>().EraseBackground((HDC)wp, hwnd))
                return 1;
            break;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd, kRefreshTimerId);
            hwnd_ = nullptr;
            tabs_ = run_edit_ = btn_run_ = btn_switch_ = btn_kill_ = nullptr;
            run_label_ = status_ = nullptr;
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
