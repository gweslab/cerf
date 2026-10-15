#define NOMINMAX
#include "task_manager_list_view.h"
#include "ui_language.h"

#include <commctrl.h>
#include <uxtheme.h>

#include <cstdio>

namespace {

bool SameProcs(const std::vector<CerfVirtTaskManager::ProcEntry>& a,
               const std::vector<CerfVirtTaskManager::ProcEntry>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const auto& x = a[i];
        const auto& y = b[i];
        if (x.pid != y.pid || x.parent_pid != y.parent_pid ||
            x.thread_count != y.thread_count ||
            x.base_priority != y.base_priority ||
            x.mem_base != y.mem_base || x.name != y.name)
            return false;
    }
    return true;
}

bool SameWins(const std::vector<CerfVirtTaskManager::WinEntry>& a,
              const std::vector<CerfVirtTaskManager::WinEntry>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const auto& x = a[i];
        const auto& y = b[i];
        if (x.hwnd != y.hwnd || x.pid != y.pid || x.thread_id != y.thread_id ||
            x.visible != y.visible || x.title != y.title)
            return false;
    }
    return true;
}

}  /* namespace */

HWND TaskManagerListView::Create(HWND parent, int ctrl_id, HFONT font, UiLanguage& language) {
    language_ = &language;
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    list_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                            LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                            0, 0, 0, 0, parent, (HMENU)(INT_PTR)ctrl_id,
                            GetModuleHandleW(nullptr), nullptr);
    SendMessageW(list_, WM_SETFONT, (WPARAM)font, TRUE);
    ListView_SetExtendedListViewStyle(list_,
                                      LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP);
    SetColumns();
    return list_;
}

void TaskManagerListView::ApplyDarkColors(COLORREF bg, COLORREF text) {
    ListView_SetBkColor(list_, bg);
    ListView_SetTextBkColor(list_, bg);
    ListView_SetTextColor(list_, text);
    /* ApplyToDialog themes the listview (and thus its header) DarkMode_Explorer,
       which darkens rows but leaves the header light; DarkMode_ItemsView is the
       theme class that darkens the column-header background. */
    SetWindowTheme(ListView_GetHeader(list_), L"DarkMode_ItemsView", nullptr);
    /* The themed header background is dark but its text stays black, and the
       header's NM_CUSTOMDRAW is sent to the listview (not our dialog) - so
       subclass the listview to recolor the header text via custom draw. */
    header_text_ = text;
    SetWindowLongPtrW(list_, GWLP_USERDATA, (LONG_PTR)this);
    list_base_proc_ = (WNDPROC)SetWindowLongPtrW(
        list_, GWLP_WNDPROC, (LONG_PTR)&TaskManagerListView::ListProcStatic);
}

LRESULT CALLBACK TaskManagerListView::ListProcStatic(HWND hwnd, UINT msg,
                                                     WPARAM wp, LPARAM lp) {
    auto* self = reinterpret_cast<TaskManagerListView*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (!self || !self->list_base_proc_)
        return DefWindowProcW(hwnd, msg, wp, lp);
    if (msg == WM_NOTIFY) {
        auto* hdr = reinterpret_cast<NMHDR*>(lp);
        if (hdr->hwndFrom == ListView_GetHeader(hwnd) &&
            hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMCUSTOMDRAW*>(lp);
            if (cd->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->dwDrawStage == CDDS_ITEMPREPAINT) {
                SetTextColor(cd->hdc, self->header_text_);
                return CDRF_NEWFONT;
            }
        }
    }
    return CallWindowProcW(self->list_base_proc_, hwnd, msg, wp, lp);
}

void TaskManagerListView::Move(int x, int y, int w, int h) {
    MoveWindow(list_, x, y, w, h, TRUE);
}

void TaskManagerListView::SelectRow(int item) {
    if (item < 0) return;
    ListView_SetItemState(list_, item, LVIS_SELECTED | LVIS_FOCUSED,
                          LVIS_SELECTED | LVIS_FOCUSED);
}

void TaskManagerListView::SetMode(Mode m) {
    if (m == mode_) return;
    mode_ = m;
    ListView_DeleteAllItems(list_);
    SetColumns();
    procs_.clear();
    wins_.clear();
    shown_gen_ = 0;
    displayed_ = 0;
}

void TaskManagerListView::SetColumns() {
    HWND hdr = ListView_GetHeader(list_);
    const int n = hdr ? (int)SendMessageW(hdr, HDM_GETITEMCOUNT, 0, 0) : 0;
    for (int i = n - 1; i >= 0; --i) ListView_DeleteColumn(list_, i);

    struct Col { const wchar_t* title; int width; };
    const Col kWin[]  = {
        { language_->Text("task_manager.column.title"), 230 }, { L"HWND", 90 }, { L"PID", 90 }, { language_->Text("task_manager.column.visible"), 60 },
    };
    const Col kProc[] = {
        { language_->Text("task_manager.column.process"), 150 }, { L"PID", 90 }, { language_->Text("task_manager.column.parent"), 90 },
        { language_->Text("task_manager.column.threads"), 60 }, { language_->Text("task_manager.column.priority"), 60 }, { language_->Text("task_manager.column.mem_base"), 90 },
    };
    const Col* cols = (mode_ == Mode::Windows) ? kWin : kProc;
    const int  cnt  = (mode_ == Mode::Windows) ? 4 : 6;
    for (int i = 0; i < cnt; ++i) {
        LVCOLUMNW c = {};
        c.mask    = LVCF_TEXT | LVCF_WIDTH;
        c.pszText = (LPWSTR)cols[i].title;
        c.cx      = cols[i].width;
        ListView_InsertColumn(list_, i, &c);
    }
}

bool TaskManagerListView::Update(const CerfVirtTaskManager::Snapshot& snap) {
    if (snap.gen == shown_gen_) return false;
    const bool first = shown_gen_ == 0;
    shown_gen_ = snap.gen;
    if (mode_ == Mode::Windows) {
        if (!first && SameWins(snap.wins, wins_)) return false;
        wins_ = snap.wins;
    } else {
        if (!first && SameProcs(snap.procs, procs_)) return false;
        procs_ = snap.procs;
    }
    Fill();
    return true;
}

void TaskManagerListView::Fill() {
    uint32_t sel = 0;
    const bool had_sel = SelectedLParam(&sel);

    SendMessageW(list_, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(list_);
    wchar_t buf[64];

    if (mode_ == Mode::Windows) {
        /* One row per process (Zune has no working toolhelp, so this window
           walk IS the process list - same one-per-PID collapse xplorer's task
           manager does). The representative is the process's best top-level
           window: a visible, titled one wins over a hidden helper window. */
        std::vector<CerfVirtTaskManager::WinEntry> rows;
        std::vector<int> score;
        for (const auto& wd : wins_) {
            const int s = (wd.visible ? 2 : 0) + (wd.title.empty() ? 0 : 1);
            size_t k = 0;
            for (; k < rows.size(); ++k)
                if (rows[k].pid == wd.pid) break;
            if (k == rows.size()) { rows.push_back(wd); score.push_back(s); }
            else if (s > score[k]) { rows[k] = wd; score[k] = s; }
        }
        for (int i = 0; i < (int)rows.size(); ++i) {
            const auto& wd = rows[(size_t)i];
            LVITEMW it = {};
            it.mask    = LVIF_TEXT | LVIF_PARAM;
            it.iItem   = i;
            it.pszText = (LPWSTR)(wd.title.empty() ? language_->Text("task_manager.column.no_title")
                                                   : wd.title.c_str());
            it.lParam  = (LPARAM)wd.hwnd;
            ListView_InsertItem(list_, &it);
            _snwprintf_s(buf, _TRUNCATE, L"0x%08X", wd.hwnd);
            ListView_SetItemText(list_, i, 1, buf);
            _snwprintf_s(buf, _TRUNCATE, L"0x%08X", wd.pid);
            ListView_SetItemText(list_, i, 2, buf);
            ListView_SetItemText(list_, i, 3,
                                 (LPWSTR)(wd.visible ? language_->Text("common.yes") : language_->Text("common.no")));
            if (had_sel && wd.hwnd == sel) SelectRow(i);
        }
        displayed_ = (int)rows.size();
    } else {
        for (int i = 0; i < (int)procs_.size(); ++i) {
            const auto& p = procs_[(size_t)i];
            LVITEMW it = {};
            it.mask    = LVIF_TEXT | LVIF_PARAM;
            it.iItem   = i;
            it.pszText = (LPWSTR)p.name.c_str();
            it.lParam  = (LPARAM)p.pid;
            ListView_InsertItem(list_, &it);
            _snwprintf_s(buf, _TRUNCATE, L"0x%08X", p.pid);
            ListView_SetItemText(list_, i, 1, buf);
            _snwprintf_s(buf, _TRUNCATE, L"0x%08X", p.parent_pid);
            ListView_SetItemText(list_, i, 2, buf);
            _snwprintf_s(buf, _TRUNCATE, L"%u", p.thread_count);
            ListView_SetItemText(list_, i, 3, buf);
            _snwprintf_s(buf, _TRUNCATE, L"%d", p.base_priority);
            ListView_SetItemText(list_, i, 4, buf);
            _snwprintf_s(buf, _TRUNCATE, L"0x%08X", p.mem_base);
            ListView_SetItemText(list_, i, 5, buf);
            if (had_sel && p.pid == sel) SelectRow(i);
        }
        displayed_ = (int)procs_.size();
    }
    SendMessageW(list_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(list_, nullptr, TRUE);
}

bool TaskManagerListView::SelectedLParam(uint32_t* out) const {
    const int i = ListView_GetNextItem(list_, -1, LVNI_SELECTED);
    if (i < 0) return false;
    LVITEMW it = {};
    it.mask  = LVIF_PARAM;
    it.iItem = i;
    if (!ListView_GetItem(list_, &it)) return false;
    *out = (uint32_t)it.lParam;
    return true;
}

bool TaskManagerListView::SelectedProc(uint32_t* pid) const {
    if (mode_ != Mode::Processes) return false;
    return SelectedLParam(pid);
}

bool TaskManagerListView::SelectedWindow(uint32_t* hwnd, uint32_t* pid) const {
    if (mode_ != Mode::Windows) return false;
    uint32_t h = 0;
    if (!SelectedLParam(&h)) return false;
    *hwnd = h;
    *pid  = 0;
    for (const auto& wd : wins_)
        if (wd.hwnd == h) { *pid = wd.pid; break; }
    return true;
}
