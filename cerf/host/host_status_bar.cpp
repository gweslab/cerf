#define NOMINMAX

#include "host_status_bar.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "host_widget.h"
#include "host_widget_registry.h"

REGISTER_SERVICE(HostStatusBar);

namespace {
constexpr wchar_t  kStatusClass[] = L"CerfHostStatusBar";
constexpr int      kIconBoxW      = 26;
constexpr UINT     kTickTimerId   = 1;
constexpr UINT     kTickMs        = 100;
constexpr COLORREF kClrBg         = RGB(32, 32, 32);
constexpr COLORREF kClrSep        = RGB(60, 60, 60);
}  /* namespace */

HostStatusBar::~HostStatusBar() {
    if (bg_brush_) DeleteObject(bg_brush_);
    if (sep_pen_)  DeleteObject(sep_pen_);
}

void HostStatusBar::OnReady() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &HostStatusBar::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kStatusClass;
    if (RegisterClassExW(&wc) == 0) {
        const DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            LOG(Caution, "HostStatusBar: RegisterClassExW failed (gle=%lu)\n", err);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
    bg_brush_ = CreateSolidBrush(kClrBg);
    sep_pen_  = CreatePen(PS_SOLID, 1, kClrSep);
}

void HostStatusBar::CreateOn(HWND parent, const RECT& rect) {
    hwnd_ = CreateWindowExW(0, kStatusClass, L"",
                            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                            rect.left, rect.top,
                            rect.right - rect.left, rect.bottom - rect.top,
                            parent, nullptr, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        LOG(Caution, "HostStatusBar: CreateWindowExW failed (gle=%lu)\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    /* The tooltip window class lives in ICC_BAR_CLASSES, NOT ICC_STANDARD_CLASSES
       — without it CreateWindowExW(TOOLTIPS_CLASSW) yields a dead control and no
       tip ever shows. */
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_BAR_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    tip_hwnd_ = CreateWindowExW(0, TOOLTIPS_CLASSW, nullptr,
                                WS_POPUP | TTS_ALWAYSTIP, 0, 0, 0, 0,
                                hwnd_, nullptr, GetModuleHandleW(nullptr), nullptr);
    RebuildTooltips();
    SetTimer(hwnd_, kTickTimerId, kTickMs, nullptr);
}

void HostStatusBar::Reposition(const RECT& r) {
    if (hwnd_) MoveWindow(hwnd_, r.left, r.top,
                          r.right - r.left, r.bottom - r.top, TRUE);
}

bool HostStatusBar::Relayout(const std::vector<HostWidget*>& ordered) {
    if (!hwnd_) return false;
    RECT rc;
    GetClientRect(hwnd_, &rc);
    const int total_slots = rc.right > 0 ? rc.right / kIconBoxW : 0;

    /* ordered is sorted by (Group, Name); InputControl widgets are the tail.
       They pin to the right and always show; device widgets fill the rest and
       drop the leftmost on overflow. */
    int term_count = 0;
    for (auto* w : ordered)
        if (w->Group() == WidgetGroup::InputControl) ++term_count;
    const int dev_count = (int)ordered.size() - term_count;

    const int term_show = term_count < total_slots ? term_count : total_slots;
    const int dev_slots = total_slots - term_show > 0 ? total_slots - term_show : 0;
    const int dev_show  = dev_count < dev_slots ? dev_count : dev_slots;

    std::vector<HostWidget*> vis;
    vis.reserve((size_t)(dev_show + term_show));
    for (int i = 0; i < dev_show; ++i) vis.push_back(ordered[(size_t)i]);
    for (int j = term_count - term_show; j < term_count; ++j)
        vis.push_back(ordered[(size_t)(dev_count + j)]);

    const int block_left = rc.right - (int)vis.size() * kIconBoxW;
    std::vector<std::pair<HostWidget*, RECT>> nl;
    nl.reserve(vis.size());
    for (size_t k = 0; k < vis.size(); ++k) {
        RECT box = { block_left + (int)k * kIconBoxW, rc.top,
                     block_left + (int)(k + 1) * kIconBoxW, rc.bottom };
        nl.push_back({ vis[k], box });
    }

    bool changed = nl.size() != layout_.size();
    for (size_t i = 0; !changed && i < nl.size(); ++i)
        if (nl[i].first != layout_[i].first ||
            !EqualRect(&nl[i].second, &layout_[i].second))
            changed = true;

    layout_.swap(nl);
    if (changed) RebuildTooltips();
    return changed;
}

void HostStatusBar::RebuildTooltips() {
    if (!tip_hwnd_ || !hwnd_) return;

    for (size_t i = 1; i <= tip_count_; ++i) {
        TTTOOLINFOW ti = { TTTOOLINFOW_V1_SIZE };
        ti.hwnd = hwnd_;
        ti.uId  = (UINT_PTR)i;
        SendMessageW(tip_hwnd_, TTM_DELTOOLW, 0, (LPARAM)&ti);
    }

    tip_texts_.clear();
    tip_texts_.reserve(layout_.size());
    for (auto& e : layout_) tip_texts_.push_back(e.first->Tooltip());
    tip_count_ = layout_.size();

    /* cbSize MUST be TTTOOLINFOW_V1_SIZE — with no Common-Controls v6 manifest
       CERF runs comctl32 v5, which rejects the larger modern sizeof(TTTOOLINFOW)
       and silently fails TTM_ADDTOOL (the result: no tooltips). */
    for (size_t i = 0; i < layout_.size(); ++i) {
        TTTOOLINFOW ti = { TTTOOLINFOW_V1_SIZE };
        ti.uFlags   = 0;
        ti.hwnd     = hwnd_;
        ti.uId      = (UINT_PTR)(i + 1);
        ti.rect     = layout_[i].second;
        ti.lpszText = (LPWSTR)tip_texts_[i].c_str();
        SendMessageW(tip_hwnd_, TTM_ADDTOOLW, 0, (LPARAM)&ti);
    }
}

void HostStatusBar::UpdateTipText(size_t idx, std::wstring text) {
    if (!tip_hwnd_ || idx >= tip_texts_.size()) return;
    tip_texts_[idx] = std::move(text);
    TTTOOLINFOW ti = { TTTOOLINFOW_V1_SIZE };
    ti.hwnd     = hwnd_;
    ti.uId      = (UINT_PTR)(idx + 1);
    ti.lpszText = (LPWSTR)tip_texts_[idx].c_str();
    SendMessageW(tip_hwnd_, TTM_UPDATETIPTEXTW, 0, (LPARAM)&ti);
}

HostWidget* HostStatusBar::WidgetAt(int x) const {
    for (auto& e : layout_)
        if (x >= e.second.left && x < e.second.right) return e.first;
    return nullptr;
}

LRESULT CALLBACK HostStatusBar::WndProcStatic(HWND hwnd, UINT msg,
                                              WPARAM wp, LPARAM lp) {
    HostStatusBar* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<HostStatusBar*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<HostStatusBar*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    return self ? self->WndProc(hwnd, msg, wp, lp)
                : DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT HostStatusBar::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    /* Relay mouse events so the tooltip control can show per-icon tips. */
    if (tip_hwnd_ && (msg == WM_MOUSEMOVE || msg == WM_LBUTTONDOWN ||
                      msg == WM_LBUTTONUP || msg == WM_RBUTTONDOWN ||
                      msg == WM_RBUTTONUP)) {
        MSG mm = {};
        mm.hwnd    = hwnd;
        mm.message = msg;
        mm.wParam  = wp;
        mm.lParam  = lp;
        SendMessageW(tip_hwnd_, TTM_RELAYEVENT, (WPARAM)GetMessagePos(), (LPARAM)&mm);
    }

    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(dc, &rc, bg_brush_);

            /* 1px top separator from the canvas. */
            HGDIOBJ old_pen = SelectObject(dc, sep_pen_);
            MoveToEx(dc, rc.left, rc.top, nullptr);
            LineTo(dc, rc.right, rc.top);
            SelectObject(dc, old_pen);

            for (auto& e : layout_) e.first->DrawComposited(dc, e.second);

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_SIZE:
            Relayout(emu_.Get<HostWidgetRegistry>().Ordered());
            return 0;

        case WM_TIMER:
            if (wp == kTickTimerId) {
                auto ordered = emu_.Get<HostWidgetRegistry>().Ordered();
                bool repaint = false;
                for (HostWidget* w : ordered) repaint |= w->SampleActivity();
                repaint |= Relayout(ordered);
                for (size_t i = 0; i < layout_.size(); ++i) {
                    if (layout_[i].first->PollDirty()) {
                        repaint = true;
                        UpdateTipText(i, layout_[i].first->Tooltip());
                    }
                }
                if (repaint) InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;

        case WM_LBUTTONDOWN: {
            const int x = (int)(short)LOWORD(lp);
            if (HostWidget* w = WidgetAt(x)) w->OnPrimaryAction();
            return 0;
        }

        case WM_RBUTTONUP: {
            const int x = (int)(short)LOWORD(lp);
            HostWidget* w = WidgetAt(x);
            if (!w) return 0;
            auto& reg = emu_.Get<HostWidgetRegistry>();
            HMENU m = reg.BuildContextMenu(w);
            POINT pt = { x, (int)(short)HIWORD(lp) };
            ClientToScreen(hwnd, &pt);
            const int id = (int)TrackPopupMenu(
                m, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(m);
            if (id) reg.Dispatch(id);
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, kTickTimerId);
            if (tip_hwnd_) { DestroyWindow(tip_hwnd_); tip_hwnd_ = nullptr; }
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
