#define NOMINMAX

#include "host_status_bar.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "host_dark_mode.h"
#include "host_widget.h"
#include "host_widget_registry.h"

REGISTER_SERVICE(HostStatusBar);

namespace {
constexpr wchar_t  kStatusClass[]  = L"CerfHostStatusBar";
constexpr int      kIconBoxW       = 26;
constexpr UINT     kTickTimerId    = 1;
constexpr UINT     kTickMs         = 100;
constexpr COLORREF kClrBg          = RGB(32, 32, 32);
constexpr COLORREF kClrSep         = RGB(60, 60, 60);
constexpr COLORREF kClrBgLight     = RGB(240, 240, 240);
constexpr COLORREF kClrSepLight    = RGB(200, 200, 200);
}  /* namespace */

HostStatusBar::~HostStatusBar() {
    if (bg_brush_)       DeleteObject(bg_brush_);
    if (sep_pen_)        DeleteObject(sep_pen_);
    if (bg_brush_light_) DeleteObject(bg_brush_light_);
    if (sep_pen_light_)  DeleteObject(sep_pen_light_);
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
    bg_brush_       = CreateSolidBrush(kClrBg);
    sep_pen_        = CreatePen(PS_SOLID, 1, kClrSep);
    bg_brush_light_ = CreateSolidBrush(kClrBgLight);
    sep_pen_light_  = CreatePen(PS_SOLID, 1, kClrSepLight);
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
       - without it CreateWindowExW(TOOLTIPS_CLASSW) yields a dead control and no
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

    /* ordered is sorted by (Group, Name); the GuestAdditions..InputCapture
       range is the tail. They pin to the right and always show; device widgets
       fill the rest and drop the leftmost on overflow. */
    int term_count = 0;
    for (auto* w : ordered)
        if (w->Group() >= WidgetGroup::GuestAdditions) ++term_count;
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

    /* cbSize is the backward-compatible TTTOOLINFOW_V1_SIZE - accepted by every
       comctl32 (v5 and the v6 the manifest now pulls in); avoids the larger
       modern sizeof(TTTOOLINFOW) that older comctl32 rejects from TTM_ADDTOOL. */
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

bool HostStatusBar::WidgetScreenRect(const HostWidget* w, RECT& out) const {
    for (auto& e : layout_) {
        if (e.first == w) {
            out = e.second;   /* client coords */
            MapWindowPoints(hwnd_, nullptr, reinterpret_cast<POINT*>(&out), 2);
            return true;
        }
    }
    return false;
}

bool HostStatusBar::CaptureWidgetScreenRect(RECT& out) const {
    for (auto& e : layout_)
        if (e.first->Group() == WidgetGroup::InputCapture)
            return WidgetScreenRect(e.first, out);
    return false;
}

HostWidget* HostStatusBar::WidgetAt(int x) const {
    for (auto& e : layout_)
        if (x >= e.second.left && x < e.second.right) return e.first;
    return nullptr;
}

void HostStatusBar::SecondaryAction(HostWidget* w, int x, int y, UINT button_flag) {
    auto& reg = emu_.Get<HostWidgetRegistry>();
    auto items = w->BuildMenu();
    if (w->MenuIsOneAction() && items.size() == 1 && items[0].enabled &&
        items[0].on_click && items[0].submenu.empty()) {
        items[0].on_click();
        return;
    }
    HMENU m = reg.BuildContextMenu(items);
    POINT pt = { x, y };
    ClientToScreen(hwnd_, &pt);
    const int id = (int)TrackPopupMenu(m, TPM_RETURNCMD | TPM_LEFTALIGN | button_flag,
                                       pt.x, pt.y, 0, hwnd_, nullptr);
    DestroyMenu(m);
    if (id) reg.Dispatch(id);
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

            /* Double-buffer: the bar repaints at the activity-glow rate while a
               widget has RX/TX, and erasing + redrawing every icon straight to
               the window flickers. Compose into a memory DC and blit once. */
            HDC     mem    = CreateCompatibleDC(dc);
            HBITMAP bmp    = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
            HGDIOBJ oldbmp = SelectObject(mem, bmp);

            const bool dark = emu_.Get<HostDarkMode>().IsDark();
            const COLORREF bar_bg = dark ? kClrBg : kClrBgLight;
            FillRect(mem, &rc, dark ? bg_brush_ : bg_brush_light_);

            /* 1px top separator from the canvas. */
            HGDIOBJ old_pen = SelectObject(mem, dark ? sep_pen_ : sep_pen_light_);
            MoveToEx(mem, rc.left, rc.top, nullptr);
            LineTo(mem, rc.right, rc.top);
            SelectObject(mem, old_pen);

            for (auto& e : layout_) e.first->DrawComposited(mem, e.second, bar_bg);

            BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);

            SelectObject(mem, oldbmp);
            DeleteObject(bmp);
            DeleteDC(mem);
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
            HostWidget* w = WidgetAt(x);
            if (w && !w->TryPrimaryAction())
                SecondaryAction(w, x, (int)(short)HIWORD(lp), TPM_LEFTBUTTON);
            return 0;
        }

        case WM_RBUTTONUP: {
            const int x = (int)(short)LOWORD(lp);
            if (HostWidget* w = WidgetAt(x))
                SecondaryAction(w, x, (int)(short)HIWORD(lp), TPM_RIGHTBUTTON);
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, kTickTimerId);
            if (tip_hwnd_) { DestroyWindow(tip_hwnd_); tip_hwnd_ = nullptr; }
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
