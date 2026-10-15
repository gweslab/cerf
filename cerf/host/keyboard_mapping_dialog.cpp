#define NOMINMAX
#include "keyboard_mapping_dialog.h"
#include "ui_language.h"

#include "../core/cerf_emulator.h"
#include "host_dark_mode.h"
#include "host_window.h"
#include "keyboard_map.h"
#include "pc_keyboard_layout.h"

#include <cstdio>
#include "../core/string_utils.h"

#include <cwchar>
#include <string>

REGISTER_SERVICE(KeyboardMappingDialog);

namespace {

constexpr wchar_t kClass[] = L"CerfKeyboardMappingDlg";

constexpr int kUnitW   = 46;
constexpr int kUnitH   = 36;
constexpr int kGap     = 5;
constexpr int kMargin  = 16;
constexpr int kHeaderH = 58;   /* line 1: hint text; line 2: lock-layer checkbox */
constexpr int kTop     = kMargin + kHeaderH;

constexpr int kClientW = (int)(kPcKeyboardUnitsW * kUnitW + 0.5f) + 2 * kMargin;
constexpr int kClientH = kTop + (int)(kPcKeyboardUnitsH * kUnitH + 0.5f) + kMargin;

struct Palette {
    COLORREF bg, cap_mapped, cap_unmapped, border, text, accent, active, mod;
};

/* A cap font ~2px shorter than the UI font, so legends sit inside the key. */
HFONT MakeCapFont(HFONT base) {
    LOGFONTW lf = {};
    if (base && GetObjectW(base, sizeof(lf), &lf) == sizeof(lf)) {
        if (lf.lfHeight < 0)      lf.lfHeight += 2;
        else if (lf.lfHeight > 0) lf.lfHeight -= 2;
        return CreateFontIndirectW(&lf);
    }
    return nullptr;
}

Palette MakePalette(bool dark) {
    if (dark)
        return { RGB(32, 32, 36),  RGB(60, 60, 66),  RGB(44, 44, 47),
                 RGB(96, 96, 102), RGB(235, 235, 235), RGB(120, 180, 255),
                 RGB(38, 84, 140), RGB(48, 68, 98) };
    return { RGB(240, 240, 240), RGB(252, 252, 252), RGB(224, 224, 224),
             RGB(168, 168, 168), RGB(24, 24, 24),    RGB(20, 96, 200),
             RGB(176, 208, 248), RGB(208, 224, 250) };
}

}  /* namespace */

bool KeyboardMappingDialog::ShouldRegister() {
    return emu_.TryGet<KeyboardMap>() != nullptr;
}

void KeyboardMappingDialog::OnReady() {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &KeyboardMappingDialog::WndProcStatic;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hIcon         = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;   /* painted in WM_PAINT */
    wc.lpszClassName = kClass;
    RegisterClassExW(&wc);   /* ERROR_CLASS_ALREADY_EXISTS is benign */
}

void KeyboardMappingDialog::OnShutdown() {
    if (cap_font_) { DeleteObject(cap_font_); cap_font_ = nullptr; }
}

const KeyBinding* KeyboardMappingDialog::FindBinding(uint8_t vk,
                                                     uint8_t layer) const {
    const KeyBinding* base      = nullptr;
    const KeyBinding* layer_hit = nullptr;
    for (const KeyBinding& b : emu_.Get<KeyboardMap>().Bindings()) {
        if (b.host_vk != vk) continue;
        if (b.layer == layer) layer_hit = &b;
        if (b.layer == 0)     base = &b;
    }
    if (layer == 0)  return base;          /* base view */
    if (layer_hit)   return layer_hit;     /* explicit layer override */
    /* A key with no explicit layer binding has no verified modified mapping, so
       it dims; only the active modifier itself stays lit. */
    return (base && base->holds_layer == layer) ? base : nullptr;
}

RECT KeyboardMappingDialog::CapRect(const KeyCap& cap) const {
    const int x = kMargin + (int)(cap.x * kUnitW + 0.5f);
    const int y = kTop    + (int)(cap.y * kUnitH + 0.5f);
    const int w = (int)(cap.w * kUnitW + 0.5f) - kGap;
    return { x, y, x + w, y + kUnitH - kGap };
}

RECT KeyboardMappingDialog::ToggleRect(int index) const {
    constexpr int kBox = 16, kW = 96, kStride = 110;
    const int left = kMargin + index * kStride;   /* second header line */
    const int top  = kMargin + 30;
    return { left, top, left + kW, top + kBox };
}

void KeyboardMappingDialog::DrawCap(HDC dc, const KeyCap& cap) {
    const bool    dark = emu_.Get<HostDarkMode>().IsDark();
    const Palette pal  = MakePalette(dark);
    const RECT    rc   = CapRect(cap);

    const KeyBinding* b = FindBinding(cap.vk, active_layer_);
    const bool mapped   = (b != nullptr);
    const bool modifier = mapped && b->holds_layer != 0;   /* clickable layer */
    const bool is_active = modifier && b->holds_layer == active_layer_;

    const COLORREF fill = !mapped  ? pal.cap_unmapped
                        : is_active ? pal.active
                        : modifier  ? pal.mod
                                    : pal.cap_mapped;
    HBRUSH br = CreateSolidBrush(fill);
    FillRect(dc, &rc, br);
    DeleteObject(br);

    HPEN    pen = CreatePen(PS_SOLID, modifier ? 2 : 1,
                            modifier ? pal.accent : pal.border);
    HGDIOBJ op  = SelectObject(dc, pen);
    HGDIOBJ ob  = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(pen);

    if (!mapped) return;   /* dimmed, no strings */

    SetBkMode(dc, TRANSPARENT);
    if (b->guest_label == nullptr) {
        SetTextColor(dc, pal.text);
        RECT tr = rc;
        DrawTextW(dc, cap.legend, -1, &tr,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }

    RECT top = rc; top.bottom = (rc.top + rc.bottom) / 2;
    RECT bot = rc; bot.top    = top.bottom;
    SetTextColor(dc, pal.text);
    DrawTextW(dc, cap.legend, -1, &top, DT_CENTER | DT_BOTTOM | DT_SINGLELINE);
    /* A modifier already reads as special via its fill+border; an ordinary remap
       accents the guest action so it stands out from identity keys. */
    SetTextColor(dc, modifier ? pal.text : pal.accent);
    DrawTextW(dc, b->guest_label, -1, &bot, DT_CENTER | DT_TOP | DT_SINGLELINE);
}

void KeyboardMappingDialog::Paint(HDC dc) {
    const bool    dark = emu_.Get<HostDarkMode>().IsDark();
    const Palette pal  = MakePalette(dark);

    RECT client;
    GetClientRect(hwnd_, &client);
    HBRUSH bg = CreateSolidBrush(pal.bg);
    FillRect(dc, &client, bg);
    DeleteObject(bg);

    HFONT font = emu_.Get<HostDarkMode>().UiFont();
    HGDIOBJ of = SelectObject(dc, font ? font : GetStockObject(DEFAULT_GUI_FONT));

    /* Header line - lists the board's modifiers (it may have more than one) and
       only then offers the layer preview. */
    const auto     toggles = emu_.Get<KeyboardMap>().ToggleLayers();
    std::wstring   mods;
    uint32_t       seen_layers = 0;
    const wchar_t* active_name = nullptr;
    bool           active_is_toggle = false;
    for (const KeyBinding& b : emu_.Get<KeyboardMap>().Bindings()) {
        if (b.holds_layer == 0) continue;
        const wchar_t* name = b.guest_label ? b.guest_label : emu_.Get<UiLanguage>().Text("keyboard.modifier");
        if (b.holds_layer == active_layer_) active_name = name;
        if (b.holds_layer < 32 && !(seen_layers & (1u << b.holds_layer))) {
            seen_layers |= 1u << b.holds_layer;
            if (!mods.empty()) mods += L" / ";
            mods += name;
        }
    }
    if (!active_name)
        for (const KeyboardToggleLayer& t : toggles)
            if (t.layer == active_layer_) { active_name = t.name; active_is_toggle = true; break; }

    std::wstring header;
    if (active_layer_ != 0) {
        const wchar_t* m = active_name ? active_name : emu_.Get<UiLanguage>().Text("keyboard.the_modifier");
        header = emu_.Get<UiLanguage>().Format(
            active_is_toggle ? "keyboard.preview_toggle" : "keyboard.preview_modifier",
            {{"modifier", WideToUtf8(m)}});
    } else if (!mods.empty()) {
        header = emu_.Get<UiLanguage>().Format("keyboard.preview_hint",
                                              {{"modifiers", WideToUtf8(mods)}});
    } else {
        header = emu_.Get<UiLanguage>().Text(
            "keyboard.dimmed_keys_are_unmapped_blue_shows_the_guest_action");
    }
    RECT hr = { kMargin, kMargin, kClientW - kMargin, kMargin + 24 };
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, pal.text);
    DrawTextW(dc, header.c_str(), -1, &hr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    for (int i = 0; i < (int)toggles.size(); ++i) {
        const RECT r = ToggleRect(i);
        const bool checked = (active_layer_ == toggles[i].layer);
        RECT box = { r.left, r.top, r.left + 16, r.bottom };
        HBRUSH fb = CreateSolidBrush(checked ? pal.active : pal.cap_mapped);
        FillRect(dc, &box, fb);
        DeleteObject(fb);
        HPEN bp = CreatePen(PS_SOLID, 1, checked ? pal.accent : pal.border);
        HGDIOBJ obp = SelectObject(dc, bp);
        HGDIOBJ obb = SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, box.left, box.top, box.right, box.bottom);
        SelectObject(dc, obb);
        SelectObject(dc, obp);
        DeleteObject(bp);
        if (checked) {
            HPEN cp = CreatePen(PS_SOLID, 2, pal.text);
            HGDIOBJ ocp = SelectObject(dc, cp);
            MoveToEx(dc, box.left + 3, box.top + 8, nullptr);
            LineTo(dc, box.left + 6, box.top + 12);
            LineTo(dc, box.left + 13, box.top + 4);
            SelectObject(dc, ocp);
            DeleteObject(cp);
        }
        RECT tr = { box.right + 6, r.top, r.right, r.bottom };
        SetTextColor(dc, pal.text);
        DrawTextW(dc, toggles[i].name, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }

    if (!cap_font_)
        cap_font_ = MakeCapFont(font ? font : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    HGDIOBJ ocf = cap_font_ ? SelectObject(dc, cap_font_) : nullptr;
    for (const KeyCap& cap : kPcKeyboard) DrawCap(dc, cap);
    if (ocf) SelectObject(dc, ocf);

    SelectObject(dc, of);
}

void KeyboardMappingDialog::OnClick(int x, int y) {
    POINT pt = { x, y };

    const auto toggles = emu_.Get<KeyboardMap>().ToggleLayers();
    for (int i = 0; i < (int)toggles.size(); ++i) {
        RECT r = ToggleRect(i);
        if (PtInRect(&r, pt)) {
            active_layer_ = (active_layer_ == toggles[i].layer) ? 0 : toggles[i].layer;
            InvalidateRect(hwnd_, nullptr, FALSE);
            return;
        }
    }

    for (const KeyCap& cap : kPcKeyboard) {
        RECT rc = CapRect(cap);
        if (!PtInRect(&rc, pt)) continue;
        const KeyBinding* base = FindBinding(cap.vk, 0);
        if (base && base->holds_layer != 0) {
            active_layer_ = (active_layer_ == base->holds_layer)
                                ? 0 : base->holds_layer;
            InvalidateRect(hwnd_, nullptr, FALSE);
        }
        return;
    }
}

void KeyboardMappingDialog::Show() {
    if (hwnd_) { SetForegroundWindow(hwnd_); return; }   /* already open -> raise */

    HWND owner = emu_.Get<HostWindow>().Hwnd();
    active_layer_ = 0;

    const DWORD style = WS_CAPTION | WS_SYSMENU | WS_DLGFRAME | WS_POPUP;
    RECT wr = { 0, 0, kClientW, kClientH };
    AdjustWindowRect(&wr, style, FALSE);
    const int ww = wr.right - wr.left;
    const int wh = wr.bottom - wr.top;
    RECT orc = { 0, 0, 0, 0 };
    GetWindowRect(owner, &orc);
    const int wx = orc.left + ((orc.right - orc.left) - ww) / 2;
    const int wy = orc.top  + ((orc.bottom - orc.top) - wh) / 2;

    /* Modeless tool window owned by the main window: the user parks it beside
       the guest as a persistent key-map hint. Pumped by the UI thread loop. */
    hwnd_ = CreateWindowExW(WS_EX_TOOLWINDOW, kClass, emu_.Get<UiLanguage>().Text("keyboard.keyboard_mapping"),
                            style, wx, wy, ww, wh, owner, nullptr,
                            GetModuleHandleW(nullptr), this);
    if (!hwnd_) return;

    emu_.Get<HostDarkMode>().ApplyToDialog(hwnd_);
    ShowWindow(hwnd_, SW_SHOW);
    SetForegroundWindow(hwnd_);
}

LRESULT KeyboardMappingDialog::WndProc(HWND hwnd, UINT msg, WPARAM wp,
                                       LPARAM lp) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            Paint(dc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_LBUTTONUP:
            OnClick((int)(short)LOWORD(lp), (int)(short)HIWORD(lp));
            return 0;
        case WM_KEYDOWN:
            if (wp == VK_ESCAPE) DestroyWindow(hwnd);
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            hwnd_ = nullptr;
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT CALLBACK KeyboardMappingDialog::WndProcStatic(HWND hwnd, UINT msg,
                                                      WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
    }
    auto* self = reinterpret_cast<KeyboardMappingDialog*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (self) return self->WndProc(hwnd, msg, wp, lp);
    return DefWindowProcW(hwnd, msg, wp, lp);
}
