#define NOMINMAX

#include "notification_overlay.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "host_dpi.h"
#include "host_fonts.h"
#include "host_gdiplus.h"

#include <algorithm>

REGISTER_SERVICE(NotificationOverlay);

namespace {

constexpr int  kMargin        = 12;
constexpr int  kCardW         = 320;
constexpr int  kRegularMinW   = kCardW + 2 * kMargin;
constexpr int  kRegularMinH   = 300;
constexpr int  kPad           = 10;
constexpr int  kGap           = 8;
constexpr int  kRadius        = 6;
constexpr int  kShadow        = 2;
constexpr int  kFontPx        = 13;
constexpr int  kCompactMaxW   = 360;
constexpr int  kCompactPadX   = 6;
constexpr int  kCompactPadY   = 4;
constexpr int  kCompactFontPx = 11;
constexpr int  kLineGap       = 2;
constexpr int  kMorePadY      = 3;
constexpr BYTE kShadowAlpha   = 70;

constexpr UINT kTextFlags =
    DT_LEFT | DT_TOP | DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX;

struct Palette { COLORREF fill, rim, text; };
constexpr Palette kWarning = { RGB(242, 201,  76), RGB(191, 149,  30), RGB( 30,  30,  30) };
constexpr Palette kError   = { RGB(204,  60,  60), RGB(150,  35,  35), RGB(255, 255, 255) };
constexpr Palette kMore    = { RGB( 64,  64,  64), RGB( 40,  40,  40), RGB(230, 230, 230) };

}

NotificationOverlay::~NotificationOverlay() {
    if (bold_)    DeleteObject(bold_);
    if (regular_) DeleteObject(regular_);
}

void NotificationOverlay::RenderInto(HWND canvas, HDC dc, int dib_w, int dib_h) {
    auto& stack = emu_.Get<NotificationStack>();
    const uint64_t gen = stack.Generation();
    if (gen == gen_ && cards_.empty()) return;

    RECT client{};
    GetClientRect(canvas, &client);
    const int  w   = std::min(dib_w, (int)client.right);
    const int  h   = std::min(dib_h, (int)client.bottom);
    const UINT dpi = emu_.Get<HostDpi>().ForWindow(canvas);

    bool dirty = w != w_ || h != h_ || dpi != dpi_;
    if (gen != gen_) {
        gen_  = stack.Snapshot(cards_);
        dirty = true;
    }
    if (dirty) Relayout(dc, w, h, dpi);
    if (!placed_.empty()) Draw(dc);
}

bool NotificationOverlay::HitTest(int x, int y, uint32_t& id) const {
    const POINT pt{ x, y };
    for (const Placed& p : placed_) {
        if (PtInRect(&p.box, pt)) {
            id = p.id;
            return true;
        }
    }
    return false;
}

void NotificationOverlay::EnsureFonts(int px) {
    if (px == font_px_ && bold_ && regular_) return;
    if (bold_)    DeleteObject(bold_);
    if (regular_) DeleteObject(regular_);
    const wchar_t* face = emu_.Get<HostFonts>().UiFace();
    bold_    = CreateFontW(-px, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           VARIABLE_PITCH | FF_SWISS, face);
    regular_ = CreateFontW(-px, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           VARIABLE_PITCH | FF_SWISS, face);
    if (!bold_ || !regular_)
        emu_.Get<Fatal>().Die("NotificationOverlay: CreateFontW %dpx failed (gle=%lu)",
                              px, GetLastError());
    font_px_ = px;
}

int NotificationOverlay::MeasureText(HDC dc, HFONT font, const std::wstring& text,
                                     int width) const {
    RECT rc{ 0, 0, width, 0 };
    HGDIOBJ old = SelectObject(dc, font);
    DrawTextW(dc, text.c_str(), (int)text.size(), &rc, kTextFlags | DT_CALCRECT);
    SelectObject(dc, old);
    return rc.bottom - rc.top;
}

void NotificationOverlay::Relayout(HDC dc, int w, int h, UINT dpi) {
    placed_.clear();
    w_   = w;
    h_   = h;
    dpi_ = dpi;
    if (cards_.empty() || w <= 0 || h <= 0) return;

    auto px = [dpi](int v) { return MulDiv(v, (int)dpi, 96); };
    compact_ = w < px(kRegularMinW) || h < px(kRegularMinH);
    const int margin   = compact_ ? 0 : px(kMargin);
    const int width    = compact_ ? std::min(w, px(kCompactMaxW))
                                  : std::min(px(kCardW), w - 2 * margin);
    const int pad_x    = px(compact_ ? kCompactPadX : kPad);
    const int pad_y    = px(compact_ ? kCompactPadY : kPad);
    const int gap      = compact_ ? 0 : px(kGap);
    const int line_gap = compact_ ? 0 : px(kLineGap);
    radius_ = compact_ ? 0 : px(kRadius);
    shadow_ = compact_ ? 0 : px(kShadow);
    EnsureFonts(px(compact_ ? kCompactFontPx : kFontPx));

    const int text_w = std::max(1, width - 2 * pad_x);
    const int right  = w - margin;
    const int left   = right - width;
    const int budget = h / 2 - margin;

    std::vector<Placed> measured;
    std::vector<int>    heights;
    for (size_t i = cards_.size(); i-- > 0;) {
        Placed p;
        p.id   = cards_[i].id;
        p.kind = cards_[i].kind;
        const std::wstring& text = cards_[i].text;
        const size_t nl = text.find(L'\n');
        p.title = text.substr(0, nl);
        if (nl != std::wstring::npos) p.body = text.substr(nl + 1);
        const int title_h = MeasureText(dc, bold_, p.title, text_w);
        const int body_h  = p.body.empty() ? 0 : MeasureText(dc, regular_, p.body, text_w);
        p.title_rc = { left + pad_x, pad_y, right - pad_x, pad_y + title_h };
        p.body_rc  = { left + pad_x, p.title_rc.bottom + line_gap,
                       right - pad_x, p.title_rc.bottom + line_gap + body_h };
        heights.push_back(2 * pad_y + title_h + (body_h ? line_gap + body_h : 0));
        measured.push_back(std::move(p));
    }

    size_t visible = 0;
    int    used    = 0;
    for (int card_h : heights) {
        const int need = card_h + (visible ? gap : 0);
        if (visible && used + need > budget) break;
        used += need;
        ++visible;
    }
    size_t    hidden    = measured.size() - visible;
    const int more_pad  = px(kMorePadY);
    const int more_h    = hidden ? MeasureText(dc, regular_, L"+", text_w) + 2 * more_pad : 0;
    while (hidden && visible > 1 && used + gap + more_h > budget) {
        --visible;
        used -= heights[visible] + gap;
        ++hidden;
    }

    int y = h - margin;
    for (size_t k = 0; k < visible; ++k) {
        Placed& p = measured[k];
        const int top = y - heights[k];
        p.box = { left, top, right, y };
        OffsetRect(&p.title_rc, 0, top);
        OffsetRect(&p.body_rc, 0, top);
        y = top - gap;
        placed_.push_back(std::move(p));
    }
    if (hidden) {
        Placed more;
        more.more     = true;
        more.box      = { left, y - more_h, right, y };
        more.title_rc = { left + pad_x, y - more_h + more_pad, right - pad_x, y - more_pad };
        more.title    = L"+" + std::to_wstring(hidden) + L" more";
        placed_.push_back(std::move(more));
    }
}

void NotificationOverlay::Draw(HDC dc) {
    auto& gdip = emu_.Get<HostGdiPlus>();
    const int     old_mode = SetBkMode(dc, TRANSPARENT);
    const HGDIOBJ old_font = SelectObject(dc, bold_);
    for (const Placed& p : placed_) {
        const Palette& pal = p.more ? kMore
                           : p.kind == NotificationKind::Error ? kError : kWarning;
        if (compact_) {
            SetDCBrushColor(dc, pal.fill);
            FillRect(dc, &p.box, (HBRUSH)GetStockObject(DC_BRUSH));
            const RECT divider{ p.box.left, p.box.top, p.box.right, p.box.top + 1 };
            SetDCBrushColor(dc, pal.rim);
            FillRect(dc, &divider, (HBRUSH)GetStockObject(DC_BRUSH));
        } else {
            RECT shadow = p.box;
            OffsetRect(&shadow, 0, shadow_);
            gdip.FillRoundRectAlphaAA(dc, shadow, radius_, RGB(0, 0, 0), kShadowAlpha);
            gdip.FillRoundRectAA(dc, p.box, radius_, pal.fill, pal.rim);
        }
        SetTextColor(dc, pal.text);
        RECT title_rc = p.title_rc;
        SelectObject(dc, p.more ? regular_ : bold_);
        DrawTextW(dc, p.title.c_str(), (int)p.title.size(), &title_rc, kTextFlags);
        if (!p.body.empty()) {
            RECT body_rc = p.body_rc;
            SelectObject(dc, regular_);
            DrawTextW(dc, p.body.c_str(), (int)p.body.size(), &body_rc, kTextFlags);
        }
    }
    SelectObject(dc, old_font);
    SetBkMode(dc, old_mode);
}
