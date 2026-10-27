#include "notification_overlay.h"

#include "dpi_scale.h"

#include <cerfcore/core/cerf_emulator.h>

#include <algorithm>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(NotificationOverlay);

namespace {

constexpr int     kMargin        = 12;
constexpr int     kCardW         = 320;
constexpr int     kRegularMinW   = kCardW + 2 * kMargin;
constexpr int     kRegularMinH   = 300;
constexpr int     kPad           = 10;
constexpr int     kGap           = 8;
constexpr int     kRadius        = 6;
constexpr int     kShadow        = 2;
constexpr int     kFontPx        = 13;
constexpr int     kCompactMaxW   = 360;
constexpr int     kCompactMargin = 1;
constexpr int     kCompactGap    = 1;
constexpr int     kCompactPadX   = 7;
constexpr int     kCompactPadY   = 5;
constexpr int     kCompactRadius = 4;
constexpr int     kCompactShadow = 1;
constexpr int     kCompactFontPx = 11;
constexpr int     kLineGap       = 2;
constexpr int     kMorePadY      = 3;
constexpr uint8_t kShadowAlpha   = 70;

constexpr uint32_t kTextFlags = text::kLeft | text::kTop | text::kWordBreak | text::kEditControl;

struct Palette {
    Rgb fill, rim, text;
};
constexpr Palette kWarning = {{242, 201, 76}, {191, 149, 30}, {30, 30, 30}};
constexpr Palette kError   = {{204, 60, 60}, {150, 35, 35}, {255, 255, 255}};
constexpr Palette kMore    = {{64, 64, 64}, {40, 40, 40}, {230, 230, 230}};

}

void NotificationOverlay::Render(Painter& p, int width, int height, int dpi) {
    auto&          stack = emu_.Get<cerfcore::NotificationStack>();
    const uint64_t gen   = stack.Generation();
    if (gen == gen_ && cards_.empty()) return;

    bool dirty = width != w_ || height != h_ || dpi != dpi_;
    if (gen != gen_) {
        gen_  = stack.Snapshot(cards_);
        dirty = true;
    }
    if (dirty) Relayout(p, width, height, dpi);
    if (!placed_.empty()) Draw(p);
}

bool NotificationOverlay::HitTest(int x, int y, uint32_t& id) const {
    for (const Placed& placed : placed_) {
        if (!placed.box.Contains(x, y)) continue;
        id = placed.id;
        return true;
    }
    return false;
}

void NotificationOverlay::Relayout(Painter& p, int width, int height, int dpi) {
    placed_.clear();
    w_   = width;
    h_   = height;
    dpi_ = dpi;
    if (cards_.empty() || width <= 0 || height <= 0) return;

    auto       px      = [dpi](int v) { return ScaleForDpi(v, dpi); };
    const bool compact = width < px(kRegularMinW) || height < px(kRegularMinH);
    const int  margin  = px(compact ? kCompactMargin : kMargin);
    const int  card_w  = std::min(px(compact ? kCompactMaxW : kCardW), width - 2 * margin);
    const int  pad_x   = px(compact ? kCompactPadX : kPad);
    const int  pad_y   = px(compact ? kCompactPadY : kPad);
    const int  gap     = px(compact ? kCompactGap : kGap);
    const int  line_gap = compact ? 0 : px(kLineGap);
    radius_            = px(compact ? kCompactRadius : kRadius);
    shadow_            = px(compact ? kCompactShadow : kShadow);
    font_px_           = px(compact ? kCompactFontPx : kFontPx);
    const Font bold{FontFace::kUi, font_px_, true};
    const Font regular{FontFace::kUi, font_px_, false};

    const int text_w = std::max(1, card_w - 2 * pad_x);
    const int right  = width - margin;
    const int left   = right - card_w;
    const int budget = height / 2 - margin;

    std::vector<Placed> measured;
    std::vector<int>    heights;
    for (size_t i = cards_.size(); i-- > 0;) {
        Placed placed;
        placed.id         = cards_[i].id;
        placed.kind       = cards_[i].kind;
        const std::string& text = cards_[i].text;
        const size_t       nl   = text.find('\n');
        placed.title            = text.substr(0, nl);
        if (nl != std::string::npos) placed.body = text.substr(nl + 1);
        const int title_h = p.TextHeight(placed.title, bold, text_w, kTextFlags);
        const int body_h  = placed.body.empty() ? 0 : p.TextHeight(placed.body, regular, text_w, kTextFlags);
        placed.title_rc   = {left + pad_x, pad_y, right - pad_x, pad_y + title_h};
        placed.body_rc    = {left + pad_x, placed.title_rc.bottom + line_gap, right - pad_x,
                             placed.title_rc.bottom + line_gap + body_h};
        heights.push_back(2 * pad_y + title_h + (body_h ? line_gap + body_h : 0));
        measured.push_back(std::move(placed));
    }

    size_t visible = 0;
    int    used    = 0;
    for (int card_h : heights) {
        const int need = card_h + (visible ? gap : 0);
        if (visible && used + need > budget) break;
        used += need;
        ++visible;
    }
    size_t    hidden   = measured.size() - visible;
    const int more_pad = px(kMorePadY);
    const int more_h   = hidden ? p.TextHeight("+", regular, text_w, kTextFlags) + 2 * more_pad : 0;
    while (hidden && visible > 1 && used + gap + more_h > budget) {
        --visible;
        used -= heights[visible] + gap;
        ++hidden;
    }

    int y = height - margin;
    for (size_t k = 0; k < visible; ++k) {
        Placed&   placed = measured[k];
        const int top    = y - heights[k];
        placed.box       = {left, top, right, y};
        placed.title_rc  = placed.title_rc.Offset(0, top);
        placed.body_rc   = placed.body_rc.Offset(0, top);
        y                = top - gap;
        placed_.push_back(std::move(placed));
    }
    if (hidden) {
        Placed more;
        more.more     = true;
        more.box      = {left, y - more_h, right, y};
        more.title_rc = {left + pad_x, y - more_h + more_pad, right - pad_x, y - more_pad};
        more.title    = "+" + std::to_string(hidden) + " more";
        placed_.push_back(std::move(more));
    }
}

void NotificationOverlay::Draw(Painter& p) {
    const Font bold{FontFace::kUi, font_px_, true};
    const Font regular{FontFace::kUi, font_px_, false};
    for (auto it = placed_.rbegin(); it != placed_.rend(); ++it) {
        const Placed&  placed = *it;
        const Palette& pal    = placed.more ? kMore
                                : placed.kind == cerfcore::NotificationKind::Error ? kError
                                                                                   : kWarning;
        p.FillRoundRectAlphaAA(placed.box.Offset(0, shadow_), radius_, Rgb{0, 0, 0}, kShadowAlpha);
        p.FillRoundRectAA(placed.box, radius_, pal.fill, pal.rim);
        p.DrawTextBox(placed.title_rc, placed.title, placed.more ? regular : bold, pal.text,
                      kTextFlags);
        if (!placed.body.empty())
            p.DrawTextBox(placed.body_rc, placed.body, regular, pal.text, kTextFlags);
    }
}

}
