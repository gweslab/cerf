#include "hud_renderer.h"

#include "dpi_scale.h"
#include "host_key_name.h"
#include "hud_selection.h"
#include "pc_key_legend.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/hud_database.h>
#include <cerfcore/host/keyboard_map.h>

#include <algorithm>
#include <cmath>

namespace cerffrontend {

REGISTER_SERVICE(HudRenderer);

namespace {

using cerfcore::HudDpadShape;
using cerfcore::HudNode;

constexpr Rgb     kBlack{0, 0, 0};
constexpr Rgb     kSeparator{64, 64, 64};
constexpr Rgb     kVeil{255, 255, 255};
constexpr uint8_t kVeilAlpha       = 28;
constexpr uint8_t kVeilCenterAlpha = 40;
constexpr uint8_t kVeilDownAlpha   = 80;
constexpr Rgb     kInk{236, 236, 236};
constexpr Rgb kArrow{160, 160, 160};
constexpr Rgb kHint{150, 150, 150};
constexpr Rgb kLatchRim{90, 160, 255};

constexpr double kRadiusPart  = 0.18;
constexpr double kIconPart    = 0.5;
constexpr double kLabelPart   = 0.42;
constexpr double kLabelRoomPart = 0.86;
constexpr double kHintPart    = 0.2;
constexpr double kHintMaxPart = 0.3;
constexpr int    kHintMinPx   = 8;
constexpr double kArrowReach  = 0.8;
constexpr double kArrowSize   = 0.18;
constexpr double kArrowDepth  = 1.3;
constexpr double kCenterPart  = 0.3;
constexpr int    kSeparatorPx = 1;
constexpr int    kLatchRimPx  = 2;
constexpr int     kBackdropSamples = 4;
constexpr double  kSampleSide      = 8.0;
constexpr uint8_t kFadeEdgeAlpha   = 128;
constexpr uint8_t kFadeMidAlpha    = 200;

int Round(double v) { return static_cast<int>(std::lround(v)); }

Rect ToRect(const FrameRect& r) { return {Round(r.x), Round(r.y), Round(r.x + r.w), Round(r.y + r.h)}; }

Point ToPoint(FramePoint p) { return {Round(p.x), Round(p.y)}; }

using cerfcore::HudSide;

bool AlongX(HudSide side) { return side == HudSide::kTop || side == HudSide::kBottom; }

double Outward(HudSide side) { return side == HudSide::kBottom || side == HudSide::kRight ? 1.0 : -1.0; }

Rgb Average(const CanvasPixels& canvas, FramePoint center) {
    const int x0 = std::max(0, Round(center.x - kSampleSide / 2.0));
    const int y0 = std::max(0, Round(center.y - kSampleSide / 2.0));
    const int x1 = std::min(canvas.width, Round(center.x + kSampleSide / 2.0));
    const int y1 = std::min(canvas.height, Round(center.y + kSampleSide / 2.0));
    uint64_t  r = 0, g = 0, b = 0, n = 0;
    for (int y = y0; y < y1; ++y) {
        for (int x = x0; x < x1; ++x) {
            const uint32_t v = canvas.bits[static_cast<size_t>(y) * canvas.width + x];
            r += (v >> 16) & 0xFFu;
            g += (v >> 8) & 0xFFu;
            b += v & 0xFFu;
            ++n;
        }
    }
    if (n == 0) return kBlack;
    return {static_cast<uint8_t>(r / n), static_cast<uint8_t>(g / n), static_cast<uint8_t>(b / n)};
}

}

void HudRenderer::Render(Painter& p, const ViewportLayout::Layout& frame, int dpi, const CanvasPixels& canvas) {
    auto&                  controls = emu_.Get<HudControls>();
    const cerfcore::DbHud* hud      = emu_.Get<HudSelection>().Active();
    if (hud == nullptr || frame.dst_w <= 0 || frame.dst_h <= 0) {
        controls.Clear();
        return;
    }
    controls.Place(*hud, frame);
    for (const HudBandShown& band : controls.Bands()) DrawBackdrop(p, band, canvas);
    const int separator_px = ScaleForDpi(kSeparatorPx, dpi);
    for (const HudSeparator& s : controls.Separators()) {
        const Point line[] = {ToPoint(s.from), ToPoint(s.to)};
        p.Polyline(line, 2, kSeparator, separator_px);
    }
    const cerfcore::KeyboardMap* map   = emu_.TryGet<cerfcore::KeyboardMap>();
    const uint8_t                layer = map == nullptr ? 0 : HeldLayer(*map);
    for (const HudShown& shown : controls.Shown()) {
        if (shown.node->kind == HudNode::Kind::kButton)
            DrawButton(p, shown, Face(shown.node->button, map, layer), Renamed(shown.node->button.keys, map), dpi);
        else                                            DrawDpad(p, shown);
    }
}

uint8_t HudRenderer::HeldLayer(const cerfcore::KeyboardMap& map) {
    const auto& controls = emu_.Get<HudControls>();
    for (const cerfcore::KeyBinding& b : map.Bindings())
        if (b.layer == 0 && b.holds_layer != 0 && controls.KeyDown(b.vk)) return b.holds_layer;
    return 0;
}

cerfcore::HudFace HudRenderer::Face(const cerfcore::HudButton& button, const cerfcore::KeyboardMap* map, uint8_t layer) {
    if (map != nullptr && layer != 0 && button.keys.size() == 1)
        if (const char* label = map->GuestLabel(button.keys[0], layer)) {
            for (const cerfcore::HudLayerFace& held : button.layer_faces)
                if (map->HeldLayer(held.held) == layer) return held.face;
            return {label, {}};
        }
    if (!button.face.label.empty() || !button.face.icon.empty()) return button.face;
    std::string label;
    for (uint8_t vk : button.keys) {
        const char* guest  = map == nullptr ? nullptr : map->GuestLabel(vk, 0);
        const char* legend = PcKeyLegend(vk);
        if (!label.empty()) label += '+';
        label += guest != nullptr ? std::string(guest) : legend != nullptr ? std::string(legend) : HostKeyName(vk);
    }
    return {label, {}};
}

bool HudRenderer::Renamed(const std::vector<uint8_t>& keys, const cerfcore::KeyboardMap* map) {
    if (map == nullptr) return false;
    return std::any_of(keys.begin(), keys.end(), [map](uint8_t vk) {
        const char* guest  = map->GuestLabel(vk, 0);
        const char* legend = PcKeyLegend(vk);
        return guest != nullptr && (legend == nullptr || !SameKeyName(guest, legend));
    });
}

void HudRenderer::DrawBackdrop(Painter& p, const HudBandShown& band, const CanvasPixels& canvas) {
    const FramePlacement& place  = emu_.Get<HudControls>().Placement();
    const bool            along  = AlongX(band.side);
    const double          extent = along ? place.DeviceWidth() : place.DeviceHeight();
    const double          inner  = band.inner;
    const auto at = [&](double t, double v) { return place.ToCanvas(along ? FramePoint{t, v} : FramePoint{v, t}); };

    GradientStop samples[kBackdropSamples];
    for (int i = 0; i < kBackdropSamples; ++i) {
        const double share = (i + 0.5) / kBackdropSamples;
        samples[i] = {share, Average(canvas, at(extent * share, inner - Outward(band.side) * kSampleSide / 2.0)), 255};
    }
    const Rect area = ToRect(band.canvas);
    p.FillGradient(area, ToPoint(at(0.0, inner)), ToPoint(at(extent, inner)), samples, kBackdropSamples);
    const GradientStop fade[] = {{0.0, kBlack, kFadeEdgeAlpha}, {0.5, kBlack, kFadeMidAlpha}, {1.0, kBlack, 255}};
    p.FillGradient(area, ToPoint(at(0.0, inner)), ToPoint(at(0.0, band.outer)), fade, 3);
}

void HudRenderer::DrawButton(Painter& p, const HudShown& shown, const cerfcore::HudFace& face, bool renamed, int dpi) {
    auto&                      controls = emu_.Get<HudControls>();
    const cerfcore::HudButton& button   = shown.node->button;
    const Rect                 box      = ToRect(shown.canvas);
    const int                  side     = std::min(box.Width(), box.Height());
    if (controls.Pressed(shown.node) || controls.KeysDown(button.keys)) p.BlendRect(box, kVeil, kVeilDownAlpha);
    if (controls.Latched(shown.node)) p.Rectangle(box, kLatchRim, ScaleForDpi(kLatchRimPx, dpi), nullptr);

    if (!face.icon.empty()) {
        p.DrawSymbol(box, face.icon, std::max(1, Round(side * kIconPart)), kInk);
    } else {
        Font      font{FontFace::kUi, std::max(1, Round(side * kLabelPart)), true};
        const int room  = std::max(1, Round(box.Width() * kLabelRoomPart));
        const int width = p.TextWidth(face.label, font);
        if (width > room) font.px = std::max(1, font.px * room / width);
        p.DrawTextBox(box, face.label, font, kInk, text::kCenter | text::kVCenter | text::kSingleLine);
    }

    if (controls.InsideCanvas()) return;
    const std::string hint = KeyHint(button.keys);
    if (hint.empty() || SameKeyName(hint, face.label)) return;
    if (face.label.empty() && !renamed) return;
    DrawHint(p, box, hint, HintPx(side, dpi), text::kLeft | text::kBottom);
}

void HudRenderer::DrawDpad(Painter& p, const HudShown& shown) {
    auto&                    controls = emu_.Get<HudControls>();
    const cerfcore::HudDpad& dpad     = shown.node->dpad;
    const FramePlacement&    place    = controls.Placement();
    const FrameRect&         dr       = shown.device;
    const bool               circle   = dpad.shape == HudDpadShape::kCircle;
    const double             hx       = (circle ? std::min(dr.w, dr.h) : dr.w) / 2.0;
    const double             hy       = (circle ? std::min(dr.w, dr.h) : dr.h) / 2.0;
    const FramePoint         c{dr.x + dr.w / 2.0, dr.y + dr.h / 2.0};
    const Rect               box  = ToRect(place.ToCanvas(FrameRect{c.x - hx, c.y - hy, 2.0 * hx, 2.0 * hy}));
    const int                side = std::min(box.Width(), box.Height());
    const Point              mid  = ToPoint(place.ToCanvas(c));
    p.FillRoundRectAlphaAA(box, circle ? side / 2 : std::max(1, Round(side * kRadiusPart)), kVeil, kVeilAlpha);

    struct Side {
        const std::vector<uint8_t>& keys;
        FramePoint                  along;
        double                      reach;
    };
    const Side   sides[] = {{dpad.up, {0.0, -1.0}, hy},
                            {dpad.down, {0.0, 1.0}, hy},
                            {dpad.left, {-1.0, 0.0}, hx},
                            {dpad.right, {1.0, 0.0}, hx}};
    const double size    = std::min(hx, hy) * kArrowSize;
    for (const Side& s : sides)
        if (!s.keys.empty()) DrawArrow(p, c, s.along, s.reach * kArrowReach, size, controls.KeysDown(s.keys));
    if (dpad.center.empty()) return;
    const int radius = std::max(1, Round(std::min(hx, hy) * kCenterPart));
    p.FillRoundRectAlphaAA(Rect{mid.x - radius, mid.y - radius, mid.x + radius, mid.y + radius}, radius, kVeil,
                           controls.KeysDown(dpad.center) ? kVeilDownAlpha : kVeilCenterAlpha);
}

void HudRenderer::DrawArrow(Painter& p, FramePoint center, FramePoint along, double reach, double size, bool down) {
    const FramePlacement& place = emu_.Get<HudControls>().Placement();
    const FramePoint      tip{center.x + along.x * reach, center.y + along.y * reach};
    const FramePoint      base{tip.x - along.x * size * kArrowDepth, tip.y - along.y * size * kArrowDepth};
    const FramePoint      across{-along.y * size, along.x * size};
    const Point points[] = {ToPoint(place.ToCanvas(tip)),
                            ToPoint(place.ToCanvas(FramePoint{base.x + across.x, base.y + across.y})),
                            ToPoint(place.ToCanvas(FramePoint{base.x - across.x, base.y - across.y}))};
    const Rgb   color    = down ? kInk : kArrow;
    p.FillPolygonAA(points, 3, color, color);
}

void HudRenderer::DrawHint(Painter& p, const Rect& box, const std::string& hint, int px, uint32_t flags) {
    const int  pad = std::max(1, px / 3);
    const Rect inner{box.left + pad, box.top + pad, box.right - pad, box.bottom - pad};
    Font       font{FontFace::kUi, std::max(1, std::min(px, inner.Height())), false};
    const int  width = p.TextWidth(hint, font);
    if (width > inner.Width()) font.px = std::max(1, font.px * inner.Width() / width);
    p.DrawTextBox(inner, hint, font, kHint, flags | text::kSingleLine);
}

std::string HudRenderer::KeyHint(const std::vector<uint8_t>& keys) {
    std::string out;
    for (uint8_t vk : keys) {
        const char* legend = PcKeyLegend(vk);
        if (legend == nullptr) return std::string();
        if (!out.empty()) out += '+';
        out += legend;
    }
    return out;
}

int HudRenderer::HintPx(double side, int dpi) {
    const int px = std::max(ScaleForDpi(kHintMinPx, dpi), Round(side * kHintPart));
    return std::min(px, std::max(1, Round(side * kHintMaxPart)));
}

}
