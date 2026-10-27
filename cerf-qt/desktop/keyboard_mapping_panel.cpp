#include "keyboard_mapping_panel.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/keyboard_map.h>

#include <string>
#include <vector>

namespace cerffrontend {

REGISTER_SERVICE(KeyboardMappingPanel);

namespace {

constexpr Font kUiFont{FontFace::kSystem, 0, false};
constexpr Font kCapFont{FontFace::kSystem, -2, false};

}

KeyboardMappingPanel::Palette KeyboardMappingPanel::MakePalette(bool dark) {
    if (dark)
        return {{32, 32, 36},   {60, 60, 66},    {44, 44, 47},   {96, 96, 102},
                {235, 235, 235}, {120, 180, 255}, {38, 84, 140}, {48, 68, 98}};
    return {{240, 240, 240}, {252, 252, 252}, {224, 224, 224}, {168, 168, 168},
            {24, 24, 24},    {20, 96, 200},   {176, 208, 248}, {208, 224, 250}};
}

const cerfcore::KeyBinding* KeyboardMappingPanel::FindBinding(uint8_t vk, uint8_t layer) const {
    const cerfcore::KeyBinding* base      = nullptr;
    const cerfcore::KeyBinding* layer_hit = nullptr;
    for (const cerfcore::KeyBinding& b : emu_.Get<cerfcore::KeyboardMap>().Bindings()) {
        if (b.vk != vk) continue;
        if (b.layer == layer) layer_hit = &b;
        if (b.layer == 0) base = &b;
    }
    if (layer == 0) return base;
    if (layer_hit) return layer_hit;
    return (base && base->holds_layer == layer) ? base : nullptr;
}

Rect KeyboardMappingPanel::CapRect(const KeyCap& cap) {
    const int x = kMargin + static_cast<int>(cap.x * kUnitW + 0.5f);
    const int y = kTop + static_cast<int>(cap.y * kUnitH + 0.5f);
    const int w = static_cast<int>(cap.w * kUnitW + 0.5f) - kGap;
    return {x, y, x + w, y + kUnitH - kGap};
}

Rect KeyboardMappingPanel::ToggleRect(int index) {
    constexpr int kBox = 16, kW = 96, kStride = 110;
    const int     left = kMargin + index * kStride;
    const int     top  = kMargin + 30;
    return {left, top, left + kW, top + kBox};
}

void KeyboardMappingPanel::DrawCap(Painter& p, const KeyCap& cap, const Palette& pal) {
    const Rect rc = CapRect(cap);

    const cerfcore::KeyBinding* b         = FindBinding(cap.vk, active_layer_);
    const bool                  mapped    = b != nullptr;
    const bool                  modifier  = mapped && b->holds_layer != 0;
    const bool                  is_active = modifier && b->holds_layer == active_layer_;

    const Rgb fill = !mapped    ? pal.cap_unmapped
                     : is_active ? pal.active
                     : modifier  ? pal.mod
                                 : pal.cap_mapped;
    p.FillRect(rc, fill);
    p.Rectangle(rc, modifier ? pal.accent : pal.border, modifier ? 2 : 1, nullptr);
    if (!mapped) return;

    if (b->guest_label == nullptr) {
        p.DrawTextBox(rc, cap.legend, kCapFont, pal.text,
                      text::kCenter | text::kVCenter | text::kSingleLine);
        return;
    }
    const int  mid = (rc.top + rc.bottom) / 2;
    const Rect top{rc.left, rc.top, rc.right, mid};
    const Rect bot{rc.left, mid, rc.right, rc.bottom};
    p.DrawTextBox(top, cap.legend, kCapFont, pal.text,
                  text::kCenter | text::kBottom | text::kSingleLine);
    p.DrawTextBox(bot, b->guest_label, kCapFont, modifier ? pal.text : pal.accent,
                  text::kCenter | text::kTop | text::kSingleLine);
}

void KeyboardMappingPanel::Paint(Painter& p, const Rect& client, bool dark) {
    const Palette pal = MakePalette(dark);
    p.FillRect(client, pal.bg);

    auto&                                          map     = emu_.Get<cerfcore::KeyboardMap>();
    const std::vector<cerfcore::KeyboardToggleLayer> toggles = map.ToggleLayers();
    std::string mods;
    uint32_t    seen_layers = 0;
    std::string active_name;
    bool        active_is_toggle = false;
    for (const cerfcore::KeyBinding& b : map.Bindings()) {
        if (b.holds_layer == 0) continue;
        const std::string name = b.guest_label ? b.guest_label : "modifier";
        if (b.holds_layer == active_layer_) active_name = name;
        if (b.holds_layer < 32 && !(seen_layers & (1u << b.holds_layer))) {
            seen_layers |= 1u << b.holds_layer;
            if (!mods.empty()) mods += " / ";
            mods += name;
        }
    }
    if (active_name.empty())
        for (const cerfcore::KeyboardToggleLayer& t : toggles)
            if (t.layer == active_layer_) {
                active_name      = t.name;
                active_is_toggle = true;
                break;
            }

    std::string header;
    if (active_layer_ != 0) {
        const std::string m = active_name.empty() ? "the modifier" : active_name;
        header = active_is_toggle ? "Previewing the " + m + " layer - untick " + m + " to return."
                                  : "Previewing the " + m + " layer - click " + m + " again to return.";
    } else if (!mods.empty()) {
        header = "Dimmed keys are unmapped. Click a highlighted modifier (" + mods + ") to preview its layer.";
    } else {
        header = "Dimmed keys are unmapped; blue shows the guest action where it differs from "
                 "the key.";
    }
    p.DrawTextBox({kMargin, kMargin, kClientW - kMargin, kMargin + 24}, header, kUiFont, pal.text,
                  text::kLeft | text::kVCenter | text::kSingleLine);

    for (int i = 0; i < static_cast<int>(toggles.size()); ++i) {
        const Rect r       = ToggleRect(i);
        const bool checked = active_layer_ == toggles[static_cast<size_t>(i)].layer;
        const Rect box{r.left, r.top, r.left + 16, r.bottom};
        p.FillRect(box, checked ? pal.active : pal.cap_mapped);
        p.Rectangle(box, checked ? pal.accent : pal.border, 1, nullptr);
        if (checked) {
            const Point tick[] = {{box.left + 3, box.top + 8}, {box.left + 6, box.top + 12},
                                  {box.left + 13, box.top + 4}};
            p.Polyline(tick, 3, pal.text, 2);
        }
        p.DrawTextBox({box.right + 6, r.top, r.right, r.bottom},
                      toggles[static_cast<size_t>(i)].name, kUiFont, pal.text,
                      text::kLeft | text::kVCenter | text::kSingleLine);
    }

    for (const KeyCap& cap : kPcKeyboard) DrawCap(p, cap, pal);
}

bool KeyboardMappingPanel::OnClick(int x, int y) {
    const std::vector<cerfcore::KeyboardToggleLayer> toggles =
        emu_.Get<cerfcore::KeyboardMap>().ToggleLayers();
    for (int i = 0; i < static_cast<int>(toggles.size()); ++i) {
        if (!ToggleRect(i).Contains(x, y)) continue;
        const uint8_t layer = toggles[static_cast<size_t>(i)].layer;
        active_layer_       = active_layer_ == layer ? 0 : layer;
        return true;
    }
    for (const KeyCap& cap : kPcKeyboard) {
        if (!CapRect(cap).Contains(x, y)) continue;
        const cerfcore::KeyBinding* base = FindBinding(cap.vk, 0);
        if (!base || base->holds_layer == 0) return false;
        active_layer_ = active_layer_ == base->holds_layer ? 0 : base->holds_layer;
        return true;
    }
    return false;
}

}
