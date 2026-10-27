#pragma once

#include "../painter.h"
#include "../pc_keyboard_layout.h"

#include <cerfcore/core/service.h>

#include <cstdint>

namespace cerfcore { struct KeyBinding; }

namespace cerffrontend {

class KeyboardMappingPanel : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int kUnitW   = 46;
    static constexpr int kUnitH   = 36;
    static constexpr int kGap     = 5;
    static constexpr int kMargin  = 16;
    static constexpr int kHeaderH = 58;
    static constexpr int kTop     = kMargin + kHeaderH;
    static constexpr int kClientW = static_cast<int>(kPcKeyboardUnitsW * kUnitW + 0.5f) + 2 * kMargin;
    static constexpr int kClientH = kTop + static_cast<int>(kPcKeyboardUnitsH * kUnitH + 0.5f) + kMargin;

    static constexpr const char* kTitle = "Keyboard mapping";

    void Reset() { active_layer_ = 0; }
    void Paint(Painter& p, const Rect& client, bool dark);
    bool OnClick(int x, int y);

private:
    struct Palette {
        Rgb bg, cap_mapped, cap_unmapped, border, text, accent, active, mod;
    };

    static Palette MakePalette(bool dark);
    static Rect    CapRect(const KeyCap& cap);
    static Rect    ToggleRect(int index);

    const cerfcore::KeyBinding* FindBinding(uint8_t vk, uint8_t layer) const;
    void                        DrawCap(Painter& p, const KeyCap& cap, const Palette& pal);

    uint8_t active_layer_ = 0;
};

}
