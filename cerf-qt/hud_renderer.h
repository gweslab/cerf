#pragma once

#include "hud_controls.h"
#include "painter.h"
#include "viewport_layout.h"

#include <cerfcore/core/service.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerfcore {
class KeyboardMap;
}

namespace cerffrontend {

struct CanvasPixels {
    const uint32_t* bits   = nullptr;
    int             width  = 0;
    int             height = 0;
};

class HudRenderer : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Render(Painter& p, const ViewportLayout::Layout& frame, int dpi, const CanvasPixels& canvas);

private:
    uint8_t                  HeldLayer(const cerfcore::KeyboardMap& map);
    static cerfcore::HudFace Face(const cerfcore::HudButton& button, const cerfcore::KeyboardMap* map, uint8_t layer);
    static bool              Renamed(const std::vector<uint8_t>& keys, const cerfcore::KeyboardMap* map);
    void DrawBackdrop(Painter& p, const HudBandShown& band, const CanvasPixels& canvas);
    void DrawButton(Painter& p, const HudShown& shown, const cerfcore::HudFace& face, bool renamed, int dpi);
    void DrawDpad(Painter& p, const HudShown& shown);
    void DrawArrow(Painter& p, FramePoint center, FramePoint along, double reach, double size, bool down);
    void DrawHint(Painter& p, const Rect& box, const std::string& hint, int px, uint32_t flags);
    static std::string KeyHint(const std::vector<uint8_t>& keys);
    static int         HintPx(double side, int dpi);
};

}
