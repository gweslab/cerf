#pragma once

#include "hud_layout.h"
#include "viewport_layout.h"

#include <cerfcore/core/service.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace cerffrontend {

struct HudShown {
    const cerfcore::HudNode* node = nullptr;
    FrameRect                device;
    FrameRect                canvas;
};

struct HudBandShown {
    cerfcore::HudSide side  = cerfcore::HudSide::kBottom;
    double            inner = 0.0;
    double            outer = 0.0;
    double            lo    = 0.0;
    double            hi    = 0.0;
    FrameRect         canvas;
};

class HudControls : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int kMousePointer = -1;

    void SetCanvasArea(const std::optional<FrameRect>& area) { canvas_area_ = area; }
    void Place(const cerfcore::DbHud& hud, const ViewportLayout::Layout& frame);
    void Clear();

    const std::vector<HudShown>&     Shown() const { return shown_; }
    const std::vector<HudBandShown>& Bands() const { return bands_; }
    const std::vector<HudSeparator>& Separators() const { return separators_; }
    const FramePlacement&            Placement() const { return placement_; }
    bool                             InsideCanvas() const { return placed_area_.has_value(); }

    bool HitTest(int x, int y) const;
    bool InBand(int x, int y) const;
    bool Press(int pointer, int x, int y);
    void Move(int pointer, int x, int y);
    void Release(int pointer, bool hold_latches);
    bool ToggleLatch(int x, int y);
    void CancelAll();

    bool KeyDown(uint8_t vk) const;
    bool KeysDown(const std::vector<uint8_t>& keys) const;
    bool Latched(const cerfcore::HudNode* node) const { return latched_.count(node) != 0; }
    bool Pressed(const cerfcore::HudNode* node) const;

    std::vector<uint8_t> DpadKeys(const HudShown& shown, FramePoint device) const;

private:
    struct PointerPress {
        const cerfcore::HudNode*              node = nullptr;
        std::vector<uint8_t>                  keys;
        std::chrono::steady_clock::time_point since;
        bool                                  unlatch = false;
    };

    void            Publish(const cerfcore::DbHud& hud, const HudFrame& frame, double sx, double sy);
    const HudShown* At(int x, int y) const;
    const HudShown* Of(const cerfcore::HudNode* node) const;
    void            PressKeys(const std::vector<uint8_t>& keys);
    void            ReleaseKeys(const std::vector<uint8_t>& keys);
    void            RunAction(const std::string& id);

    const cerfcore::DbHud*                         hud_ = nullptr;
    ViewportLayout::Layout                         frame_;
    std::optional<FrameRect>                       canvas_area_;
    std::optional<FrameRect>                       placed_area_;
    FramePlacement                                 placement_{FrameRect{}, 0};
    std::vector<HudShown>                          shown_;
    std::vector<HudBandShown>                      bands_;
    std::vector<HudSeparator>                      separators_;
    std::map<int, PointerPress>                    pointers_;
    std::map<const cerfcore::HudNode*, std::vector<uint8_t>> latched_;
    std::array<uint8_t, 256>                       count_{};
};

}
