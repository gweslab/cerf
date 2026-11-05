#pragma once

#include "canvas_input.h"
#include "hud_controls.h"

#include <cerfcore/core/service.h>

#include <compare>
#include <cstdint>
#include <set>

namespace cerffrontend {

class OverlayInput : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    enum class Producer : uint8_t { kCanvasMouse, kOverlayTouch, kOverlayMouse };
    enum class Press : uint8_t { kNone, kTaken, kControl };
    enum class Release : uint8_t { kPassed, kTaken, kControl };

    bool     Takes(int x, int y) const;
    uint32_t OwnedHeld(Producer producer, int pointer) const;
    bool     OnMouse(Producer producer, int pointer, const CanvasMouse& m, bool hold_latches);
    Press    OnPress(Producer producer, int pointer, MouseButton button, int x, int y);
    bool     OnMove(Producer producer, int pointer, int x, int y);
    Release  OnRelease(Producer producer, int pointer, MouseButton button, bool hold_latches);
    void     OnCancel(Producer producer, int pointer);
    void     CancelAll(Producer producer);

private:
    struct Key {
        Producer    producer = Producer::kCanvasMouse;
        int         pointer  = 0;
        MouseButton button   = MouseButton::kNone;

        auto operator<=>(const Key&) const = default;
    };

    static HudPointer HudKey(Producer producer, int pointer);

    bool CardAt(int x, int y, uint32_t& id) const;
    bool HudTakes(int x, int y) const;
    bool HwLineAt(int x, int y) const;

    std::set<Key> owned_;
};

}
