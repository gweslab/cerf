#include "overlay_input.h"

#include "boot_screen.h"
#include "canvas_tabs.h"
#include "frontend_window.h"
#include "notification_overlay.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/notification_stack.h>

#include <vector>

namespace cerffrontend {

REGISTER_SERVICE(OverlayInput);

HudPointer OverlayInput::HudKey(Producer producer, int pointer) { return HudPointer{static_cast<int>(producer), pointer}; }

bool OverlayInput::CardAt(int x, int y, uint32_t& id) const {
    return emu_.Get<NotificationOverlay>().HitTest(x, y, id);
}

bool OverlayInput::HudTakes(int x, int y) const {
    if (emu_.Get<CanvasTabs>().Current() != cerfcore::CanvasTab::Framebuffer) return false;
    const HudControls& hud = emu_.Get<HudControls>();
    return hud.InsideCanvas() ? hud.InBand(x, y) : hud.HitTest(x, y);
}

bool OverlayInput::HwLineAt(int x, int y) const {
    return emu_.Get<CanvasTabs>().Current() == cerfcore::CanvasTab::Boot && emu_.Get<BootScreen>().HitTestHwLine(x, y);
}

bool OverlayInput::Takes(int x, int y) const {
    uint32_t card = 0;
    return CardAt(x, y, card) || HudTakes(x, y) || HwLineAt(x, y);
}

uint32_t OverlayInput::OwnedHeld(Producer producer, int pointer) const {
    uint32_t held = 0;
    for (const Key& key : owned_)
        if (key.producer == producer && key.pointer == pointer) held |= CanvasInput::ButtonBit(key.button);
    return held;
}

OverlayInput::Press OverlayInput::OnPress(Producer producer, int pointer, MouseButton button, int x, int y) {
    if (CanvasInput::ButtonBit(button) == 0) return Press::kNone;
    const Key key{producer, pointer, button};
    uint32_t  card = 0;
    if (CardAt(x, y, card)) {
        owned_.insert(key);
        if (button == MouseButton::kLeft) emu_.Get<cerfcore::NotificationStack>().Dismiss(card);
        return Press::kTaken;
    }
    if (HwLineAt(x, y)) {
        owned_.insert(key);
        if (button == MouseButton::kLeft) emu_.Get<FrontendWindow>().SetTab(cerfcore::CanvasTab::Hw, true);
        return Press::kTaken;
    }
    if (!HudTakes(x, y)) return Press::kNone;
    owned_.insert(key);
    HudControls& hud = emu_.Get<HudControls>();
    if (button == MouseButton::kRight) hud.ToggleLatch(x, y);
    if (button != MouseButton::kLeft || !hud.Press(HudKey(producer, pointer), x, y)) return Press::kTaken;
    return Press::kControl;
}

bool OverlayInput::OnMove(Producer producer, int pointer, int x, int y) {
    HudControls&     hud = emu_.Get<HudControls>();
    const HudPointer hud_pointer = HudKey(producer, pointer);
    if (!hud.Holds(hud_pointer)) return false;
    hud.Move(hud_pointer, x, y);
    return true;
}

OverlayInput::Release OverlayInput::OnRelease(Producer producer, int pointer, MouseButton button, bool hold_latches) {
    if (owned_.erase(Key{producer, pointer, button}) == 0) return Release::kPassed;
    HudControls&     hud         = emu_.Get<HudControls>();
    const HudPointer hud_pointer = HudKey(producer, pointer);
    if (button != MouseButton::kLeft || !hud.Holds(hud_pointer)) return Release::kTaken;
    hud.Release(hud_pointer, hold_latches);
    return Release::kControl;
}

void OverlayInput::OnCancel(Producer producer, int pointer) {
    for (auto it = owned_.begin(); it != owned_.end();) {
        if (it->producer == producer && it->pointer == pointer) it = owned_.erase(it);
        else                                                    ++it;
    }
    HudControls&     hud         = emu_.Get<HudControls>();
    const HudPointer hud_pointer = HudKey(producer, pointer);
    if (hud.Holds(hud_pointer)) hud.Release(hud_pointer, false);
}

void OverlayInput::CancelAll(Producer producer) {
    std::vector<int> pointers;
    for (const Key& key : owned_)
        if (key.producer == producer) pointers.push_back(key.pointer);
    for (int pointer : pointers) OnCancel(producer, pointer);
}

bool OverlayInput::OnMouse(Producer producer, int pointer, const CanvasMouse& m, bool hold_latches) {
    switch (m.kind) {
        case CanvasMouse::Kind::kDown:
            return OnPress(producer, pointer, m.button, m.x, m.y) != Press::kNone;
        case CanvasMouse::Kind::kMove:
            return OnMove(producer, pointer, m.x, m.y);
        case CanvasMouse::Kind::kUp:
            return OnRelease(producer, pointer, m.button, hold_latches) != Release::kPassed;
        case CanvasMouse::Kind::kCaptureLost:
        case CanvasMouse::Kind::kWheel:
            return false;
    }
    return false;
}

}
