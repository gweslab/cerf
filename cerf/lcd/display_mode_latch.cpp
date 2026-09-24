#include "display_mode_latch.h"

#include "../core/cerf_emulator.h"
#include "../host/host_window.h"
#include "../state/state_stream.h"

bool DisplayModeLatch::Publish(CerfEmulator& emu, bool display_enabled, uint32_t width, uint32_t height) {
    if (!display_enabled) {
        published_ = false;
        return false;
    }
    if (published_ && width == width_ && height == height_) return false;

    published_ = true;
    width_ = width;
    height_ = height;
    emu.Get<HostWindow>().OnLcdEnabled();
    return true;
}

void DisplayModeLatch::SaveState(StateWriter& w) const {
    w.Write<uint8_t>("enable_published", published_ ? 1u : 0u);
    w.Write("published_w", width_);
    w.Write("published_h", height_);
}

void DisplayModeLatch::RestoreState(StateReader& r) {
    uint8_t en = 0;
    r.Read("enable_published", en);
    published_ = en != 0;
    r.Read("published_w", width_);
    r.Read("published_h", height_);
}
