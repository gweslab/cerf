#include "display_size_latch.h"

#include "../core/cerf_emulator.h"
#include "../host/host_window.h"
#include "../state/state_stream.h"

#include <cstdint>

bool DisplaySizeLatch::PublishOnce(CerfEmulator& emu, bool display_enabled) {
    if (published_ || !display_enabled) return false;
    published_ = true;
    emu.Get<HostWindow>().OnLcdEnabled();
    return true;
}

void DisplaySizeLatch::SaveState(StateWriter& w) const {
    w.Write<uint8_t>(published_ ? 1u : 0u);
}

void DisplaySizeLatch::RestoreState(StateReader& r) {
    uint8_t v = 0;
    r.Read(v);
    published_ = v != 0;
}
