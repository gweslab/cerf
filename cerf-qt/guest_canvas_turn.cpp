#include "guest_canvas_turn.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_resize_regs.h>

namespace cerffrontend {

REGISTER_SERVICE(GuestCanvasTurn);

int GuestCanvasTurn::LogicalQuarter(int presentation_quarter) const {
    auto*          fb    = emu_.TryGet<cerfcore::CerfVirtFramebuffer>();
    const uint32_t guest = fb ? fb->Quarter() : 0u;
    return static_cast<int>(cerfcore::CerfVirt::QuarterTurnsFrom(guest, static_cast<uint32_t>(presentation_quarter)));
}

}
