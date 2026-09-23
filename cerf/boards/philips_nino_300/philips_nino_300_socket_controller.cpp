#include "../../peripherals/ite_it8368/ite_it8368_bus_window.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "philips_nino_300_id.h"

#include <cstdint>

namespace {

/* The IT8368E sits on chip select 2, PA $1040_0000 (Table 4.2.1, TMPR3911.pdf
   PDF p.103). pcmcia_mips.dll sub_18811D0 VirtualCopies 34 bytes of it. */
constexpr uint32_t kBase = 0x10400000u;
constexpr uint32_t kSize = 0x22u;

class PhilipsNino300SocketController : public IteIt8368BusWindow {
public:
    using IteIt8368BusWindow::IteIt8368BusWindow;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsNino300;
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

protected:
    /* The chip's byte lanes are crossed on this board's bus: nk.exe sub_9F411C5C
       writes CTRL = $0B80 for $800B and GPIODIR = $F100 for $00F1. */
    bool LanesCrossed() const override { return true; }
};

}

REGISTER_SERVICE(PhilipsNino300SocketController);
