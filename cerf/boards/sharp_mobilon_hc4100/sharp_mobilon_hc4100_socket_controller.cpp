#include "../../peripherals/ite_it8368/ite_it8368_bus_window.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "sharp_mobilon_hc4100_id.h"

#include <cstdint>

namespace {

/* The IT8368E is on chip select 2, PA $1040_0000: pcmcia.dll sub_14913DC
   VirtualCopies kseg1 $B040_0000 into its register pointer, and the CS2 fault
   pa=0x10400020 lands here. */
constexpr uint32_t kBase = 0x10400000u;
constexpr uint32_t kSize = 0x22u;

class SharpMobilonHc4100SocketController : public IteIt8368BusWindow {
public:
    using IteIt8368BusWindow::IteIt8368BusWindow;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SharpMobilonHc4100;
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

protected:
    /* This board crosses the chip's byte lanes: pcmcia.dll sub_149120C writes
       GPIODIR = $F100 for the chip's $00F1 and MFIODIR = $FF07 for $07FF. */
    bool LanesCrossed() const override { return true; }
};

}

REGISTER_SERVICE(SharpMobilonHc4100SocketController);
