#include "../../peripherals/open_bus_window.h"

#include "../../core/cerf_emulator.h"

namespace {

/* Unpopulated static-bank space between the modem window and the
   CL-CD1284 debug board (SA-1110 Dev Manual ch.2 map). SA-1110 data
   aborts are MMU-generated, so these accesses complete: writes vanish,
   reads float - jlime pushes its post-MMU-off stack here on real HW. */
class Jornada720OpenBus : public OpenBusWindow {
public:
    using OpenBusWindow::OpenBusWindow;

    uint32_t MmioBase() const override { return 0x08400000u; }
    uint32_t MmioSize() const override { return 0x11C00000u; }

protected:
    Board       WindowBoard() const override { return Board::Jornada720; }
    const char* WindowTag()   const override { return "J720OpenBus"; }
};

}  /* namespace */

REGISTER_SERVICE(Jornada720OpenBus);
