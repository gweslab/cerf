#include "../../peripherals/open_bus_window.h"

#include "../../core/cerf_emulator.h"

namespace {

/* ROM Area PA 0x18000000-0x1FFFFFFF; ROMCS banks stack down from 0x1FFFFFFF, top
   16 MB populated at PA 0x1F000000 (VR4121 UM Fig 6-8, Table 6-6, Table 6-7).
   RFU below is not illegal-access-notified (UM 11.4.7: only 0x0D000000-0x0FFFFFFF
   and 0x04000000-0x09FFFFFF). Guest reader nk.exe sub_9F0B75F4 case 1 @ PA 0x1D99FFFC. */
class CasioToricomailRomOpenBus : public OpenBusWindow {
public:
    using OpenBusWindow::OpenBusWindow;

    uint32_t MmioBase() const override { return 0x18000000u; }
    uint32_t MmioSize() const override { return 0x1F000000u - 0x18000000u; }

protected:
    Board WindowBoard() const override { return Board::CasioToricomail; }
};

}  /* namespace */

REGISTER_SERVICE(CasioToricomailRomOpenBus);
