#include "../../peripherals/open_bus_window.h"

#include "../../core/cerf_emulator.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Figure 6-11 (page 6-71):
   "0x0800_0000 Static nCS<2> (64 MB)". Table 6-44 (page 6-85):
   "0x4800_0064 SA1110"; Table 6-31 (page 6-73) bit 8 SXENX reset 0 =
   "Use six 64 Mbyte chip selects (nCS<5:0>)".

   doc.dll 0x023C4E80 "LDRB r3,[r5]" chip-ID dispatch: 0x023C4F48
   "CMP r3,#0x7F" / 0x023C4F4C "BLT 0x023C4E0C" routes 0xFF to 0x023C4E0C
   "MOV r0,#0x120" / "ORR r0,r0,#3"; 0x023C4E8C "BEQ 0x023C4F28" routes
   0x00 to the chip-found path. */
class SymbolMk500NCs2OpenBus : public OpenBusWindow {
public:
    using OpenBusWindow::OpenBusWindow;

    uint32_t MmioBase() const override { return 0x08000000u; }
    uint32_t MmioSize() const override { return 0x04000000u; }

protected:
    Board WindowBoard() const override { return Board::SymbolMk500; }
};

}  /* namespace */

REGISTER_SERVICE(SymbolMk500NCs2OpenBus);
