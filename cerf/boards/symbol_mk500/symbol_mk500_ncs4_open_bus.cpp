#include "../../peripherals/open_bus_window.h"

#include "../../core/cerf_emulator.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Figure 6-11 (page 6-71):
   "0x1000_0000" "Static nCS<4> (64 MB)" in both map options.

   SMSC9211.dll (ImageBase 0x10000000) RVA 0x2C18 "LDR r3,[r1,#0x64]" /
   0x2C1C "CMP r3,r2" against the RVA 0x2D38 literal 0x87654321 / 0x2C20
   "BNE 0x2D2C" / 0x2D2C "MOV r0,#0" / 0x2D34 "BX lr". */
class SymbolMk500NCs4OpenBus : public OpenBusWindow {
public:
    using OpenBusWindow::OpenBusWindow;

    uint32_t MmioBase() const override { return 0x10000000u; }
    uint32_t MmioSize() const override { return 0x04000000u; }

protected:
    Board WindowBoard() const override { return Board::SymbolMk500; }
};

}  /* namespace */

REGISTER_SERVICE(SymbolMk500NCs4OpenBus);
