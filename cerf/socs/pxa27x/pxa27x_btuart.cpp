#include "pxa27x_uart16550.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 28-7 (page 28-12): "UART2 -
   Bluetooth UART 0x4020_0000". Table 25-2 (page 25-5): "IP[21] BTUART Transmit
   or receive error in BTUART 21". */
class Pxa27xBtuart : public Pxa27xUart16550 {
public:
    using Pxa27xUart16550::Pxa27xUart16550;

    uint32_t MmioBase() const override { return 0x40200000u; }

protected:
    uint32_t    IntcBit() const override { return 21u; }
    const char* Name()    const override { return "BTUART"; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa27xBtuart);
