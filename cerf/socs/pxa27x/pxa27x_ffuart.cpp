#include "pxa27x_uart16550.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 28-7 (page 28-12): "UART1 -
   Full Function UART 0x4010_0000". Table 25-2 (page 25-5): "IP[22] FFUART
   Transmit or receive error in FFUART 22". */
class Pxa27xFfuart : public Pxa27xUart16550 {
public:
    using Pxa27xUart16550::Pxa27xUart16550;

    uint32_t MmioBase() const override { return 0x40100000u; }

protected:
    uint32_t    IntcBit() const override { return 22u; }
    const char* Name()    const override { return "FFUART"; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa27xFfuart);
