#include "pxa27x_uart16550.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 28-7 (page 28-12): "UART 3 -
   Standard UART 0x4070_0000". Table 25-2 (page 25-5): "IP[20] STUART Transmit or
   receive error in STUART 20". */
class Pxa27xStuart : public Pxa27xUart16550 {
public:
    using Pxa27xUart16550::Pxa27xUart16550;

    uint32_t MmioBase() const override { return 0x40700000u; }

protected:
    uint32_t    IntcBit() const override { return 20u; }
    const char* Name()    const override { return "STUART"; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa27xStuart);
