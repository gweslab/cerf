#include "pxa255_uart16550.h"

namespace {

/* PXA255 FFUART — full-function UART, the kernel debug console (base
   0x40100000, INTC IS22 Table 4-35). */
class Pxa255Ffuart : public Pxa255Uart16550 {
public:
    using Pxa255Uart16550::Pxa255Uart16550;

    uint32_t MmioBase() const override { return 0x40100000u; }

protected:
    uint32_t    IntcBit() const override { return 22u; }
    const char* Name()    const override { return "FFUART"; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa255Ffuart);
