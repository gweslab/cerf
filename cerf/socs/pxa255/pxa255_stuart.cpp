#include "pxa255_uart16550.h"

namespace {

/* PXA255 STUART — standard UART, used by the IrDA driver for SIR (base
   0x40700000, INTC IS20 Table 4-35). */
class Pxa255Stuart : public Pxa255Uart16550 {
public:
    using Pxa255Uart16550::Pxa255Uart16550;

    uint32_t MmioBase() const override { return 0x40700000u; }

protected:
    uint32_t    IntcBit() const override { return 20u; }
    const char* Name()    const override { return "STUART"; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa255Stuart);
