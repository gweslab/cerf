#include "pxa255_uart16550.h"

namespace {

/* PXA255 BTUART — Bluetooth UART (base 0x40200000, INTC IS21 Table 4-35). */
class Pxa255Btuart : public Pxa255Uart16550 {
public:
    using Pxa255Uart16550::Pxa255Uart16550;

    uint32_t MmioBase() const override { return 0x40200000u; }

protected:
    uint32_t    IntcBit() const override { return 21u; }
    const char* Name()    const override { return "BTUART"; }
};

}  /* namespace */

REGISTER_SERVICE(Pxa255Btuart);
