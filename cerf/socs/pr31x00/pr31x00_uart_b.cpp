#include "pr31x00_uart.h"

#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

class Pr31x00UartB : public Pr31x00Uart {
public:
    using Pr31x00Uart::Pr31x00Uart;

    uint32_t MmioBase() const override { return 0x10C000C8u; }

protected:
    const char* TxSource() const override { return "UARTB"; }
    uint32_t RxIntBit() const override { return 1u << 21; }
    uint32_t TxEmptyIntBit() const override { return 1u << 14; }
    uint32_t TxAvailIntBit() const override { return 1u << 16; }
    uint32_t DmaFullIntBit() const override { return 1u << 13; }
    uint32_t DmaHalfIntBit() const override { return 1u << 12; }
    uint32_t ClockEnableBit() const override { return 1u << 0; }
};

}  /* namespace */

REGISTER_SERVICE(Pr31x00UartB);
