#include "pr31x00_uart.h"

#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

class Pr31x00UartA : public Pr31x00Uart {
public:
    using Pr31x00Uart::Pr31x00Uart;

    uint32_t MmioBase() const override { return 0x10C000B0u; }

protected:
    const char* TxSource() const override { return "UARTA"; }
    uint32_t RxIntBit() const override { return 1u << 31; }
    uint32_t TxEmptyIntBit() const override { return 1u << 24; }
    uint32_t TxAvailIntBit() const override { return 1u << 26; }
    uint32_t DmaFullIntBit() const override { return 1u << 23; }
    uint32_t DmaHalfIntBit() const override { return 1u << 22; }
    uint32_t ClockEnableBit() const override { return 1u << 1; }
};

}  /* namespace */

REGISTER_SERVICE(Pr31x00UartA);
