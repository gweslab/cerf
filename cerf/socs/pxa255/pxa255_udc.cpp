#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* PXA255 USB Device Controller (§12, base 0x40600000). Modeled as the
   disconnected state — no USB host is wired to the emulated device, so no
   USB events ever occur: interrupt-status bits (UDCCR W1C, USIR0/1) read 0
   and the control/mask registers (UDCCR, UICR0/1) are plain storage. */
class Pxa255Udc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40600000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kUdccrRwMask = 0xA5u;  /* REM|SRM|RSM|UDE */
    static constexpr uint32_t kUicrMask    = 0xFFu;  /* IM0..IM7 / IM8..IM15 */

    uint32_t udccr_ = 0xA0u;   /* §12.6.1 reset: REM=1, SRM=1. */
    uint32_t uicr0_ = 0xFFu;   /* §12.6.9  Table 12-20 reset: all EP int masked. */
    uint32_t uicr1_ = 0xFFu;   /* §12.6.10 Table 12-21 reset: all EP int masked. */
};

uint32_t Pxa255Udc::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return udccr_;
        case 0x04: return 0u;  /* §12.7 Table 12-33: reserved, reads undefined. */
        case 0x0C: return 0u;  /* §12.7 Table 12-33: reserved. */
        case 0x50: return uicr0_;
        case 0x54: return uicr1_;
        case 0x58: return 0u;  /* USIR0 §12.6.11: no host → no pending int. */
        case 0x5C: return 0u;  /* USIR1: no host → no pending int. */
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255Udc::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: udccr_ = value & kUdccrRwMask; return;
        case 0x04: return;  /* §12.7 Table 12-33: reserved. */
        case 0x0C: return;  /* §12.7 Table 12-33: reserved. */
        case 0x50: uicr0_ = value & kUicrMask;    return;
        case 0x54: uicr1_ = value & kUicrMask;    return;
        case 0x58: return;  /* USIR0 W1C: status bits never set with no host. */
        case 0x5C: return;  /* USIR1 W1C. */
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Pxa255Udc);
