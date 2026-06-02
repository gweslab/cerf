#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* PXA255 RTC (§4.3, Table 4-51, base 0x40900000): RCNR 0x00 (seconds
   counter), RTAR 0x04, RTSR 0x08 (Table 4-40: HZE/ALE enables bits3:2,
   HZ/AL W1C status bits1:0), RTTR 0x0C (trim, §4.3.3 resets 0x00007FFF).
   Static block; HZ/alarm interrupts unused (scheduler tick is the OST). */
class Pxa255Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40900000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kRttrMask = 0x03FFFFFFu;  /* bits 25:0 */

    uint32_t rcnr_ = 0;
    uint32_t rtar_ = 0;
    uint32_t rtsr_ = 0;
    uint32_t rttr_ = 0x00007FFFu;  /* §4.3.3 nRESET default. */
};

uint32_t Pxa255Rtc::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return rcnr_;
        case 0x04: return rtar_;
        case 0x08: return rtsr_ & 0xFu;
        case 0x0C: return rttr_ & kRttrMask;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255Rtc::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: rcnr_ = value; return;
        case 0x04: rtar_ = value; return;
        /* RTSR: HZ(bit1)/AL(bit0) are write-1-to-clear status; HZE(bit3)/
           ALE(bit2) are read/write enables (Table 4-40). */
        case 0x08: rtsr_ = (rtsr_ & 0x3u & ~value) | (value & 0xCu); return;
        case 0x0C: rttr_ = value & kRttrMask; return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Pxa255Rtc);
