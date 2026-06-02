#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* PXA255 Clocks Manager (§3.6, base 0x41300000): CCCR 0x00, CKEN 0x04,
   OSCC 0x08. CERF doesn't gate clocks, so CCCR/CKEN are plain storage.
   OSCC OOK must read 1 as soon as OON is set, or a guest polling OOK for
   oscillator stabilization hangs (no real oscillator to settle). */
class Pxa255ClockManager : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x41300000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kCccrMask = 0x000003FFu;  /* N[9:7] M[6:5] L[4:0] */
    static constexpr uint32_t kCkenMask = 0x00017BFFu;  /* CKEN R/W bits (15,10 reserved) */

    uint32_t cccr_ = 0x00000121u;  /* §3.6.1 reset: N=010, M=01, L=00001. */
    uint32_t cken_ = 0x00017BFFu;  /* §3.6.2 reset: all unit clocks enabled. */
    bool     oon_  = false;        /* OSCC OON (bit1), write-once until reset. */
};

uint32_t Pxa255ClockManager::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return cccr_;
        case 0x04: return cken_;
        case 0x08: return oon_ ? 0x3u : 0x0u;  /* OON|OOK once enabled. */
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255ClockManager::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: cccr_ = value & kCccrMask; return;
        case 0x04: cken_ = value & kCkenMask; return;
        case 0x08: if (value & 0x2u) oon_ = true; return;  /* OON write-once; OOK is RO. */
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Pxa255ClockManager);
