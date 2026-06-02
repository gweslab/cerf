#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* PXA255 Memory Controller (§6.13 Table 6-43, base 0x48000000): SDRAM/
   static-memory timing + refresh config — no functional effect on CERF's
   timing-less emulated memory, so storage (MDCNFG resets 0, Table 6-2).
   BOOT_DEF (0x44) read-only; registers span 0x00..0x58. */
class Pxa255MemoryController : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x48000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kBootDef  = 0x44u;  /* read-only. */
    static constexpr uint32_t kLastReg  = 0x58u;  /* MDMRSLP. */
    uint32_t regs_[(kLastReg / 4u) + 1u] = {};
};

uint32_t Pxa255MemoryController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    /* BOOT_DEF holds board BOOT_SEL/PKG_SEL straps (Table 6-43); its value
       is a physical board config, not 0 — halt loudly rather than return a
       guessed strap, so it gets the verified Falcon value when first read. */
    if (off == kBootDef) HaltUnsupportedAccess("ReadWord(BOOT_DEF strap)", addr, 0);
    if (off <= kLastReg && (off & 3u) == 0u) return regs_[off / 4u];
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255MemoryController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    /* BOOT_DEF is read-only; a write is anomalous — surface it loudly
       rather than silently dropping it. */
    if (off == kBootDef) HaltUnsupportedAccess("WriteWord(BOOT_DEF read-only)", addr, value);
    if (off <= kLastReg && (off & 3u) == 0u) { regs_[off / 4u] = value; return; }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Pxa255MemoryController);
