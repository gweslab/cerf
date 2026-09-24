#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* PXA255 internal LCD controller (§7.7 Table 7-16, base 0x44000000), decoded
   registers 0x000..0x21C, reset 0. Panel scanout is unmodeled: this board's
   display is the external SED1356 (0x0C000000) and the OAL uses this block
   only as scratch, so enabling scanout (LCCR0.ENB=1, §7.6.1) halts. */
class Pxa255LcdController : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa255;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x44000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    static constexpr uint32_t kLccr0   = 0x000u;  /* §7.6.1: ENB = bit 0. */
    static constexpr uint32_t kLastReg = 0x21Cu;  /* LDCMD1, end of decoded window. */
    uint32_t regs_[(kLastReg / 4u) + 1u] = {};
};

uint32_t Pxa255LcdController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off <= kLastReg && (off & 3u) == 0u) return regs_[off / 4u];
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255LcdController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == kLccr0 && (value & 0x1u))
        HaltUnsupportedAccess("WriteWord(LCCR0.ENB: PXA255 internal LCD scanout not modeled)",
                              addr, value);
    if (off <= kLastReg && (off & 3u) == 0u) { regs_[off / 4u] = value; return; }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255LcdController::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_, sizeof(regs_));
}

void Pxa255LcdController::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_, sizeof(regs_));
}

}  /* namespace */

REGISTER_SERVICE(Pxa255LcdController);
