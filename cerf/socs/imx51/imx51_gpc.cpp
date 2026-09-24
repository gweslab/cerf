#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 GPC (General Power Controller), MCIMX51RM Ch 34, base 0x73FD8000 (Ch 2
   Table 2-1). R/W register file (general regs + DPTC/DVFS + PGC/SRPGC
   power-gating sub-blocks 0x220-0x310); the OAL clock/power init read-modify-
   writes these, so reads return the last write. */
constexpr uint32_t kBase = 0x73FD8000u;
constexpr uint32_t kSize = 0x00001000u;

struct GpcReset { uint32_t off; uint32_t val; };
constexpr GpcReset kResets[] = {   /* Table 34-1 non-zero reset values */
    {0x000, 0x02108000u},  /* CNTR   */
    {0x008, 0x00000001u},  /* VCR    */
    {0x00C, 0x00000700u},  /* ALL_PU */
    {0x010, 0x00000030u},  /* NEON   */
};

class Imx51Gpc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        for (const auto& r : kResets) regs_[r.off >> 2] = r.val;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override { return regs_[(addr - kBase) >> 2]; }
    void WriteWord(uint32_t addr, uint32_t value) override {
        regs_[(addr - kBase) >> 2] = value;
    }

    /* JIT-thread-only register file (no worker thread). */
    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx51Gpc);
