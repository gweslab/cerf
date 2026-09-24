#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 DPLLIP clock PLL, MCIMX51RM Ch.22. Three instances: DPLL1/2/3 @
   0x83F80000 / 0x83F84000 / 0x83F88000 (RM AIPS-2 map). R/W config (CERF has
   no clock tree). DP_CTL (0x0, §22.2.2.1) bit0 LRF is a RO lock flag the OAL
   polls; with no PLL settling, LRF reads 1 whenever UPEN (bit5) enables it. */
constexpr uint32_t kSize     = 0x00001000u;
constexpr uint32_t kDpCtlOff = 0x000u;
constexpr uint32_t kLrf      = 1u << 0;   /* DP_CTL[0] Lock Ready Flag (RO) */
constexpr uint32_t kUpen     = 1u << 5;   /* DP_CTL[5] DPLL up/enable */

class Imx51DpllBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        uint32_t v = regs_[off >> 2];
        if (off == kDpCtlOff) v = (v & ~kLrf) | ((v & kUpen) ? kLrf : 0u);
        return v;
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        regs_[(addr - MmioBase()) >> 2] = value;
    }

    /* JIT-thread-only register file (no worker thread). */
    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    std::array<uint32_t, kSize / 4> regs_{};
};

class Imx51Dpll1 : public Imx51DpllBase {
public:
    using Imx51DpllBase::Imx51DpllBase;
    uint32_t MmioBase() const override { return 0x83F80000u; }
};
class Imx51Dpll2 : public Imx51DpllBase {
public:
    using Imx51DpllBase::Imx51DpllBase;
    uint32_t MmioBase() const override { return 0x83F84000u; }
};
class Imx51Dpll3 : public Imx51DpllBase {
public:
    using Imx51DpllBase::Imx51DpllBase;
    uint32_t MmioBase() const override { return 0x83F88000u; }
};

}  /* namespace */

REGISTER_SERVICE(Imx51Dpll1);
REGISTER_SERVICE(Imx51Dpll2);
REGISTER_SERVICE(Imx51Dpll3);
