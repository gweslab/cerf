#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX31 IOMUXC pin-mux config (MCIMX31RM Ch 4 Table 4-1: GPR @0x008,
   SW_MUX_CTL @0x00C-0x150, SW_PAD_CTL @0x154-0x308, all R/W). Pure R/W storage
   - CERF models no physical pads, so mux values select nothing here; software
   just writes and reads them back. */
constexpr uint32_t kBase = 0x43FAC000u;
constexpr uint32_t kSize = 0x0000030Cu;  /* through SW_PAD_CTL last reg 0x308 (Table 4-1) */

class Imx31Iomuxc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

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

REGISTER_SERVICE(Imx31Iomuxc);
