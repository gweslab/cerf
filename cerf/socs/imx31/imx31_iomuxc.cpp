#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX31 IOMUXC pin-mux config (MCIMX31RM Ch 4 Table 4-1: GPR @0x008,
   SW_MUX_CTL @0x00C-0x150, SW_PAD_CTL @0x154-0x308, all R/W). Pure R/W storage
   — CERF models no physical pads, so mux values select nothing here; software
   just writes and reads them back. */
constexpr uint32_t kBase = 0x43FAC000u;
constexpr uint32_t kSize = 0x0000030Cu;  /* through SW_PAD_CTL last reg 0x308 (Table 4-1) */

class Imx31Iomuxc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override { return regs_[(addr - kBase) >> 2]; }
    void WriteWord(uint32_t addr, uint32_t value) override {
        regs_[(addr - kBase) >> 2] = value;
    }

private:
    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx31Iomuxc);
