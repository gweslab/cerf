#include "cortex_a8_processor_config.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../socs/imx51/imx51_id.h"

namespace {

class Imx51ProcessorConfig : public CortexA8ProcessorConfigBase {
public:
    using CortexA8ProcessorConfigBase::CortexA8ProcessorConfigBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }

    /* Cortex-A8 r2p5 (variant 2, revision 5): the i.MX51 core revision per
       MCIMX51RM Rev.1 §2 ("processor version r2p5"). */
    uint32_t Midr() const override { return 0x412FC085u; }

    /* arm_clk = DPLL1 with CACRR ARM_PODF unwritten (/1). Ford SBOOT programs
       DPLL1 DP_OP=0x60/MFN=1/MFD=3 -> MF=6.25, PDF=0 -> 4*MF*osc = 25*24MHz =
       600 MHz. osc = 24 MHz (IMX51CEC p14); DPLL2->665 / DPLL3->432 confirm the
       24 MHz reference (MCIMX51RM Eqn 22-1). */
    uint32_t CpuClockHz() const override { return 600000000u; }

    /* Cortex-A8 with unified L2 present (ARM DDI0344K TRM, c0 Cache Level ID
       Register, page 3-39: 0x0A000023). */
    uint32_t Clidr() const override { return 0x0A000023u; }

    /* 32 KB L1 I/D and 256 KB unified L2, per ARM DDI0344K TRM Table 3-42
       (Encodings of the Cache Size Identification Register). */
    uint32_t Ccsidr(uint32_t csselr) const override {
        const uint32_t level = (csselr >> 1) & 0x7u;
        const uint32_t ind   =  csselr       & 0x1u;
        if (level == 0) {
            return ind ? 0x200FE01Au   /* L1 I-cache, 32 KB */
                       : 0xE00FE01Au;  /* L1 D-cache, 32 KB */
        }
        if (level == 1) {
            return 0xF03FE03Au;        /* unified L2, 256 KB */
        }
        return 0u;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Imx51ProcessorConfig, ArmProcessorConfig);
