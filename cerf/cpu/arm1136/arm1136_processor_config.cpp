#include "../arm_processor_config.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../socs/imx31/imx31_id.h"

namespace {

class Arm1136ProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }

    /* ARM DDI 0100I "Reading the program counter" (p. A2-9): STR/STM of R15
       stores insn+8 or insn+12 - "IMPLEMENTATION DEFINED". The ARM1136 TRM
       (ARM DDI 0211) does not document the choice; 8 is unverified. */
    uint32_t PcStoreOffset()              const override { return 8; }

    bool     BaseRestoredAbortModel()     const override { return true; }


    uint32_t CacheLineSize()              const override { return 32; }

    uint32_t Midr()                       const override { return 0x4127B363u; }

    uint32_t Ctr()                        const override { return 0x1D152152u; }

    bool     HasDsp()                     const override { return true; }
    bool     HasLoadStoreDouble()         const override { return true; }
    bool     HasPreload()                 const override { return true; }

    /* ARMv5+ ISA additions on top of v4. */
    bool     HasClz()                     const override { return true; }
    bool     HasBlxReg()                  const override { return true; }
    bool     HasArmv5UnconditionalSpace() const override { return true; }

    /* v5T+ load-to-PC interworking (DDI0406C §A2.3.1). */
    bool     HasLoadToPcInterworking()    const override { return true; }

    /* ARMv6 ISA additions on top of v5. */
    bool     HasExtendRotate()            const override { return true; }
    bool     HasRev()                     const override { return true; }
    bool     HasLdrexStrex()              const override { return true; }
    /* ARM DDI 0211I section 2.10 (p. 2-24): "These instructions were
       introduced in rev1 of the ARM1136JF-S processor (r1p0)." */
    bool     HasLdrexStrexV6k()           const override { return true; }
    bool     HasCp15V6()                  const override { return true; }
    /* ARM DDI 0211I section 6.2.5: "Every supersection is defined to have its
       Domain as 0" and they work at either XP setting; Figures 6-4/6-7/6-8
       show bits[23:20] SBZ and bits[8:5] Ignored, so the PA is 32-bit. */
    ArmSupersectionFormat SupersectionFormat() const override {
        return ArmSupersectionFormat::kPa32;
    }

    /* ARM DDI 0406C.c Figure D12-1 (p. D12-2526): c1 opc1=0 CRm=c0
       opc2={0-2} System control registers, Read/Write. */
    bool     HasAuxControlRegister()      const override { return true; }

    bool     HasVfp()                     const override { return true; }

    /* ARM DDI 0274H Table 3-3 (p. 3-16): the VFP11 coprocessor of the
       ARM1136JF-S resets MVFR0 to 0x11111111 and MVFR1 to 0x00000000, both
       read-only. */
    uint32_t Mvfr0()                      const override { return 0x11111111u; }
    uint32_t Mvfr1()                      const override { return 0x00000000u; }

    /* ARM DDI 0274H Table 3-5 (p. 3-17): FPSID Implementor 0x41, hardware
       implementation, Format 1, both precisions, architecture b0001 VFPv2,
       part number 0x20 VFP11, variant 0xB; footnote a gives Revision 0x3 for
       "the r1p0 to r1p4 releases of the ARM1136JF-S processor". */
    uint32_t Fpsid()                      const override { return 0x410120B3u; }

    /* MCIMX31RM Figure 3-24 (PDF p235) clock tree + Table 3-5 PDR0
       field decode: Pyxis OAL writes PDR0=0xFF841E5B (MCU_PDF=3,
       MAX_PODF=3, IPG_PODF=1) so arm_clk/ipg_clk = 4*2/4 = 2. */
    uint32_t CpuToOscrDivider()           const override { return 2; }

    /* Divider = CpuClockHz / source_clock (icount ratio). highfreq =
       ipg_clk_highfreq = 66 MHz (kernel reads it from BSP_ARGS+0xE8;
       532M/66M≈8); lowfreq = CKIL 32.768 kHz (532M/32768≈16235). */
    uint32_t CpuToHighfreqClockDivider()  const override { return 8; }
    uint32_t CpuToLowfreqClockDivider()   const override { return 16235; }

    /* MCIMX31RM §3.5.3 arm_clk max = 532 MHz. */
    uint32_t CpuClockHz()                 const override { return 532000000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Arm1136ProcessorConfig, ArmProcessorConfig);
