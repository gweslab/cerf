#include "../arm_processor_config.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

/* Intel XScale core as integrated in the PXA255 ("Cotulla"), ARMv5TE. */
class XscaleProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }

    /* ARMv5 / StrongARM / XScale store PC+8 for STR/STM of R15. Not
       documented in the Intel manuals (ARM-ARM implementation-defined);
       matches sibling SA-1110 (StrongARM ancestor) and ARM1136 configs. */
    uint32_t PcStoreOffset()              const override { return 8; }

    /* XScale Core Dev Manual §2.2.5: "the contents of the base register
       will not be updated ... referred to in ARM V5TE as the Base
       Restored Abort Model." */
    bool     BaseRestoredAbortModel()     const override { return true; }

    bool     MemoryBeforeWritebackModel() const override { return true; }

    bool     GenerateSyscalls()           const override { return false; }

    /* Cache Type Register line length 0b10 = 8 words = 32 bytes
       (XScale Core Dev Manual Table 7-5). */
    uint32_t CacheLineSize()              const override { return 32; }

    /* CP15 Register 0 ID. PXA255 manual Table 2-3 (A0 stepping):
       ARM ID = 0x69052D06 (0x69 Intel, 0x05 ARMv5TE, core gen 001 =
       XScale, product number 010000 = PXA255, revision 0110 = A0). */
    uint32_t Midr()                       const override { return 0x69052D06u; }

    /* Cache Type Register, XScale Table 7-5 fields with PXA255 sizes
       (manual §1.1: 32-KByte I-cache + 32-KByte D-cache, 32-way,
       8-word lines): class 0b0101, Harvard, Dsize/Isize 0b110,
       assoc 0b101, line 0b10. */
    uint32_t Ctr()                        const override { return 0x0B1AA1AAu; }

    /* XScale Core Dev Manual §2.2.4: implements the ARM DSP-Enhanced
       instruction set (SMLAxy/QADD/...) and LDRD/STRD/PLD. */
    bool     HasDsp()                     const override { return true; }
    bool     HasLoadStoreDouble()         const override { return true; }

    /* XScale Core Dev Manual §2.1: ARMv5TE adds CLZ and the V5(T)
       unconditional instruction space (BLX imm, PLD); enhanced
       ARM-Thumb transfer (BLX reg). */
    bool     HasClz()                     const override { return true; }
    bool     HasBlxReg()                  const override { return true; }
    bool     HasArmv5UnconditionalSpace() const override { return true; }

    /* PXA255 has no VFP / media coprocessor (Intel Media Processing =
       40-bit DSP accumulator via CP0, not VFP). All v6/v7 ISA additions
       absent — inherit base defaults (false). */

    /* PXA255 max run mode (PXA255 manual Table 3-20 CCCR): 3.6864 MHz
       crystal * L_mult(27) * M(x4) = 398.13 MHz core; OSCR is the
       3.6864 MHz crystal directly (/108); 32.768 kHz low-freq ref (/12150). */
    uint32_t CpuClockHz()                 const override { return 398131200u; }
    uint32_t CpuToOscrDivider()           const override { return 108; }
    uint32_t CpuToHighfreqClockDivider()  const override { return 108; }
    uint32_t CpuToLowfreqClockDivider()   const override { return 12150; }
};

}  /* namespace */

REGISTER_SERVICE_AS(XscaleProcessorConfig, ArmProcessorConfig);
