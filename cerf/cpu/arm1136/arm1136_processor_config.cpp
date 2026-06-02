#include "../arm_processor_config.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

class Arm1136ProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        return emu_.Get<BoardDetector>().GetBoard() == Board::ZuneKeel;
    }

    uint32_t PcStoreOffset()              const override { return 8; }

    bool     BaseRestoredAbortModel()     const override { return true; }

    bool     MemoryBeforeWritebackModel() const override { return true; }

    bool     GenerateSyscalls()           const override { return false; }

    uint32_t CacheLineSize()              const override { return 32; }

    uint32_t Midr()                       const override { return 0x4127B363u; }

    uint32_t Ctr()                        const override { return 0x1D152152u; }

    bool     HasDsp()                     const override { return true; }
    bool     HasLoadStoreDouble()         const override { return true; }

    /* ARMv5+ ISA additions on top of v4. */
    bool     HasClz()                     const override { return true; }
    bool     HasBlxReg()                  const override { return true; }
    bool     HasArmv5UnconditionalSpace() const override { return true; }

    /* ARMv6 ISA additions on top of v5. */
    bool     HasExtendRotate()            const override { return true; }
    bool     HasRev()                     const override { return true; }
    bool     HasLdrexStrex()              const override { return true; }
    bool     HasCp15V6()                  const override { return true; }

    bool     HasVfp()                     const override { return true; }

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
