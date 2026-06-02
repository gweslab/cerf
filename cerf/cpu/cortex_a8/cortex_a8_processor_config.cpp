#include "../arm_processor_config.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

class CortexA8ProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OmapEvm3530;
    }

    uint32_t PcStoreOffset()              const override { return 12; }
    bool     BaseRestoredAbortModel()     const override { return true; }
    bool     MemoryBeforeWritebackModel() const override { return true; }
    bool     GenerateSyscalls()           const override { return false; }
    uint32_t CacheLineSize()              const override { return 64; }
    uint32_t Midr()                       const override { return 0x410fc080u; }
    uint32_t Ctr()                        const override { return 0x82048004u; }

    /* floor(720 000 000 / 32 768) — Cortex-A8 nominal max MPU clock
       over GPTIMER1 32 kHz functional clock. Used by Omap3530Gptimer1
       / Omap3530Synctimer to convert guest_cycle_counter → ticks. */
    uint32_t CpuToOscrDivider()           const override { return 21972u; }

    /* 720 MHz Cortex-A8 max MPU clock per OMAP3530 TRM §1.4.1. */
    uint32_t CpuClockHz()                 const override { return 720000000u; }

    bool     HasDsp()                     const override { return true; }
    bool     HasLoadStoreDouble()         const override { return true; }

    bool     HasClz()                     const override { return true; }
    bool     HasBlxReg()                  const override { return true; }
    bool     HasArmv5UnconditionalSpace() const override { return true; }
    bool     HasMovwMovt()                const override { return true; }
    bool     HasBitField()                const override { return true; }
    bool     HasRev()                     const override { return true; }
    bool     HasExtendRotate()            const override { return true; }
    bool     HasLdrexStrex()              const override { return true; }
    bool     HasBarrierInsn()             const override { return true; }
    bool     HasCp15V6()                  const override { return true; }
    bool     HasCp15V7()                  const override { return true; }
    bool     HasVmsav7()                  const override { return true; }

    uint32_t Clidr()                      const override { return 0x0A000003u; }

    uint32_t Ccsidr(uint32_t csselr) const override {
        const uint32_t level = (csselr >> 1) & 0x7u;
        const uint32_t ind   =  csselr       & 0x1u;
        if (level == 0) {
            return ind ? 0x2007e01au   /* L1 I-cache, 16 KB */
                       : 0xe007e01au;  /* L1 D-cache, 16 KB */
        }
        if (level == 1) {
            return 0xf0000000u;
        }
        return 0u;
    }

    bool     HasVfp()  const override { return true; }
    bool     HasNeon() const override { return true; }
    uint32_t Fpsid()   const override { return 0x410330C0u; }
    uint32_t Mvfr0()   const override { return 0x11110222u; }
    uint32_t Mvfr1()   const override { return 0x00011111u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(CortexA8ProcessorConfig, ArmProcessorConfig);
