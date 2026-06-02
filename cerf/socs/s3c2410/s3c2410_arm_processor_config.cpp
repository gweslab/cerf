#include "../../cpu/arm_processor_config.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

class S3C2410ArmProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    uint32_t PcStoreOffset()              const override { return 12; }
    bool     BaseRestoredAbortModel()     const override { return true; }
    bool     MemoryBeforeWritebackModel() const override { return true; }
    bool     GenerateSyscalls()           const override { return false; }
    uint32_t CacheLineSize()              const override { return 32; }
    uint32_t Midr()                       const override { return 0x69059201u; }
    uint32_t Ctr()                        const override { return 0x0B172172u; }
    bool     HasDsp()                     const override { return true; }
    bool     HasLoadStoreDouble()         const override { return true; }

    /* S3C2410 User Manual §7.7.1 — FCLK default 200 MHz (max 266). */
    uint32_t CpuClockHz()                 const override { return 200000000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(S3C2410ArmProcessorConfig, ArmProcessorConfig);
