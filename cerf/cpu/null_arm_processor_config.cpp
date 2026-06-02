#include "arm_processor_config.h"

#include "../boards/board_detector.h"
#include "../core/cerf_emulator.h"

namespace {

class NullArmProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        return emu_.Get<BoardDetector>().GetBoard() == Board::Unknown;
    }

    uint32_t PcStoreOffset()              const override { return 0; }
    bool     BaseRestoredAbortModel()     const override { return false; }
    bool     MemoryBeforeWritebackModel() const override { return false; }
    bool     GenerateSyscalls()           const override { return false; }
    uint32_t CacheLineSize()              const override { return 0; }
    uint32_t Midr()                       const override { return 0; }
    uint32_t Ctr()                        const override { return 0; }
    uint32_t CpuClockHz()                 const override { return 0; }
    bool     HasDsp()                     const override { return false; }
    bool     HasLoadStoreDouble()         const override { return false; }
};

}  /* namespace */

REGISTER_SERVICE_AS(NullArmProcessorConfig, ArmProcessorConfig);
