#include "../arm_processor_config.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"

namespace {

class Arm720TProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }

    uint32_t PcStoreOffset()              const override { return 12; }
    bool     BaseRestoredAbortModel()     const override { return false; }
    bool     MemoryBeforeWritebackModel() const override { return true; }
    bool     GenerateSyscalls()           const override { return false; }
    uint32_t CacheLineSize()              const override { return 32; }
    uint32_t Midr()                       const override { return 0x41807200u; }
    uint32_t Ctr()                        const override { return 0x41807200u; }

    bool     HasDsp()                     const override { return false; }
    bool     HasLoadStoreDouble()         const override { return false; }

    /* ARM720T core in Microsoft Poseidon NDA board: 70 MHz typical. */
    uint32_t CpuClockHz()                 const override { return 70000000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Arm720TProcessorConfig, ArmProcessorConfig);
