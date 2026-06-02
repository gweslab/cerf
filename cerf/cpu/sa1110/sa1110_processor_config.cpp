#include "../arm_processor_config.h"

#include <intrin.h>

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../jit/decoded_insn.h"
#include "../../jit/place_fns.h"

namespace {

class Sa1110ProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Ipaq3650;
    }

    uint32_t PcStoreOffset()              const override { return 8; }

    /* Linux proc-sa1100.S:238  dabort=v4_early_abort → base-RESTORED. */
    bool     BaseRestoredAbortModel()     const override { return true; }

    bool     MemoryBeforeWritebackModel() const override { return true; }

    bool     GenerateSyscalls()           const override { return false; }

    /* Linux proc-sa1100.S:33  #define DCACHELINESIZE 32. */
    uint32_t CacheLineSize()              const override { return 32; }

    /* SA-1110 Dev Manual §5.2.1 (Arch 01 = v4, Part B11 = SA1110);
       Linux proc-sa1100.S:277 sa1110 = 0x6901b110 mask 0xfffffff0. */
    uint32_t Midr()                       const override { return 0x6901B110u; }

    uint32_t Ctr()                        const override { return 0x6901B110u; }

    bool     HasDsp()                     const override { return false; }
    bool     HasLoadStoreDouble()         const override { return false; }

    uint16_t CycleCostFor(const DecodedInsn& d) const override {
        if (d.place_fn == &PlaceBlockDataTransfer) {
            /* LDM/STM = MAX(2, registers). */
            const unsigned n = __popcnt16(d.register_list);
            return static_cast<uint16_t>(n < 2 ? 2 : n);
        }
        if (d.place_fn == &PlaceMRSorMSR) {
            /* d.s == 1 marks MSR (control write); MRS read = 1. */
            return d.s ? 3 : 1;
        }
        if (d.place_fn == &PlaceMSRImmediate) return 3;
        return 1;
    }

    /* 206 MHz core / 3.6864 MHz OSCR (SA-1110 Dev Manual §9.4.1). */
    uint32_t CpuToOscrDivider() const override { return 56; }
    uint32_t CpuClockHz()       const override { return 206000000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Sa1110ProcessorConfig, ArmProcessorConfig);
