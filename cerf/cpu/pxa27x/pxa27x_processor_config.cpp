#include "../arm_processor_config.h"
#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../socs/pxa27x/pxa270_id.h"

namespace {

class Pxa27xProcessorConfig : public ArmProcessorConfig {
public:
    using ArmProcessorConfig::ArmProcessorConfig;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa270;
    }

    uint32_t PcStoreOffset()              const override { return 8; }
    bool     BaseRestoredAbortModel()     const override { return true; }
    uint32_t CacheLineSize()              const override { return 32; }

    uint32_t Midr()                       const override { return 0x69054117u; }

    uint32_t Ctr()                        const override { return 0x0D172172u; }

    bool     HasDsp()                     const override { return true; }
    bool     HasLoadStoreDouble()          const override { return true; }

    /* Intel PXA27x Developer's Manual 280000-001 Section 1.3.1 (page 1-19):
       "The Intel XScale microarchitecture complies with the ARM Architecture
       V5TE. The PXA27x processor implements the integer instruction set of the
       ARM Architecture V5TE." */
    bool     HasPreload()                 const override { return true; }

    /* Intel PXA27x Developer's Manual 280000-001 Section 2.2.5.3 (page 2-5):
       "Auxiliary Control Register (P-Bit) Access: Coprocessor 15, Register 1,
       opcode_2 = 1". */
    bool     HasAuxControlRegister()      const override { return true; }

    bool     HasClz()                     const override { return true; }
    bool     HasLoadToPcInterworking()    const override { return true; }
    bool     HasBlxReg()                  const override { return true; }
    bool     HasArmv5UnconditionalSpace() const override { return true; }
    bool     AccessesSpsrInSystemMode()   const override { return true; }

    /* Intel PXA27x Developer's Manual 280000-001 Table 3-7 (page 3-20): "L = 7
       (Core = 91.0 MHz) is used for hardware boot-up frequency". */
    uint32_t CpuClockHz()                 const override { return 91000000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(Pxa27xProcessorConfig, ArmProcessorConfig);
