#include "xscale_processor_config_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

namespace {
class Iop13xxProcessorConfig final : public XscaleProcessorConfigBase {
public:
    using XscaleProcessorConfigBase::XscaleProcessorConfigBase;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::IOP13xx;
    }
    /* Linux v3.18 arch/arm/mm/proc-xsc3.S identifies Intel XSC3 with
       MIDR value/mask 0x69056000/0xffffe000. */
    uint32_t Midr() const override { return 0x69056000u; }
    /* Third Generation Intel XScale Microarchitecture Developer's Manual,
       Table 30: 32-KiB, 4-way I/D L1 caches with 32-byte lines. */
    uint32_t Ctr() const override { return 0x0B192192u; }
    /* Linux v3.18 arch/arm/mach-iop13xx/include/mach/time.h decodes the
       IOP13xx CORE_FREQ_800 strap as 800000000 Hz. */
    uint32_t CpuClockHz() const override { return 800000000u; }
    /* siemens_mp377_v1040 nk.exe sub_80448694 installs 16-entry L1
       descriptors with bit 18 set for both PCI outbound windows. */
    ArmSupersectionFormat SupersectionFormat() const override { return ArmSupersectionFormat::kXScale; }

};
} // namespace
REGISTER_SERVICE_AS(Iop13xxProcessorConfig, ArmProcessorConfig);
