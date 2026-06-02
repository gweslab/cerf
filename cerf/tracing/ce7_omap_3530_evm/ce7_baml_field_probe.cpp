#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcCtorExit       = 0x4044EC98u;
constexpr uint32_t kPcReadStreamEntry = 0x40452518u;
constexpr uint32_t kVaPCurThd = 0xFFFFC824u;

void DumpBamlReader(const TraceContext& c, const char* tag, uint32_t this_va) {
    const uint32_t pcurthd =
        c.ReadVa32(kVaPCurThd).value_or(0u);
    const auto& mmu_state = *c.emu.Get<ArmMmu>().State();
    const uint32_t ttbr =
        mmu_state.translation_table_base.word & 0xFFFFC000u;

    uint32_t w[10];
    for (int i = 0; i < 10; ++i)
        w[i] = c.ReadVa32(this_va + i * 4u).value_or(0xDEADC0DEu);

    LOG(Trace,
        "[baml] %s this=0x%08X pTh=0x%08X TTBR0=0x%08X "
        "+00=0x%08X +04=0x%08X +08=0x%08X +0C=0x%08X "
        "+10=0x%08X +14=0x%08X +18=0x%08X +1C=0x%08X "
        "+20=0x%08X +24=0x%08X\n",
        tag, this_va, pcurthd, ttbr,
        w[0], w[1], w[2], w[3], w[4], w[5], w[6],
        w[7], w[8], w[9]);
}

class TraceCe7BamlFieldProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto user_proc_only = [](const TraceContext& c) -> bool {
                return (c.emu.Get<ArmMmu>()
                            .State()
                            ->translation_table_base.word
                        & 0xFFFFC000u) != 0u;
            };

            tm.OnPcFiltered(kPcCtorExit, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 20 && (n % 50u) != 0u) return;
                    DumpBamlReader(c, "ctor-EXIT", c.regs[0]);
                });

            tm.OnPcFiltered(kPcReadStreamEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 20 && (n % 50u) != 0u) return;
                    DumpBamlReader(c, "ReadStream-ENTRY", c.regs[0]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7BamlFieldProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
