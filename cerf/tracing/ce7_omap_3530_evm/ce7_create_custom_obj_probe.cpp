#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcCcoEntry            = 0x401583ECu;
constexpr uint32_t kPcCcoPostBaseControl  = 0x40158494u;
constexpr uint32_t kPcCcoPostNamespaceCheck = 0x40158500u;
constexpr uint32_t kVaPCurThd             = 0xFFFFC824u;

class TraceCe7CreateCustomObjProbe : public Service {
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

            tm.OnPcFiltered(kPcCcoEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 20 && (n % 50u) != 0u) return;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t pObjData = c.regs[1];
                    const uint32_t this_factory = c.regs[0];
                    uint32_t d[8];
                    for (int i = 0; i < 8; ++i)
                        d[i] = c.ReadVa32(pObjData + i * 4u).value_or(0xDEAD0001u);
                    const uint32_t ns_first = c.ReadVa32(this_factory + 0x64u).value_or(0xDEAD0001u);
                    const uint32_t ns_last  = c.ReadVa32(this_factory + 0x68u).value_or(0xDEAD0001u);
                    LOG(Trace,
                        "[cco] ENTRY #%u pTh=0x%08X this(factory)=0x%08X "
                        "pObjData=0x%08X "
                        "Type=0x%08X Id=0x%08X +08=0x%08X +0C=0x%08X "
                        "+10=0x%08X +14=0x%08X +18=0x%08X +1C=0x%08X "
                        "m_Namespaces._First=0x%08X ._Last=0x%08X count=%d\n",
                        n, pcurthd, this_factory, pObjData,
                        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
                        ns_first, ns_last,
                        (ns_first && ns_last && ns_last > ns_first) ?
                            (int)((ns_last - ns_first) >> 2) : -1);
                });

            tm.OnPcFiltered(kPcCcoPostBaseControl, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 20 && (n % 50u) != 0u) return;
                    LOG(Trace,
                        "[cco] post-CreateBaseControl #%u R0=0x%08X\n",
                        n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcCcoPostNamespaceCheck, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    LOG(Trace,
                        "[cco] NAMESPACE-CHECK BEQ-Error #%u "
                        "R5=0x%08X (was MOVEQ→0x8000FFFF iff namespace was NULL) "
                        "R0(nsIdx)=0x%08X R3(count_or_setval)=0x%08X\n",
                        n, c.regs[5], c.regs[0], c.regs[3]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7CreateCustomObjProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
