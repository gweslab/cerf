#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcCbcEntry              = 0x40157EA0u;
constexpr uint32_t kPcCbcPostGetPresCore    = 0x40157ED0u;
constexpr uint32_t kPcCbcSetEUnexpected     = 0x40157ED8u;
constexpr uint32_t kPcCbcPostCreateObj      = 0x40157EF8u;
constexpr uint32_t kPcCbcCheckCoreDOnull    = 0x40157F04u;
constexpr uint32_t kVaPCurThd               = 0xFFFFC824u;

class TraceCe7CreateBaseControlProbe : public Service {
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

            tm.OnPcFiltered(kPcCbcEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cbc] ENTRY #%u pTh=0x%08X this(factory)=0x%08X "
                        "CoreBaseIndex=0x%08X obj_id=0x%08X ppBaseControl=0x%08X\n",
                        n, pcurthd, c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
                });

            tm.OnPcFiltered(kPcCbcPostGetPresCore, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[cbc] post-GetPresentationCore #%u R0(core*)=0x%08X\n",
                        n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcCbcSetEUnexpected, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    LOG(Trace,
                        "[cbc] SET-E_UNEXPECTED #%u LR=0x%08X "
                        "(reached either via GetPresCore==NULL OR pCoreDO==NULL)\n",
                        n, c.regs[14]);
                });

            tm.OnPcFiltered(kPcCbcPostCreateObj, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[cbc] post-CreateObjectByTypeIndex #%u R0=0x%08X\n",
                        n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcCbcCheckCoreDOnull, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[cbc] check-pCoreDO-NULL #%u R1(pCoreDO)=0x%08X\n",
                        n, c.regs[1]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7CreateBaseControlProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
