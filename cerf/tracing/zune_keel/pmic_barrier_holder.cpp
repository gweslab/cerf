#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "bundle.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* Kernel MUTEX_PMIC barrier: sub_8823F0AC acquires (WaitForMultipleObjects
   returns to 0x8823F0D0), sub_8823F114 releases. Track the live balance; if it
   stays held, report the last acquirer (pid/lr) — the thread stuck holding it. */
std::atomic<int>      g_balance{0};
std::atomic<uint32_t> g_holder_pid{0};
std::atomic<uint32_t> g_holder_lr{0};

class ZuneKeelPmicBarrierHolder : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            tm.OnPc(0x8823F0D0u, [](const TraceContext& c) {
                g_balance.fetch_add(1, std::memory_order_relaxed);
                g_holder_pid.store(c.emu.Get<ArmMmu>().State()->process_id,
                                   std::memory_order_relaxed);
                g_holder_lr.store(c.regs[14], std::memory_order_relaxed);
            });
            tm.OnPc(0x8823F114u, [](const TraceContext&) {
                g_balance.fetch_sub(1, std::memory_order_relaxed);
            });

            /* Poll: if the lock has been held continuously for many iterations,
               report the holder once. */
            tm.OnRunLoopIter([](const TraceContext&) {
                static int held_iters = 0;
                static bool reported = false;
                if (g_balance.load(std::memory_order_relaxed) > 0) {
                    if (++held_iters == 50000 && !reported) {
                        reported = true;
                        LOG(Trace, "[PMIC-HELD] mutex held >50k iters, "
                                   "holder pid=0x%08X lr=0x%08X balance=%d\n",
                            g_holder_pid.load(), g_holder_lr.load(),
                            g_balance.load());
                    }
                } else {
                    held_iters = 0;
                }
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelPmicBarrierHolder);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
