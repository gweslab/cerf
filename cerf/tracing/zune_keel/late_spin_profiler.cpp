#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#include <atomic>

#if CERF_DEV_MODE

namespace {

/* Locate the late-boot busy-spin: sample pc/lr/sp/procid + insn word every
   25000 RunLoop iters past iter 100000. boot_progress logs PC only for the
   first 2000 iters, so it can't see the late loop. */
class ZuneKeelLateSpinProfiler : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            static std::atomic<uint64_t> n{0};
            tm.OnRunLoopIter([](const TraceContext& c) {
                const uint64_t i = n.fetch_add(1, std::memory_order_relaxed);
                if (i < 100000 || (i % 25000) != 0) return;
                const uint32_t procid =
                    c.emu.Get<ArmMmu>().State()->process_id;
                const uint32_t insn = c.ReadVa32(c.pc).value_or(0xDEADDEADu);
                LOG(Trace, "[LATE-SPIN] iter=%llu pc=0x%08X lr=0x%08X sp=0x%08X "
                           "procid=0x%08X insn@pc=0x%08X\n",
                    static_cast<unsigned long long>(i), c.pc, c.regs[14],
                    c.regs[13], procid, insn);
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelLateSpinProfiler);

#endif  /* CERF_DEV_MODE */
