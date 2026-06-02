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

/* services.exe (pid 0x0A000000) hosts zserv/zam and is the process that should
   launch gemstone (the UI). It loads the app stack by ~t+41s then stops making
   progress. Sample its user-space PC late in boot to see where it spins/idles. */
class ZuneKeelServicesStallPc : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.pc >= 0x80000000u) return;                 /* user only */
                if (c.emu.Get<ArmMmu>().State()->process_id != 0x0A000000u) return;
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                /* skip the busy early boot; sample the late steady state */
                if (i < 200000u) return;
                if ((i & 0x3FFFu) != 0) return;
                LOG(Trace, "[SVC-PC] i=%u pc=0x%08X lr=0x%08X sp=0x%08X "
                           "r0=0x%08X r1=0x%08X\n",
                    i, c.pc, c.regs[14], c.regs[13], c.regs[0], c.regs[1]);
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelServicesStallPc);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
