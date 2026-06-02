#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"
#include "zune_process_resolver.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* pmc_atapi_mx31.dll sub_3057E1C creates PMC/DiskStarted signaled at its end;
   zserv waits on that to launch gemstone (the UI). Hooks (device.exe context)
   show whether it reaches the create or hits an early-return bail first. */
class ZuneKeelPmcDiskStartedBisect : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            const TracePredicate dev = zune_resolver::PidPredicateForName("device.exe");

            tm.OnPcFiltered(0x3057E1Cu, dev, [](const TraceContext& c) {
                static std::atomic<int> n{0};
                LOG(Trace, "[PMC-PMINIT] sub_3057E1C ENTRY #%d a1=0x%08X a2=0x%08X\n",
                    n.fetch_add(1), c.regs[0], c.regs[1]);
            });

            /* Reached only if every early bail was passed — right before the
               CreateEvent(PMC/DiskStarted) call. */
            tm.OnPcFiltered(0x3058330u, dev, [](const TraceContext& c) {
                LOG(Trace, "[PMC-PMINIT] reached PMC/DiskStarted create site "
                           "(no early bail) lr=0x%08X\n", c.regs[14]);
            });

            /* The store a1[21]=hEvent right after the create — confirms the event
               handle returned. */
            tm.OnPcFiltered(0x3058354u, dev, [](const TraceContext& c) {
                LOG(Trace, "[PMC-PMINIT] PMC/DiskStarted created, handle=0x%08X\n",
                    c.regs[0]);
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelPmcDiskStartedBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
