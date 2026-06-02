#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"

#include <atomic>

#if CERF_DEV_MODE

namespace {

/* nk.exe exception dispatcher sub_800C2268. At entry R0=context, R1=type,
   R2=FAR, R3=FSR; context offsets PSR=+0x60 SP=+0x98 LR=+0x9C PC=+0xA0 (from
   its PC/Lr/Sp/Psr decompile). Dumps the faulting context to find why a
   thread faults with a garbage SP (the CS0+0x60EC0 frame-store fatal). */
class Falcon4220ExcHandlerContext : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kFalcon4220BundleCrc32, [&] {
            static std::atomic<uint64_t> hits{0};
            tm.OnPc(0x800C2268u, [](const TraceContext& c) {
                const uint64_t n = hits.fetch_add(1, std::memory_order_relaxed);
                const uint32_t ctx = c.regs[0];
                auto psr = c.ReadVa32(ctx + 0x60u);
                auto sp  = c.ReadVa32(ctx + 0x98u);
                auto lr  = c.ReadVa32(ctx + 0x9Cu);
                auto pc  = c.ReadVa32(ctx + 0xA0u);
                const uint32_t sp_val = sp.has_value() ? *sp : 0xFFFFFFFFu;
                /* Always log the bogus-SP case (target) plus the first 64
                   for context, so the fatal call is never throttled out. */
                if (n >= 64 && sp_val >= 0x00100000u) return;
                LOG(Trace, "[FALCON] exc-handler n=%llu type=%d FAR=0x%08X "
                           "FSR=0x%08X | faultPC=0x%08X faultLR=0x%08X "
                           "faultSP=0x%08X faultPSR=0x%08X | ctx=0x%08X "
                           "handlerLR=0x%08X handlerCPSR=0x%08X\n",
                    static_cast<unsigned long long>(n),
                    static_cast<int>(c.regs[1]), c.regs[2], c.regs[3],
                    pc.has_value()  ? *pc  : 0xDEADBEEFu,
                    lr.has_value()  ? *lr  : 0xDEADBEEFu,
                    sp_val,
                    psr.has_value() ? *psr : 0xDEADBEEFu,
                    ctx, c.regs[14], c.cpsr);
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(Falcon4220ExcHandlerContext);

#endif  /* CERF_DEV_MODE */
