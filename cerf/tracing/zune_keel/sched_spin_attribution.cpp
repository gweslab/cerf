#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* The kernel uptime accumulator sub_8823BF34 reads its EPIT-derived tick
   source *(0x88FDF4A8+16) on every call. Sample it to see whether the
   timebase advances (counter live, compare-IRQ missing) or is frozen. */
class ZuneKeelSchedSpinAttribution : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            tm.OnPc(0x8823BF34u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if ((i & 0x3FFu) != 0) return;  /* every 1024th call */
                auto base = c.ReadVa32(0x88FDF4A8u);
                auto tick = base.has_value() ? c.ReadVa32(*base + 16u)
                                             : std::optional<uint32_t>{};
                auto acc  = c.ReadVa32(0x88FDC250u);
                LOG(Trace, "[EPIT-TICK] #%u lr=0x%08X acc(0x88FDC250)=0x%08X "
                           "cpsr=0x%08X I=%d mode=0x%02X\n",
                    i, c.regs[14],
                    acc.has_value() ? *acc : 0xDEADBEEFu,
                    c.cpsr, (c.cpsr >> 7) & 1, c.cpsr & 0x1Fu);
                (void)tick;
            });
            /* ARM high-vector IRQ entry (SCTLR.V=1). One fire = an interrupt
               was delivered; zero fires across the boot = no IRQ delivery. */
            tm.OnPc(0xFFFF0018u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 8 || (i & 0xFFFu) == 0) {
                    LOG(Trace, "[IRQ-VECTOR] fire #%u pc=0x%08X lr=0x%08X\n",
                        i, c.pc, c.regs[14]);
                }
            });
            /* sub_88205830 = IRQ-enable (CPSR &= ~0x80). Sample CPSR a couple
               instructions in, to see steady-state I outside the
               briefly-disabled window the timebase-poll hook lands in. */
            /* 0x8820583C = BX LR, the instruction AFTER MSR CPSR_fc completes.
               CPSR here is the post-unmask value — shows whether the guest
               actually reaches I=0 interruptible state in steady state. */
            tm.OnPc(0x8820583Cu, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 4 || (i & 0x3FFu) == 0) {
                    LOG(Trace, "[POST-UNMASK] #%u cpsr=0x%08X I=%d mode=0x%02X\n",
                        i, c.cpsr, (c.cpsr >> 7) & 1, c.cpsr & 0x1Fu);
                }
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelSchedSpinAttribution);

#endif  /* CERF_DEV_MODE */
