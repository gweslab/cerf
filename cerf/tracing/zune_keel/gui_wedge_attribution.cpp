#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"
#include "zune_process_resolver.h"

#include <atomic>

#if CERF_DEV_MODE

namespace {

/* Post-t+18 hard wedge: device.exe spins at PC 0x03F90850 (lr=0, thread
   top-level). Dump its instruction bytes + caller + registers to byte-match
   the owning slot-1 DLL and reveal what the loop polls/waits on. */
class ZuneKeelGuiWedgeAttribution : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            static std::atomic<int> fired{0};
            tm.OnPcFiltered(0x03F90850u,
                            zune_resolver::PidPredicateForName("device.exe"),
                            [](const TraceContext& c) {
                if (fired.fetch_add(1, std::memory_order_relaxed) != 0) return;
                const uint32_t win = 0x03F90830u;
                uint32_t w[24];
                for (int i = 0; i < 24; ++i)
                    w[i] = c.ReadVa32(win + i * 4u).value_or(0xDEADDEADu);
                LOG(Trace, "[GUI-WEDGE] PC=0x%08X LR=0x%08X procid=0x%08X "
                           "cpsr=0x%08X SP=0x%08X\n",
                    c.pc, c.regs[14],
                    c.emu.Get<ArmMmu>().State()->process_id, c.cpsr, c.regs[13]);
                for (int i = 0; i < 24; i += 6)
                    LOG(Trace, "[GUI-WEDGE] @0x%08X: %08X %08X %08X %08X %08X %08X\n",
                        win + i * 4u, w[i], w[i+1], w[i+2], w[i+3], w[i+4], w[i+5]);
                LOG(Trace, "[GUI-WEDGE] R0=%08X R1=%08X R2=%08X R3=%08X R4=%08X "
                           "R5=%08X R6=%08X R7=%08X R8=%08X R9=%08X R10=%08X "
                           "R11=%08X R12=%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[4],
                    c.regs[5], c.regs[6], c.regs[7], c.regs[8], c.regs[9],
                    c.regs[10], c.regs[11], c.regs[12]);
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelGuiWedgeAttribution);

#endif  /* CERF_DEV_MODE */
