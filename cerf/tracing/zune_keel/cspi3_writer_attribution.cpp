#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#include <atomic>

#if CERF_DEV_MODE

namespace {

/* The CSPI3 XCH writer fired at PC 0x03191820 (LR 0x03191170) — a shared
   slot-1 ROM driver DLL. Dump its bytes + caller to byte-match the owning DLL
   and identify the CSPI3 SS1 slave. Timing-dependent — may need a few runs. */
class ZuneKeelCspi3Attribution : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            DumpAt(tm, 0x03191820u, "writer");
            DumpAt(tm, 0x03191170u, "caller");
        });
    }

private:
    static void DumpAt(TraceManager& tm, uint32_t pc, const char* tag) {
        tm.OnPc(pc, [pc, tag](const TraceContext& c) {
            static std::atomic<int> fired{0};
            if (fired.fetch_add(1, std::memory_order_relaxed) != 0) return;
            const uint32_t win = pc & ~0x1Fu;
            uint32_t w[16];
            for (int i = 0; i < 16; ++i)
                w[i] = c.ReadVa32(win + i * 4u).value_or(0xDEADDEADu);
            LOG(Trace, "[CSPI3-ATTR] %s PC=0x%08X LR=0x%08X procid=0x%08X "
                       "contextidr=0x%08X\n",
                tag, c.pc, c.regs[14],
                c.emu.Get<ArmMmu>().State()->process_id,
                c.emu.Get<ArmMmu>().State()->contextidr);
            LOG(Trace, "[CSPI3-ATTR] %s bytes@0x%08X: %08X %08X %08X %08X "
                       "%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X "
                       "%08X %08X\n",
                tag, win, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
                w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]);
            LOG(Trace, "[CSPI3-ATTR] %s regs R0=%08X R1=%08X R2=%08X R3=%08X "
                       "R4=%08X R5=%08X R6=%08X R7=%08X R10=%08X R12=%08X\n",
                tag, c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[4],
                c.regs[5], c.regs[6], c.regs[7], c.regs[10], c.regs[12]);
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelCspi3Attribution);

#endif  /* CERF_DEV_MODE */
