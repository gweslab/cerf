#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#if CERF_DEV_MODE

namespace {

void ReadWStr(const TraceContext& c, uint32_t va, char* out, int cap) {
    int n = 0;
    for (; n < cap - 1; ++n) {
        auto wc = c.ReadVa16(va + n * 2u);
        if (!wc || *wc == 0) break;
        out[n] = (*wc < 0x80u) ? static_cast<char>(*wc) : '?';
    }
    out[n] = 0;
}

/* filesys.exe RunApps (sub_17EF8; runs at slot-0 image base, confirmed by the
   CreateProcessW LR=0x18658): 0x18654 = the CreateProcessW launch call (R0 =
   image name, freshly mapped by sub_18720), 0x186A4 = the
   WaitForMultipleObjects park when a Launch dependency is unsatisfied.
   Unfiltered on purpose: only filesys's RunApps runs this exact code path,
   and a stray alias is obvious (its R0 won't resolve to a real exe name). */
class Falcon4220RunAppsDiag : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kFalcon4220BundleCrc32, [&] {
            /* 0x181EC = the registry-parse wcscpy(hMem, name): R1 = the name
               in a stack buffer (readable), [SP+0x13C] = the Launch order.
               Builds the full order->name map so the stuck order-20 is named. */
            tm.OnPc(0x181ECu, [](const TraceContext& c) {
                char name[96]; ReadWStr(c, c.regs[1], name, 96);
                auto order = c.ReadVa32(c.regs[13] + 0x13Cu);
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                LOG(Trace, "[FALCON] RunApps PARSE order=%u name='%s' slot=%u\n",
                    order.value_or(0xFFFFFFFFu), name, slot);
            });
            tm.OnPc(0x18654u, [](const TraceContext& c) {
                char name[96]; ReadWStr(c, c.regs[0], name, 96);
                auto w0 = c.ReadVa32(c.regs[0]);
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                LOG(Trace, "[FALCON] RunApps LAUNCH app='%s' R0=0x%08X "
                           "[R0]=0x%08X slot=%u\n",
                    name, c.regs[0], w0.value_or(0xFFFFFFFFu), slot);
            });
            /* coredll!SignalStarted (0x3F8DCA4, shared XIP): each init app calls
               it with its launch id (R0) to satisfy filesys RunApps's Depend
               wait. If device.exe (slot 3) never fires this, it is blocked before
               signaling ready and RunApps stays parked at order 20. */
            tm.OnPc(0x3F8DCA4u, [](const TraceContext& c) {
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                LOG(Trace, "[FALCON] SignalStarted id=%u slot=%u\n",
                    c.regs[0], slot);
            });
            /* coredll!ActivateDeviceEx return site (0x3F82D20, the POP after the
               PSL BX R4 trap to the kernel devmgr where the driver Init runs).
               Pairs with the entry hook: an entry with no matching return = the
               driver whose Init blocks device.exe before SignalStarted. */
            tm.OnPc(0x3F82D20u, [](const TraceContext& c) {
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                LOG(Trace, "[FALCON] ActivateDeviceEx RETURN h=0x%08X slot=%u\n",
                    c.regs[0], slot);
            });
            tm.OnPc(0x186A4u, [](const TraceContext& c) {
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                LOG(Trace, "[FALCON] RunApps PARK slot=%u (LR=0x%08X)\n",
                    slot, c.regs[14]);
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(Falcon4220RunAppsDiag);

#endif  /* CERF_DEV_MODE */
