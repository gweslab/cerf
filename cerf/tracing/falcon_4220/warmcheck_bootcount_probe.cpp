#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#include <optional>

#if CERF_DEV_MODE

namespace {

/* Hunts the runtime writer of HKLM\Comm\BootCount=1 (absent from the hive, yet
   UnitGetBootType reads =1): RegSetValueExW is UNFILTERED across all slots since
   the writer precedes WarmCheck (slot 4). Read confirmed via adjacent RegCloseKey
   (result buffer TLB-hot, name string not; AAPCS lpData = arg 5, [SP+0]). */
uint32_t Slot(const TraceContext& c) {
    return c.emu.Get<ArmMmu>().State()->process_id >> 25;
}

void WideToAscii(const TraceContext& c, uint32_t va, char* out, int cap) {
    int n = 0;
    for (; n < cap - 1; ++n) {
        auto wc = c.ReadVa16(va + n * 2u);
        if (!wc || *wc == 0) break;
        out[n] = (*wc < 0x80u) ? static_cast<char>(*wc) : '?';
    }
    out[n] = 0;
}

class FalconWarmCheckBootCountProbe : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kFalcon4220BundleCrc32, [this, &tm] {
            TracePredicate warmcheck = [](const TraceContext& c) {
                return Slot(c) == 4u;
            };
            tm.OnPcFiltered(0x3F8AF38u, warmcheck, [this](const TraceContext& c) {
                q_lpdata_ = c.ReadVa32(c.regs[13]).value_or(0u);   /* lpData = [SP+0] */
                q_lr_     = c.regs[14];
            });
            tm.OnPcFiltered(0x3F8ABF8u, warmcheck, [this](const TraceContext& c) {
                if (q_lpdata_ == 0u) return;
                auto v = c.ReadVa32(q_lpdata_);
                LOG(Trace, "[FALCON-BC] read result=%d caller_LR=0x%08X\n",
                    v ? static_cast<int>(*v) : -1, q_lr_);
                q_lpdata_ = 0u;
            });
            tm.OnPc(0x3F8AFD8u, [](const TraceContext& c) {   /* RegSetValueExW, all slots */
                auto lp = c.ReadVa32(c.regs[13]);             /* lpData = [SP+0] */
                auto v  = lp ? c.ReadVa32(*lp) : std::nullopt;
                if (!v || *v != 1u) return;
                char name[32]; WideToAscii(c, c.regs[1], name, 32);
                LOG(Trace, "[FALCON-BC] SetValue=1 name='%s' slot=%u LR=0x%08X "
                    "hKey=0x%08X\n", name, Slot(c), c.regs[14], c.regs[0]);
            });
        });
    }

private:
    uint32_t q_lpdata_ = 0u;
    uint32_t q_lr_     = 0u;
};

}  /* namespace */

REGISTER_SERVICE(FalconWarmCheckBootCountProbe);

#endif  /* CERF_DEV_MODE */
