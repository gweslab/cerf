#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "ce7_bundle.h"

#include <cstdint>
#include <unordered_map>

#if CERF_DEV_MODE

namespace {

class TraceCe7PslCaller : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(0xEFF6B824u,
                [counts = std::unordered_map<uint32_t, uint32_t>{},
                 fires = uint32_t{0}]
                (const TraceContext& c) mutable {
                ++fires;
                ++counts[c.regs[14] & ~0x3Fu];
                if ((fires % 20000u) != 0u) return;
                const uint32_t asid =
                    c.emu.Get<ArmMmu>().State()->contextidr & 0xFFu;
                LOG(Trace, "[psl36] fires=%u LR=0x%08X R0=0x%08X R1=0x%08X "
                    "R2=0x%08X SP=0x%08X asid=0x%02X\n",
                    fires, c.regs[14], c.regs[0], c.regs[1], c.regs[2],
                    c.regs[13], asid);
                uint32_t top_lr[6] = {0}; uint32_t top_ct[6] = {0};
                for (const auto& kv : counts) {
                    uint32_t lr = kv.first, ct = kv.second;
                    for (int i = 0; i < 6; ++i) {
                        if (ct > top_ct[i]) {
                            for (int j = 5; j > i; --j) { top_ct[j] = top_ct[j-1]; top_lr[j] = top_lr[j-1]; }
                            top_ct[i] = ct; top_lr[i] = lr; break;
                        }
                    }
                }
                for (int i = 0; i < 6 && top_ct[i]; ++i)
                    LOG(Trace, "[psl36]   caller=0x%08X count=%u\n", top_lr[i], top_ct[i]);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7PslCaller);

}  /* namespace */

#endif
