#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"

#include <atomic>

#if CERF_DEV_MODE

namespace {

class ZuneKeelAtaProbeAttribution : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            static std::atomic<bool> dumped{false};
            /* Unfiltered by necessity — attributing the unknown module, so no
               process predicate exists. Drop the r3==0xD8 gate and the dump
               fires for any process aliasing this VA, giving wrong attribution
               bytes; 0xD8 is the rejection's ATA-read register state. */
            tm.OnPc(0x03E925B0u, [](const TraceContext& c) {
                if (c.regs[3] != 0xD8u) return;
                if (dumped.exchange(true)) return;  /* one-shot */
                LOG(Trace, "[ATA-ATTR] fired pc=0x%08X lr=0x%08X r0=0x%08X "
                           "r1=0x%08X r2=0x%08X r3=0x%08X\n",
                    c.pc, c.regs[14], c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
                for (int32_t d = -0x10; d <= 0x10; d += 4) {
                    auto w = c.ReadVa32(c.pc + d);
                    LOG(Trace, "[ATA-ATTR]   [pc%+d] = 0x%08X\n",
                        d, w.has_value() ? *w : 0xDEADBEEFu);
                }
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelAtaProbeAttribution);

#endif  /* CERF_DEV_MODE */
