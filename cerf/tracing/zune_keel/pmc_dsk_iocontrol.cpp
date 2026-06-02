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

/* DSK_IOControl@0x3053794 / IDE_IOControl@0x305393C: r1=IOCTL code, r2=pBufIn.
   For a read IOCTL pBufIn is an SG_REQ: [0]=start sector, [4]=sector count. */
void HookIoControl(TraceManager& tm, uint32_t ea, const char* tag) {
    tm.OnPc(ea, [tag](const TraceContext& c) {
        static std::atomic<uint32_t> n{0};
        const uint32_t i = n.fetch_add(1);
        if (i >= 60u && (i & 0xFu) != 0u) return;
        const uint32_t code = c.regs[1];
        const uint32_t pin  = c.regs[2];
        uint32_t start = 0, count = 0;
        if (pin) {
            auto s = c.ReadVa32(pin);
            auto n2 = c.ReadVa32(pin + 4u);
            start = s.value_or(0xFFFFFFFFu);
            count = n2.value_or(0xFFFFFFFFu);
        }
        LOG(Trace, "[PMC-IOC] %s #%u code=0x%08X pBufIn=0x%08X "
                   "sg.start=%u sg.count=%u pid=0x%08X lr=0x%08X\n",
            tag, i, code, pin, start, count,
            c.emu.Get<ArmMmu>().State()->process_id, c.regs[14]);
        /* On the MBR read (code 2, sector 0) dump the caller chain: scan the
           stack for code-range return addresses to find mspart's parse fn. */
        if (code == 2u && start == 0u) {
            char z[240]; int p = 0; int found = 0;
            for (uint32_t o = 0; o < 0x200u && p < 220; o += 4u) {
                auto w = c.ReadVa32(c.regs[13] + o);
                if (!w) continue;
                const uint32_t v = *w;
                if ((v >= 0x01000000u && v < 0x04000000u) ||
                    (v >= 0x80000000u && v < 0x90000000u)) {
                    p += snprintf(z + p, sizeof(z) - p, "[+%X]=0x%08X ", o, v);
                    if (++found >= 12) break;
                }
            }
            LOG(Trace, "[PMC-IOC]   MBR-read callers: %s\n", z);
        }
    });
}

class ZuneKeelPmcDskIoControl : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            HookIoControl(tm, 0x3053794u, "DSK");
            HookIoControl(tm, 0x305393Cu, "IDE");
        });
    }
};

REGISTER_SERVICE(ZuneKeelPmcDskIoControl);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
