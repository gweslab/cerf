#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <array>
#include <cstdint>
#include <cstring>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kCompositorL1Pa = 0x8087C000u;

class TraceCe7CompositorL1Watch : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnRunLoopIter([this, snapshot = std::array<uint32_t, 16>{}]
                             (const TraceContext& c) mutable {
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint8_t* host = mem.TryTranslate(kCompositorL1Pa);
                if (!host) {
                    if (!ever_unmapped_logged_) {
                        LOG(Trace, "[l1watch] PA 0x%08X NOT mapped (TryTranslate=null)\n",
                            kCompositorL1Pa);
                        ever_unmapped_logged_ = true;
                    }
                    return;
                }

                /* Snapshot first 16 sections (4 bytes each = 64 bytes) and
                   diff vs prior. Any change → dump full snapshot + current
                   TTBR0 + FCSE PID + active CPSR mode. */
                uint32_t cur[16];
                std::memcpy(cur, host, sizeof(cur));
                if (std::memcmp(cur, snapshot.data(), sizeof(cur)) == 0) return;

                auto& mmu  = c.emu.Get<ArmMmu>();
                const uint32_t ttbr0 = mmu.State()->translation_table_base.word;
                const uint32_t pid   = mmu.State()->process_id;

                LOG(Trace,
                    "[l1watch] PA 0x%08X entries[0..15] changed.  "
                    "live TTBR0=0x%08X pid=0x%08X cpsr=0x%08X\n",
                    kCompositorL1Pa, ttbr0, pid, c.cpsr);
                for (int i = 0; i < 16; ++i) {
                    if (cur[i] != snapshot[i]) {
                        LOG(Trace,
                            "[l1watch]   [%02d] @PA 0x%08X : 0x%08X -> 0x%08X\n",
                            i, kCompositorL1Pa + i * 4u,
                            snapshot[i], cur[i]);
                    }
                }
                std::memcpy(snapshot.data(), cur, sizeof(cur));
            });
        });
    }

private:
    bool ever_unmapped_logged_ = false;
};

REGISTER_SERVICE(TraceCe7CompositorL1Watch);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
