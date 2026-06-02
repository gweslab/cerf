#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstring>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kCompositorL1Base = 0x808B8000u;

class TraceCe7L2PteWatch : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnRunLoopIter([prev_l1   = uint32_t{0xDEADBEEFu},
                              prev_l2_0 = uint32_t{0xDEADBEEFu},
                              prev_l2_13 = uint32_t{0xDEADBEEFu}]
                             (const TraceContext& c) mutable {
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint8_t* l1_host = mem.TryTranslate(kCompositorL1Base);
                if (!l1_host) return;
                uint32_t l1 = 0;
                std::memcpy(&l1, l1_host, 4);

                uint32_t l2_base_pa = 0;
                uint32_t l2_0  = 0;
                uint32_t l2_13 = 0;
                if ((l1 & 3u) == 1u) {
                    l2_base_pa = l1 & 0xFFFFFC00u;
                    if (uint8_t* h = mem.TryTranslate(l2_base_pa)) {
                        std::memcpy(&l2_0,  h,        4);
                        std::memcpy(&l2_13, h + 0x4C, 4);
                    }
                }

                if (l1 == prev_l1 && l2_0 == prev_l2_0 && l2_13 == prev_l2_13)
                    return;

                auto& mmu = c.emu.Get<ArmMmu>();
                LOG(Trace,
                    "[l2pte-watch] L1[0]@0x%08X 0x%08X -> 0x%08X  "
                    "L2[0]@0x%08X 0x%08X -> 0x%08X  "
                    "L2[0x13]@0x%08X 0x%08X -> 0x%08X  "
                    "ttbr0=0x%08X mode=0x%X pc=0x%08X\n",
                    kCompositorL1Base, prev_l1, l1,
                    l2_base_pa, prev_l2_0, l2_0,
                    l2_base_pa + 0x4Cu, prev_l2_13, l2_13,
                    mmu.State()->translation_table_base.word,
                    c.cpsr & 0x1Fu, c.pc);
                prev_l1    = l1;
                prev_l2_0  = l2_0;
                prev_l2_13 = l2_13;
            });
        });
    }
};
REGISTER_SERVICE(TraceCe7L2PteWatch);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
