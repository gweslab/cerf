#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>
#include <unordered_set>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcCdWaitForSingleObj = 0x40029FE8u;
constexpr uint32_t kVaPCurThd            = 0xFFFFC824u;

class TraceCe7UnknownDllProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto user_proc_only = [](const TraceContext& c) -> bool {
                return (c.emu.Get<ArmMmu>()
                            .State()
                            ->translation_table_base.word
                        & 0xFFFFC000u) != 0u;
            };

            tm.OnPcFiltered(kPcCdWaitForSingleObj, user_proc_only,
                [](const TraceContext& c) {
                    const uint32_t lr = c.regs[14];
                    if ((lr & 0xFFF00000u) != 0x40700000u) return;

                    static std::unordered_set<uint32_t> dumped_sites;
                    if (dumped_sites.size() >= 3u) return;
                    if (!dumped_sites.insert(lr & ~0xFFu).second) return;

                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t ttbr =
                        c.emu.Get<ArmMmu>()
                            .State()
                            ->translation_table_base.word
                        & 0xFFFFC000u;

                    LOG(Trace,
                        "[dll-id] xxx_WaitForSingleObject called from "
                        "unknown DLL site #%zu  LR=0x%08X\n",
                        dumped_sites.size(), lr);
                    LOG(Trace,
                        "[dll-id]   pCurThd=0x%08X TTBR0=0x%08X "
                        "hHandle=0x%08X dwMs=0x%08X CPSR=0x%08X\n",
                        pcurthd, ttbr, c.regs[0], c.regs[1], c.cpsr);

                    const uint32_t base = (lr - 0x200u) & ~0xFu;
                    for (uint32_t off = 0; off < 1024u; off += 16u) {
                        const uint32_t w0 =
                            c.ReadVa32(base + off +  0u).value_or(0xDEADBEEFu);
                        const uint32_t w1 =
                            c.ReadVa32(base + off +  4u).value_or(0xDEADBEEFu);
                        const uint32_t w2 =
                            c.ReadVa32(base + off +  8u).value_or(0xDEADBEEFu);
                        const uint32_t w3 =
                            c.ReadVa32(base + off + 12u).value_or(0xDEADBEEFu);
                        LOG(Trace,
                            "[dll-id]   0x%08X: %08X %08X %08X %08X\n",
                            base + off, w0, w1, w2, w3);
                    }
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7UnknownDllProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
