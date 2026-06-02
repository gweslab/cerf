#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>
#include <cstring>
#include <unordered_set>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcCdWaitForSingleObj = 0x40029FE8u;
constexpr uint32_t kVaPCurThd            = 0xFFFFC824u;

struct WalkResult {
    uint32_t l1_pa;
    uint32_t l1_val;
    uint32_t l2_pa;
    uint32_t l2_val;
    uint32_t pa;
    uint32_t bytes;
    bool     bytes_ok;
    bool     used_ttbr1;
};

WalkResult Walk(const TraceContext& c, uint32_t va) {
    WalkResult r{};
    auto& mmu = c.emu.Get<ArmMmu>();
    auto& mem = c.emu.Get<EmulatedMemory>();
    const auto& m = *mmu.State();

    const uint32_t ttbcr_n = m.ttbcr & 7u;
    const bool use_ttbr1 = ttbcr_n != 0u &&
                          (va >> (32u - ttbcr_n)) != 0u;
    r.used_ttbr1 = use_ttbr1;

    const uint32_t ttbr0_mask = ttbcr_n
        ? ~((1u << (14u - ttbcr_n)) - 1u)
        : 0xFFFFC000u;
    const uint32_t l1_base = use_ttbr1
        ? (m.ttbr1 & 0xFFFFC000u)
        : (m.translation_table_base.word & ttbr0_mask);

    r.l1_pa = l1_base + ((va >> 20) << 2);
    uint8_t* l1h = mem.TryTranslate(r.l1_pa);
    if (!l1h) {
        r.l1_val = 0xDEADDEAD;
        return r;
    }
    std::memcpy(&r.l1_val, l1h, 4);
    const uint32_t type = r.l1_val & 3u;
    if (type == 2u) {
        r.pa = (r.l1_val & 0xFFF00000u) | (va & 0x000FFFFFu);
    } else if (type == 1u) {
        r.l2_pa = (r.l1_val & 0xFFFFFC00u) | (((va >> 12) & 0xFFu) << 2);
        uint8_t* l2h = mem.TryTranslate(r.l2_pa);
        if (l2h) {
            std::memcpy(&r.l2_val, l2h, 4);
            const uint32_t l2t = r.l2_val & 3u;
            if (l2t == 2u || l2t == 3u) {
                r.pa = (r.l2_val & 0xFFFFF000u) | (va & 0xFFFu);
            } else if (l2t == 1u) {
                r.pa = (r.l2_val & 0xFFFF0000u) | (va & 0xFFFFu);
            }
        }
    }
    if (r.pa) {
        uint8_t* h = mem.TryTranslate(r.pa);
        if (h) {
            std::memcpy(&r.bytes, h, 4);
            r.bytes_ok = true;
        }
    }
    return r;
}

class TraceCe7DllIdPaWalk : public Service {
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
                    if (dumped_sites.size() >= 5u) return;
                    if (!dumped_sites.insert(lr & ~0xFFu).second) return;

                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const auto& m = *mmu.State();
                    const uint32_t ttbr0 = m.translation_table_base.word;
                    const uint32_t ttbr1 = m.ttbr1;
                    const uint32_t ttbcr = m.ttbcr;

                    LOG(Trace,
                        "[dll-id3] site #%zu LR=0x%08X pCurThd=0x%08X "
                        "hHandle=0x%08X dwMs=0x%08X "
                        "TTBR0=0x%08X TTBR1=0x%08X TTBCR=0x%08X (N=%u)\n",
                        dumped_sites.size(), lr, pcurthd,
                        c.regs[0], c.regs[1],
                        ttbr0, ttbr1, ttbcr, ttbcr & 7u);

                    /* Walk the LR site for diagnostic. */
                    WalkResult wlr = Walk(c, lr);
                    LOG(Trace,
                        "[dll-id3]   walk(LR=0x%08X): used_ttbr1=%d "
                        "L1@0x%08X=0x%08X L2@0x%08X=0x%08X PA=0x%08X "
                        "bytes=0x%08X ok=%d\n",
                        lr, wlr.used_ttbr1,
                        wlr.l1_pa, wlr.l1_val,
                        wlr.l2_pa, wlr.l2_val,
                        wlr.pa, wlr.bytes, wlr.bytes_ok);

                    /* Also try walking softkb.dll's known-good VA
                       (0x40777570) — if that walks ok, the issue is
                       specific to the unknown DLL's page range. */
                    if (lr != 0x40777C74u) {
                        WalkResult sk = Walk(c, 0x40777570u);
                        LOG(Trace,
                            "[dll-id3]   walk(softkb=0x40777570): used_ttbr1=%d "
                            "L1@0x%08X=0x%08X L2@0x%08X=0x%08X PA=0x%08X "
                            "bytes=0x%08X ok=%d\n",
                            sk.used_ttbr1,
                            sk.l1_pa, sk.l1_val,
                            sk.l2_pa, sk.l2_val,
                            sk.pa, sk.bytes, sk.bytes_ok);
                    }

                    /* Dump a small window via Walk(). */
                    const uint32_t base = (lr - 0x40u) & ~0xFu;
                    for (uint32_t off = 0; off < 256u; off += 16u) {
                        const auto a = Walk(c, base + off +  0u);
                        const auto b = Walk(c, base + off +  4u);
                        const auto c2 = Walk(c, base + off +  8u);
                        const auto d = Walk(c, base + off + 12u);
                        LOG(Trace,
                            "[dll-id3]   0x%08X: %08X %08X %08X %08X "
                            "(L1@%08X=%08X)\n",
                            base + off,
                            a.bytes_ok ? a.bytes : 0xDEAD0001u,
                            b.bytes_ok ? b.bytes : 0xDEAD0001u,
                            c2.bytes_ok ? c2.bytes : 0xDEAD0001u,
                            d.bytes_ok ? d.bytes : 0xDEAD0001u,
                            a.l1_pa, a.l1_val);
                    }
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7DllIdPaWalk);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
