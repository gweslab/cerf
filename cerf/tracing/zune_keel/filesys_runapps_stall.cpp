#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"
#include "zune_process_resolver.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* Names the RunApps stall: filesys sub_173D4(m) blocks entry m until every
   Depend order's started-flag is set. hMem table ptr is at filesys VA 0x3CB4C,
   count at 0x3CB40, 592-byte stride, started-flag at +4, name at +72. */
class ZuneKeelRunAppsStall : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            tm.OnPcFiltered(0x173D4u,
                            zune_resolver::PidPredicateForName("filesys.exe"),
                            [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t pid = c.emu.Get<ArmMmu>().State()->process_id;
                auto fold = [pid](uint32_t va) {
                    return ((va & 0xFE000000u) == 0u) ? (va | pid) : va;
                };
                auto rd32 = [&](uint32_t va) { return c.ReadVa32(fold(va)); };
                auto rd16 = [&](uint32_t va) { return c.ReadVa16(fold(va)); };
                auto rdname = [&](char* out, uint32_t hmem, uint32_t m) {
                    int k = 0;
                    for (; k < 19; ++k) {
                        auto w = rd16(hmem + 592u * m + 72u + k * 2u);
                        if (!w || !*w) break;
                        out[k] = (char)(*w & 0x7F);
                    }
                    out[k] = 0;
                };

                const uint32_t a1 = c.regs[0];
                auto base = rd32(0x3CB4Cu);
                auto cnt  = rd32(0x3CB40u);
                const uint32_t fired = n.fetch_add(1);
                if (fired < 12) {
                    char an[20] = {0};
                    if (base) rdname(an, *base, a1);
                    LOG(Trace, "[RUNAPPS-CHK] #%u a1=%u hmem=%s count=%d '%s'\n",
                        fired, a1, base ? "ok" : "NIL",
                        cnt ? (int)*cnt : -1, an);
                }
                if (!base || !cnt) return;
                const uint32_t hmem = *base, count = *cnt;
                if (count > 32u) return;

                /* Walk entry a1's dependency-order list; find the first dep
                   whose owning entry has started-flag (off+4) == 0. */
                for (uint32_t d = 0; d < 16u; ++d) {
                    auto dep = rd16(hmem + 592u * a1 + 8u + d * 2u);
                    if (!dep || *dep == 0) return;          /* all deps met */
                    for (uint32_t j = 0; j < count; ++j) {
                        auto ord = rd32(hmem + 592u * j);
                        if (!ord || *ord != *dep) continue;
                        auto flag = rd32(hmem + 592u * j + 4u);
                        if (flag && *flag) break;           /* dep j started */
                        /* Blocked: entry a1 waits on entry j (not started). */
                        const uint32_t i = n.fetch_add(1);
                        if (i >= 8 && (i & 0xFFu) != 0) return;
                        char an[20] = {0}, jn[20] = {0};
                        rdname(an, hmem, a1);
                        rdname(jn, hmem, j);
                        LOG(Trace, "[RUNAPPS-STALL] #%u entry[%u] '%s' "
                                   "blocked on Depend=%u entry[%u] '%s' "
                                   "(not started)\n",
                            i, a1, an, *dep, j, jn);
                        return;
                    }
                }
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelRunAppsStall);

#endif  /* CERF_DEV_MODE */
