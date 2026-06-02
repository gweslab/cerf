#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"

#if CERF_DEV_MODE

#include <cstdint>

namespace {

/* iPAQ fault-loop probe: the demand-pager (sub_80072468) writes L2 entries
   through the page-table self-map window. Capture the store VA + value at both
   L2-store sites and read CERF's current value at that VA, to test whether the
   self-map VA resolves to the same physical L2 table CERF's walk reads. */
class IpaqL2WriteProbe : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kIpaq3650BundleCrc32, [this, &tm] {
            /* enter (R0 = folded faulting VA): count by L2 sub-page index. */
            tm.OnPc(0x80072468u, [this](const TraceContext& c) {
                Bump(ent_, (c.regs[0] >> 12) & 0xFFu);
            });
            /* L2-entry stores: R0 = self-map VA, low 10 bits/4 = sub-page index. */
            tm.OnPc(0x80072554u, [this](const TraceContext& c) {
                Bump(wr_, ((c.regs[0] - 0xFFFD4000u) & 0x3FFu) >> 2);
            });
            tm.OnPc(0x800725DCu, [this](const TraceContext& c) {
                Bump(wr_, ((c.regs[0] - 0xFFFD4000u) & 0x3FFu) >> 2);
            });
            /* fail-return (page not in software PT). */
            tm.OnPc(0x8007261Cu, [this](const TraceContext&) { ++fail_; Dump(); });
        });
    }

private:
    struct Counts { uint32_t ad = 0, ee = 0, other = 0; };

    void Bump(Counts& c, uint32_t idx) {
        if (idx == 0xADu) ++c.ad;
        else if (idx == 0xEEu) ++c.ee;
        else ++c.other;
        Dump();
    }

    void Dump() {
        if ((++total_ % 4000000u) != 0u) return;
        LOG(Periph, "[PGMAP] enter[AD=%u EE=%u oth=%u] write[AD=%u EE=%u oth=%u] fail=%u\n",
            ent_.ad, ent_.ee, ent_.other, wr_.ad, wr_.ee, wr_.other, fail_);
    }

    Counts ent_, wr_;
    uint32_t fail_ = 0;
    uint32_t total_ = 0;
};

REGISTER_SERVICE(IpaqL2WriteProbe);

}  // namespace

#endif  // CERF_DEV_MODE
