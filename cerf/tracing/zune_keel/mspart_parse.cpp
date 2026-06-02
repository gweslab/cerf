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

/* mspart.dll @ runtime base 0x3ED0000 (== IDA base). sub_3ED3600 = MBR parser
   (r0=store, r2=MBR buf, *(store+40)=disk sectors from GETINFO); sub_3ED3A04
   runs only when the parse returned 0 (PD_OpenStore success path). */
class ZuneKeelMspartParse : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            /* Unfiltered: discovering WHICH process runs mspart's PD_OpenStore
               (device.exe and filesys.exe filters both produced no fires), so
               no process predicate is yet known — each handler logs pid. */
            tm.OnPc(0x3ED1178u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 6u) return;
                LOG(Trace, "[MSPART] PD_OpenStore entry pid=0x%08X lr=0x%08X\n",
                    c.emu.Get<ArmMmu>().State()->process_id, c.regs[14]);
            });
            tm.OnPc(0x3ED3600u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 6u) return;
                const uint32_t store = c.regs[0];
                const uint32_t mbr   = c.regs[2];
                auto dsk = c.ReadVa32(store + 40u);
                LOG(Trace, "[MSPART] parse entry pid=0x%08X store=0x%08X a4=%u "
                           "disk_sectors=%d\n",
                    c.emu.Get<ArmMmu>().State()->process_id, store, c.regs[3],
                    dsk.has_value() ? (int)*dsk : -1);
                for (uint32_t e = 0; e < 4u; ++e) {
                    const uint32_t off = mbr + 446u + e * 16u;
                    auto type  = c.ReadVa8(off + 4u);
                    auto start = c.ReadVa32(off + 8u);
                    auto nsec  = c.ReadVa32(off + 12u);
                    LOG(Trace, "[MSPART]   part%u type=0x%02X start=%u nsec=%u\n",
                        e, type.value_or(0xFFu), start.value_or(0u),
                        nsec.value_or(0u));
                }
            });
            tm.OnPc(0x3ED3A04u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 4u) return;
                auto cnt = c.ReadVa32(c.regs[0] + 20u);
                LOG(Trace, "[MSPART] *** ENUM SUCCESS *** pid=0x%08X part_count=%d\n",
                    c.emu.Get<ArmMmu>().State()->process_id,
                    cnt.has_value() ? (int)*cnt : -1);
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelMspartParse);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
