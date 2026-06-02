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

/* Resolve the handle services.exe/device.exe park on to its object + name, using
   the kernel handle table: objHdr = (handle & 0x1FFFFFFC) + [0xFFFFC89C], body =
   objHdr[6] (sub_8820F0E8). Dump body bytes so the name string is visible. */
void DumpHandle(const TraceContext& c, const char* who, uint32_t handle) {
    auto base = c.ReadVa32(0xFFFFC89Cu);
    if (!base) { LOG(Trace, "[HRES] %s handle=0x%08X base UNREAD\n", who, handle); return; }
    const uint32_t hdr = (handle & 0x1FFFFFFCu) + *base;
    auto body = c.ReadVa32(hdr + 24u);              /* objHdr[6] */
    LOG(Trace, "[HRES] %s handle=0x%08X hdr=0x%08X body=0x%08X\n",
        who, handle, hdr, body ? *body : 0u);
    if (!body) return;
    /* Dump 64 bytes of the object body; named events/mutexes carry the wide
       name inline or via a pointer near the head. */
    char line[160]; int p = 0;
    for (uint32_t o = 0; o < 64u; o += 4u) {
        auto w = c.ReadVa32(*body + o);
        p += snprintf(line + p, sizeof(line) - p, "%08X ", w ? *w : 0u);
        if (o == 28u) { LOG(Trace, "[HRES]   body[+0..1C]: %s\n", line); p = 0; }
    }
    LOG(Trace, "[HRES]   body[+20..3C]: %s\n", line);
    /* Try a wide-string name at the body head and at +0x20. */
    for (uint32_t off : {0u, 0x20u, 0x24u}) {
        char nm[40]; int q = 0;
        for (int k = 0; k < 18 && q < 36; ++k) {
            auto wc = c.ReadVa16(*body + off + k * 2u);
            if (!wc || *wc == 0) break;
            nm[q++] = (*wc >= 0x20 && *wc < 0x7F) ? (char)*wc : '.';
        }
        nm[q] = 0;
        if (q > 2) LOG(Trace, "[HRES]   name@+%X='%s'\n", off, nm);
    }
}

class ZuneKeelParkedHandleResolver : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            /* services.exe WaitForMultipleObjects(count=r0, handles=r1, wait=r2,
               timeout=r3) INFINITE — resolve hnd0=*(r1) (the parked handle shows
               here, e.g. 0x4BD5D28A). OnPcFiltered to coexist with SVCWAIT. */
            /* gwes.exe (0x08000000) parks before signaling GweApiSetReady — walk
               its wait stack for ddraw_ipu_sdc-range (~0x0310_xxxx) callers. */
            auto gwes_inf = [](const TraceContext& c) -> bool {
                return c.emu.Get<ArmMmu>().State()->process_id == 0x08000000u
                    && c.regs[3] == 0xFFFFFFFFu;
            };
            tm.OnPcFiltered(0x8821A5F8u, gwes_inf, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 30u && (i & 0x7Fu) != 0) return;
                char z[220]; int p = 0; int found = 0;
                for (uint32_t o = 0; o < 0x180u && p < 200; o += 4u) {
                    auto w = c.ReadVa32(c.regs[13] + o);
                    if (!w) continue;
                    if (*w >= 0x03000000u && *w < 0x03300000u) {
                        p += snprintf(z + p, sizeof(z) - p, "[+%X]=0x%08X ", o, *w);
                        if (++found >= 10) break;
                    }
                }
                auto h = c.ReadVa32(c.regs[1]);
                if (found) LOG(Trace, "[GWES-WAIT] hnd0=0x%08X drv-callers: %s\n",
                                  h ? *h : 0u, z);
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelParkedHandleResolver);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
