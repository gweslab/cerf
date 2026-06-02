#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#include <atomic>
#include <cstdint>
#include <memory>

#if CERF_DEV_MODE

namespace {

/* ddraw_ipu_sdc.dll display-power path. Names which caller drove the t+18
   SDC_EN 1->0 (power-set D4 vs DrvDisableSurface) + the upstream PM caller. */
class ZuneKeelDisplayPowerTrace : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            const auto any = [](const TraceContext&) -> bool { return true; };

            /* SDC-OFF entry. LR disambiguates the caller: 0x318F2Bx is the
               in-body return after the IPU_CONF RMW; the entry LR is either
               ~0x318BF4C (DrvDisableSurface) or ~0x318E770 (PowerSet a2=4). */
            auto c1 = std::make_shared<std::atomic<uint32_t>>(0);
            tm.OnPcFiltered(0x318F224u, any, [c1](const TraceContext& c) {
                if (c1->fetch_add(1) >= 8) return;
                LOG(Trace, "[DISP-PWR] SDC-OFF sub_318F224 lr=0x%08X pid=0x%08X\n",
                    c.regs[14], c.emu.Get<ArmMmu>().State()->process_id);
            });

            /* IOCTL_POWER_SET handler. a2 (R1) = requested device power state
               (0..3 = on/Dx, 4 = D4/off). LR = the Power Manager call site. */
            auto c2 = std::make_shared<std::atomic<uint32_t>>(0);
            tm.OnPcFiltered(0x318E6DCu, any, [c2](const TraceContext& c) {
                if (c2->fetch_add(1) >= 16) return;
                LOG(Trace, "[DISP-PWR] SetPowerState(sub_318E6DC) state=%u "
                           "ctx=0x%08X lr=0x%08X pid=0x%08X\n",
                    c.regs[1], c.regs[0], c.regs[14],
                    c.emu.Get<ArmMmu>().State()->process_id);
            });

            /* DrvDisableSurface. */
            auto c3 = std::make_shared<std::atomic<uint32_t>>(0);
            tm.OnPcFiltered(0x318BF38u, any, [c3](const TraceContext& c) {
                if (c3->fetch_add(1) >= 8) return;
                LOG(Trace, "[DISP-PWR] DrvDisableSurface(sub_318BF38) lr=0x%08X "
                           "pid=0x%08X\n",
                    c.regs[14], c.emu.Get<ArmMmu>().State()->process_id);
            });

            /* Re-enable path: sub_318E6DC a2<=3 calls sub_318F1B8 (SDC ON).
               If the display is ever told to power back on, this fires. */
            auto c4 = std::make_shared<std::atomic<uint32_t>>(0);
            tm.OnPcFiltered(0x318F1B8u, any, [c4](const TraceContext& c) {
                if (c4->fetch_add(1) >= 8) return;
                LOG(Trace, "[DISP-PWR] SDC-ON sub_318F1B8 lr=0x%08X pid=0x%08X\n",
                    c.regs[14], c.emu.Get<ArmMmu>().State()->process_id);
            });

            /* pmc_pm.dll PM exports (load-aligned: VA==IDA addr). Caller LR
               names the D0->D4 trigger: idle-timer vs SetSystemPowerState vs
               requirement release. */
            auto pmName = [](const TraceContext& c, uint32_t va, char* out, int n) {
                int q = 0;
                for (int k = 0; k < n - 1; ++k) {
                    auto w = c.ReadVa16(va + k * 2);
                    if (!w.has_value() || *w == 0) break;
                    out[q++] = (*w >= 0x20 && *w < 0x7F) ? (char)*w : '.';
                }
                out[q] = 0;
            };
            auto cs = std::make_shared<std::atomic<uint32_t>>(0);
            tm.OnPcFiltered(0x35B2B50u, any, [cs, pmName](const TraceContext& c) {
                if (cs->fetch_add(1) >= 24) return;
                char nm[40]; pmName(c, c.regs[0], nm, sizeof(nm));
                LOG(Trace, "[DISP-PWR] PmSetSystemPowerState('%s') flags=0x%08X "
                           "lr=0x%08X pid=0x%08X\n",
                    nm, c.regs[2], c.regs[14],
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
            auto cd = std::make_shared<std::atomic<uint32_t>>(0);
            tm.OnPcFiltered(0x35B2210u, any, [cd](const TraceContext& c) {
                if (cd->fetch_add(1) >= 40) return;
                LOG(Trace, "[DISP-PWR] PmSetDevicePower r0=0x%08X r1=0x%08X "
                           "r2=0x%08X lr=0x%08X pid=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14],
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
            auto cr = std::make_shared<std::atomic<uint32_t>>(0);
            tm.OnPcFiltered(0x35B3FF0u, any, [cr](const TraceContext& c) {
                if (cr->fetch_add(1) >= 24) return;
                LOG(Trace, "[DISP-PWR] PmReleasePowerRequirement r0=0x%08X "
                           "lr=0x%08X pid=0x%08X\n",
                    c.regs[0], c.regs[14],
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelDisplayPowerTrace);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
