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

/* sub_8821A5F8 = kernel WaitForMultipleObjects (R0=count, R1=handles,
   R3=timeout). Logs each process's INFINITE wait + caller LR; the
   services.exe (pid 0x0A000000) wait whose LR is in ZSERV is the blocker. */
class ZuneKeelZServWaitAttr : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            tm.OnPc(0x8821A5F8u, [](const TraceContext& c) {
                const uint32_t pid = c.emu.Get<ArmMmu>().State()->process_id;
                if (pid != 0x0A000000u) return;           /* services.exe only */
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 24 && (i & 0x1Fu) != 0) return;
                auto h = c.ReadVa32(c.regs[1]);
                LOG(Trace, "[SVCWAIT] #%u count=%u timeout=0x%08X hnd0=0x%08X "
                           "lr=0x%08X\n",
                    i, c.regs[0], c.regs[3],
                    h.has_value() ? *h : 0xDEADBEEFu, c.regs[14]);
            });

            /* 0x8821A9B8 = coredll/kernel WaitForSingleObject wrapper. Its LR
               in services.exe context is ZSERV's own call site — reveals
               ZSERV's runtime VA (extracted-PE RVA does not map). */
            tm.OnPc(0x8821A9B8u, [](const TraceContext& c) {
                const uint32_t pid = c.emu.Get<ArmMmu>().State()->process_id;
                if (pid != 0x0A000000u) return;
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 24 && (i & 0x1Fu) != 0) return;
                LOG(Trace, "[WFSO-CALLER] #%u hnd=0x%08X timeout=0x%08X "
                           "callerLR=0x%08X\n",
                    i, c.regs[0], c.regs[1], c.regs[14]);
            });

            /* ZSERV: 0x3241B3C = ZSV_Init entry; sub_3246B0C does
               OpenEvent(GweApiSetReady) @0x3246B28, WFSO(-1) @0x3246B38,
               0x3246B3C reached only after WFSO returns. Log pid (no filter) to
               find which process runs zserv + confirm bytes are PUSH{R4,LR}. */
            auto any = [](const TraceContext&) -> bool { return true; };
            tm.OnPcFiltered(0x3241B3Cu, any, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 4) return;
                auto b = c.ReadVa32(c.pc);
                LOG(Trace, "[ZSV-GWE] ZSV_Init entry pid=0x%08X lr=0x%08X "
                           "bytes=0x%08X\n", c.emu.Get<ArmMmu>().State()->process_id,
                    c.regs[14], b.has_value() ? *b : 0u);
            });
            tm.OnPcFiltered(0x3246B0Cu, any, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 4) return;
                auto b = c.ReadVa32(c.pc);
                LOG(Trace, "[ZSV-GWE] enter sub_3246B0C pid=0x%08X lr=0x%08X "
                           "bytes=0x%08X\n", c.emu.Get<ArmMmu>().State()->process_id,
                    c.regs[14], b.has_value() ? *b : 0u);
            });
            tm.OnPcFiltered(0x3246B28u, any, [](const TraceContext& c) {
                LOG(Trace, "[ZSV-GWE] OpenEvent(GweApiSetReady) handle=0x%08X "
                           "pid=0x%08X\n", c.regs[0],
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
            tm.OnPcFiltered(0x3246B3Cu, any, [](const TraceContext&) {
                LOG(Trace, "[ZSV-GWE] *** WFSO RETURNED — GweApiSetReady SIGNALED "
                           "*** (gwes completed init)\n");
            });

            /* ZSV_Init linear chain before sub_3246B0C. Last step to fire +
               next silent = the blocker. (pid-logged, first hit only.) */
            struct Step { uint32_t ea; const char* name; };
            static const Step kSteps[] = {
                {0x3241E84u, "sub_3241E84"}, {0x324284Cu, "sub_324284C"},
                {0x324329Cu, "sub_324329C"}, {0x324439Cu, "sub_324439C"},
                {0x3249358u, "sub_3249358"},
            };
            for (const auto& s : kSteps) {
                const char* nm = s.name;
                tm.OnPcFiltered(s.ea, any, [nm](const TraceContext& c) {
                    LOG(Trace, "[ZSV-STEP] %s reached pid=0x%08X lr=0x%08X\n",
                        nm, c.emu.Get<ArmMmu>().State()->process_id, c.regs[14]);
                });
            }

            /* sub_32A4594 = ZAM init: reads registry
               Services\ZSERV\ZAM\DefaultApp and launches it (the Zune UI) via
               sub_32A26F4, behind an `if(v6>=0)` chain — any gate <0 aborts the
               launch. Last gate to fire + first silent = the dead branch. */
            static const Step kZamSteps[] = {
                {0x325912Cu, "ZSV post-GweReady#1 sub_325912C"},
                {0x32A4594u, "ZAM_init sub_32A4594 ENTRY"},
                {0x32A2810u, "ZAM gate1 sub_32A2810"},
                {0x32A29E4u, "ZAM gate2 sub_32A29E4"},
                {0x32A50E0u, "ZAM gate3 sub_32A50E0"},
                {0x32A763Cu, "ZAM gate4 sub_32A763C"},
                {0x32A4B08u, "ZAM gate5 sub_32A4B08"},
                {0x32A26F4u, "*** ZAM LAUNCH DefaultApp sub_32A26F4 ***"},
                {0x325ADB0u, "ZSV post-GweReady#2 sub_325ADB0"},
                {0x3288D4Cu, "ZSV post-GweReady#3 sub_3288D4C"},
                {0x32736E0u, "ZSV post-GweReady#4 sub_32736E0"},
            };
            for (const auto& s : kZamSteps) {
                const char* nm = s.name;
                auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(s.ea, any, [nm, cnt](const TraceContext& c) {
                    if (cnt->fetch_add(1) >= 4) return;
                    LOG(Trace, "[ZAM-STEP] %s reached pid=0x%08X lr=0x%08X\n",
                        nm, c.emu.Get<ArmMmu>().State()->process_id, c.regs[14]);
                });
            }

            /* sub_32A4594 ENTERS but gate1 sub_32A2810 never fires — a call in
               the entry region blocks (no return). These are the per-call
               return-point PCs; first silent one names the blocking call. */
            static const Step kZamEntry[] = {
                {0x32A45BCu, "ret memset#1"},
                {0x32A45D8u, "ret CreateEvent#1"},
                {0x32A45E8u, "ret check#1"},
                {0x32A460Cu, "ret RegRead DefaultVolume"},
                {0x32A4618u, "ret use-DefaultVolume sub_32C2668"},
                {0x32A462Cu, "ret CreateEvent#2"},
                {0x32A4640u, "ret check#2"},
                {0x32A465Cu, "ret CreateEvent PMC//DisableSuspend"},
                {0x32A4670u, "ret check#3"},
                {0x32A4690u, "ret memset#2"},
                {0x32A46ACu, "ret RegRead RecoveryMode"},
                {0x32A46C8u, "ret KeyVault sub_32C230C"},
            };
            for (const auto& s : kZamEntry) {
                const char* nm = s.name;
                auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(s.ea, any, [nm, cnt](const TraceContext& c) {
                    if (cnt->fetch_add(1) >= 4) return;
                    LOG(Trace, "[ZAM-ENTRY] %s reached pid=0x%08X\n",
                        nm, c.emu.Get<ArmMmu>().State()->process_id);
                });
            }

            /* sub_3243084 reads Services\ZSERV\ZAM\DefaultVolume via 3 PSL
               calls; the per-call return-points narrow which one hangs. */
            static const Step kRegSteps[] = {
                {0x3243084u, "sub_3243084 ENTRY"},
                {0x32430E4u, "ret RegOpenKeyEx(ZSERV.ZAM)"},
                {0x3243138u, "ret RegQueryValueEx(DefaultVolume)"},
                {0x3243160u, "ret RegCloseKey"},
            };
            for (const auto& s : kRegSteps) {
                const char* nm = s.name;
                auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(s.ea, any, [nm, cnt](const TraceContext& c) {
                    if (cnt->fetch_add(1) >= 300) return;
                    LOG(Trace, "[ZAM-REG] %s pid=0x%08X lr=0x%08X\n",
                        nm, c.emu.Get<ArmMmu>().State()->process_id, c.regs[14]);
                });
            }
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelZServWaitAttr);

#endif  /* CERF_DEV_MODE */
