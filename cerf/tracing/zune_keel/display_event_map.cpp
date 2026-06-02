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

/* ddraw_ipu_sdc.dll sub_318B62C creates 10 events via CreateEventW; each ret-PC
   (call+4) holds the handle in R0. Maps name->handle so the stuck WAIT-INF
   handle can be matched to the event the display driver blocks on. */
class ZuneKeelDisplayEventMap : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            const auto any = [](const TraceContext&) -> bool { return true; };
            struct Ev { uint32_t ret_pc; const char* name; };
            static const Ev kEvents[] = {
                {0x318B8FCu, "Pp EOF Event"},
                {0x318B9ACu, "SDC BG Interrupt"},
                {0x318B9CCu, "SDC evt a1[116]"},
                {0x318B9ECu, "SDC evt a1[117]"},
                {0x318BA40u, "DISPLAY/External"},
                {0x318BA60u, "DISPLAY/Local"},
                {0x318BAA0u, "PMC//MtpAttach"},
                {0x318BAE0u, "PMC//MtpDetach"},
                {0x318BB20u, "USB//HostMode In"},
                {0x318BB60u, "USB//HostMode Out"},
            };
            for (const auto& e : kEvents) {
                const char* nm = e.name;
                auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(e.ret_pc, any, [nm, cnt](const TraceContext& c) {
                    if (cnt->fetch_add(1) >= 2) return;
                    LOG(Trace, "[DISP-EVT] '%s' handle=0x%08X pid=0x%08X\n",
                        nm, c.regs[0], c.emu.Get<ArmMmu>().State()->process_id);
                });
            }
        });
    }
};

REGISTER_SERVICE(ZuneKeelDisplayEventMap);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
