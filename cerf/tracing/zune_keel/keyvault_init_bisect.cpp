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

/* ActivateDeviceEx(Drivers\KeyVault) hangs; KEY_Init's sub-init chain runs in
   the driver host (device.exe), not the zserv caller — so pid is logged. */
class ZuneKeelKeyVaultInit : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            const auto any = [](const TraceContext&) -> bool { return true; };
            struct Step { uint32_t ea; const char* name; };
            static const Step kSteps[] = {
                {0x2FC5B7Cu, "KEY_Init"},
                {0x2FC5A1Cu, "sub_2FC5A1C body"},
                {0x2FD48F4u, "sub_2FD48F4 #1"},
                {0x2FC58E8u, "sub_2FC58E8 keypack #2"},
                {0x2FC5998u, "sub_2FC5998 keyhash #3"},
                {0x2FD3E18u, "sub_2FD3E18 keyfile #4"},
                {0x2FC7510u, "sub_2FC7510 #5a"},
                {0x2FD4538u, "sub_2FD4538 #5b"},
                {0x2FC5B00u, "ret sub_2FC7510"},
                {0x2FC5B0Cu, "ret sub_2FD4538"},
                {0x2FC5B20u, "ret sub_2FC5A1C DONE"},
                {0x2FC5B9Cu, "ret KEY_Init DONE"},
                /* sub_2FD4538 internal call returns (first silent = the hang). */
                {0x2FD4568u, "ret 4538.sub_2FDB960#1"},
                {0x2FD457Cu, "ret 4538.alloc"},
                {0x2FD459Cu, "ret 4538.sub_2FD4198"},
                {0x2FD45C0u, "ret 4538.sub_2FD4350"},
                {0x2FD45CCu, "ret 4538.sub_2FC7A38"},
                {0x2FD45D8u, "ret 4538.sub_2FC7A80"},
                {0x2FD45E4u, "ret 4538.sub_2FD3EDC"},
                {0x2FD45F0u, "ret 4538.sub_2FD3D98"},
                /* discriminate sub_2FD4350!=0 (crypto path) vs ==0 (cleanup). */
                {0x2FC7A38u, "sub_2FC7A38 ENTRY (crypto path)"},
                {0x2FC73F8u, "  A38.sub_2FC73F8"},
                {0x2FC75C8u, "  A38.sub_2FC75C8"},
                {0x2FD4614u, "ret 4538.cleanup-40C8"},
                {0x2FD461Cu, "ret 4538.cleanup-9E0"},
                {0x2FD4638u, "ret 4538.sub_2FDB960#2"},
                /* which cipher did sub_2FD48F4 select + use? */
                {0x2FC7360u, "*** SW-cipher sub_2FC7360 ***"},
                {0x2FD46E4u, "*** HW-cipher sub_2FD46E4 ***"},
            };
            for (const auto& s : kSteps) {
                const char* nm = s.name;
                auto cnt = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(s.ea, any, [nm, cnt](const TraceContext& c) {
                    if (cnt->fetch_add(1) >= 4) return;
                    LOG(Trace, "[KEYVAULT] %s reached pid=0x%08X lr=0x%08X\n",
                        nm, c.emu.Get<ArmMmu>().State()->process_id, c.regs[14]);
                });
            }
        });
    }
};

REGISTER_SERVICE(ZuneKeelKeyVaultInit);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
