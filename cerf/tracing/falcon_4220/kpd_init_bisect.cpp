#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#if CERF_DEV_MODE

namespace {

/* keypad.dll KBD_Init bisection (runtime VA == IDA VA; keypad.dll loads only
   into device.exe). device.exe's ActivateDeviceEx for Drivers\BuiltIn\KPD
   never returns; KBD_Init -> sub_1811950 runs synchronous calls and one of
   them blocks. Milestones bracket each blocking-capable call so the last
   firing + first non-firing names the stuck call. */
class Falcon4220KpdInitBisect : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kFalcon4220BundleCrc32, [&] {
            auto mark = [&tm](uint32_t va, const char* tag) {
                tm.OnPc(va, [tag](const TraceContext& c) {
                    const uint32_t slot =
                        c.emu.Get<ArmMmu>().State()->process_id >> 25;
                    LOG(Trace, "[FALCON] KBD_Init %s slot=%u\n", tag, slot);
                });
            };
            mark(0x1811310u, "ENTRY");
            mark(0x1811A64u, "before CreateFileW(BAK1:)");
            mark(0x1811A68u, "after CreateFileW(BAK1:)");
            mark(0x1811A84u, "after LoadLibrary(coredll)");
            mark(0x1811AECu, "after CreateThread(pwr)");
            mark(0x1811338u, "sub_1811950 returned");
            mark(0x1811364u, "KBD_Init RETURN");
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(Falcon4220KpdInitBisect);

#endif  /* CERF_DEV_MODE */
