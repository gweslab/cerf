#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "devemu_ce6_bundle.h"

namespace {

class TraceCe6EnableSurfaceGate : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kDevemuCe6BundleCrc32, [&] {
            tm.OnPc(0xC014F808u,
                [](const TraceContext& c) {
                    LOG(Trace, "[CE6_GATE] sub_C014F808 enter R0=0x%08X "
                               "process_id=0x%08X LR=0x%08X\n",
                        c.regs[0],
                        c.emu.Get<ArmMmu>().State()->process_id,
                        c.regs[14]);
                });

            tm.OnPc(0xC014F810u,
                [](const TraceContext& c) {
                    LOG(Trace, "[CE6_GATE] post-sub_C0188600 R0=0x%08X\n",
                        c.regs[0]);
                });

            tm.OnPc(0xC014F824u,
                [](const TraceContext& c) {
                    LOG(Trace, "[CE6_GATE] sub_C014F808 return R0=0x%08X\n",
                        c.regs[0]);
                });

            tm.OnPc(0xC0150FACu,
                [](const TraceContext& c) {
                    LOG(Trace, "[CE6_GATE] sub_C0150978: about to call "
                               "sub_C014F808 with R0=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[14]);
                });

            tm.OnPc(0xC0150978u,
                [](const TraceContext& c) {
                    auto mm_flag = c.ReadVa32(0xC01EBB34u);
                    auto primary = c.ReadVa32(0xC01EB878u);
                    LOG(Trace, "[CE6_GATE] sub_C0150978 entry: "
                               "a1(v4)=0x%08X a2(hmod)=0x%08X "
                               "dword_C01EBB34=0x%08X off_C01EB878=0x%08X\n",
                        c.regs[0], c.regs[1],
                        mm_flag.value_or(0xDEADBEEFu),
                        primary.value_or(0xDEADBEEFu));
                });

            tm.OnPc(0xC0150F48u,
                [](const TraceContext& c) {
                    LOG(Trace, "[CE6_GATE] sub_C0150978 0xC0150F48: "
                               "BEQ branch; R3(dword_C01EBB34 value)=0x%08X\n",
                        c.regs[3]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe6EnableSurfaceGate);

}  /* namespace */
