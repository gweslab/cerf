#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "odo_bundle.h"

#include <atomic>

namespace {

/* GWES process_id (FCSE) observed 0x0A000000 → slot 5. dword_79DC8 is
   the GWES master struct; +192 = dword_79E88. Absolute slot-5 address
   is `process_id | offset` = 0x0A079E88. Crash log shows BVA=0x0A000000
   = value stored at this struct field at the moment of the crash. */
constexpr uint32_t kGwesSlot       = 0x0A000000u;
constexpr uint32_t kDwordE88_Slot5 = 0x0A079E88u;
constexpr uint32_t kDwordDC8_Slot5 = 0x0A079DC8u;

std::atomic<uint32_t> g_last_e88{0xFFFFFFFFu};

uint32_t Read32Slot5(const TraceContext& c, uint32_t slot5_va) {
    auto v = c.ReadVa32(slot5_va);
    return v ? *v : 0xDEADBEEFu;
}

class TraceOdoGwesDrvEnableCrash : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kOdoBundleCrc32, [&] {
            auto pass_through = [](const TraceContext&) { return true; };

            /* GWES: PC right after BL j_LoadDriver in sub_2E3A4.
               R0 holds the HMODULE returned from coredll's LoadDriver.
               If R0=0, LoadDriver failed inside coredll/kernel. */
            tm.OnPcFiltered(0x0002E48Cu, pass_through,
                [](const TraceContext& c) {
                    LOG(Trace, "[ODO_CRASH] post-LoadDriver in sub_2E3A4: "
                               "R0(HMODULE)=0x%08X process_id=0x%08X\n",
                        c.regs[0],
                        c.emu.Get<ArmMmu>().State()->process_id);
                });

            /* coredll LoadDriver: PC right after the PSL trap.
               R0 holds the result from kernel-side SC_LoadDriver. */
            tm.OnPcFiltered(0x01F9AE94u, pass_through,
                [](const TraceContext& c) {
                    LOG(Trace, "[ODO_CRASH] post-PSL coredll!LoadDriver: "
                               "R0=0x%08X process_id=0x%08X LR=0x%08X\n",
                        c.regs[0],
                        c.emu.Get<ArmMmu>().State()->process_id,
                        c.regs[14]);
                });

            /* coredll LoadLibraryW: PC right after the PSL trap. */
            tm.OnPcFiltered(0x01F98F90u, pass_through,
                [](const TraceContext& c) {
                    LOG(Trace, "[ODO_CRASH] post-PSL coredll!LoadLibraryW: "
                               "R0=0x%08X process_id=0x%08X LR=0x%08X\n",
                        c.regs[0],
                        c.emu.Get<ArmMmu>().State()->process_id,
                        c.regs[14]);
                });

            tm.OnPcFiltered(0x00074794u,
                [](const TraceContext& c) {
                    return c.regs[0] == 131073u
                        && c.emu.Get<ArmMmu>().State()->process_id
                               == kGwesSlot;
                },
                [](const TraceContext& c) {
                    LOG(Trace, "[ODO_CRASH] sub_74794 thunk to DrvEnableDriver: "
                               "R12(target)=0x%08X R0=%u R1=%u R2=0x%08X "
                               "R3=0x%08X\n",
                        c.regs[12], c.regs[0], c.regs[1],
                        c.regs[2], c.regs[3]);
                });

            /* DllEntryPoint runtime PC = orig_vbase + entryrva = 0x0168136C */
            tm.OnPcFiltered(0x0168136Cu, pass_through,
                [](const TraceContext& c) {
                    LOG(Trace, "[ODO_CRASH] *** cerf_guest::DllEntryPoint ENTERED *** "
                               "R0(hinst)=0x%08X R1(reason)=%u R2=0x%08X LR=0x%08X "
                               "process_id=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[14],
                        c.emu.Get<ArmMmu>().State()->process_id);
                });

            tm.OnPcFiltered(0x01681264u, pass_through,
                [](const TraceContext& c) {
                    LOG(Trace, "[ODO_CRASH] *** cerf_guest::DrvEnableDriver "
                               "ENTERED *** R0=0x%08X R1=0x%08X R2=0x%08X "
                               "R3=0x%08X LR=0x%08X process_id=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14],
                        c.emu.Get<ArmMmu>().State()->process_id);
                });

            /* sub_3E170 entry — master DrvEnable workflow.
               Reading dword_79E88 here tells us its state BEFORE the
               whole driver-enable chain runs. */
            tm.OnPcFiltered(0x0003E170u, pass_through,
                [](const TraceContext& c) {
                    const uint32_t pid =
                        c.emu.Get<ArmMmu>().State()->process_id;
                    if (pid != kGwesSlot) return;
                    const uint32_t e88 = Read32Slot5(c, kDwordE88_Slot5);
                    LOG(Trace, "[ODO_CRASH] sub_3E170 enter R0=0x%08X R1=0x%08X "
                               "R2=0x%08X R3=0x%08X LR=0x%08X "
                               "dword_79E88=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], e88);
                });

            tm.OnPcFiltered(0x000438C8u, pass_through,
                [](const TraceContext& c) {
                    const uint32_t pid =
                        c.emu.Get<ArmMmu>().State()->process_id;
                    if (pid != kGwesSlot) return;
                    const uint32_t e88 = Read32Slot5(c, kDwordE88_Slot5);
                    LOG(Trace, "[ODO_CRASH] sub_438C8 entry "
                               "a1=0x%08X a2=0x%08X LR=0x%08X "
                               "dword_79E88=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14], e88);
                });

            tm.OnPcFiltered(0x00043C88u, pass_through,
                [](const TraceContext& c) {
                    const uint32_t pid =
                        c.emu.Get<ArmMmu>().State()->process_id;
                    if (pid != kGwesSlot) return;
                    const uint32_t e88 = Read32Slot5(c, kDwordE88_Slot5);
                    LOG(Trace, "[ODO_CRASH] sub_43C88 entry "
                               "a1=0x%08X a2=0x%08X LR=0x%08X "
                               "dword_79E88=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14], e88);
                });

            /* Poll dword_79E88 each Run() iteration; log when it
               transitions from one value to another. Cheap because the
               read is one TLB peek and the comparison is one atomic
               load. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                const uint32_t cur = Read32Slot5(c, kDwordE88_Slot5);
                const uint32_t prev =
                    g_last_e88.load(std::memory_order_acquire);
                if (cur == prev) return;
                if (cur == 0xDEADBEEFu) return;
                g_last_e88.store(cur, std::memory_order_release);
                LOG(Trace, "[ODO_CRASH] dword_79E88 changed 0x%08X -> 0x%08X "
                           "current_pc=0x%08X process_id=0x%08X\n",
                    prev, cur, c.pc,
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
        });
    }
};

REGISTER_SERVICE(TraceOdoGwesDrvEnableCrash);

}  /* namespace */
