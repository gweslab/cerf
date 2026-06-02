#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "odo_bundle.h"

namespace {

/* #72 CE3 GA crash: pins why touch.dll's UCB-codec pointer off_1654110 is NULL
   under --guest-additions — VirtualAlloc fail vs VirtualCopy fail (sub_1651858
   then zeroes it) vs already-NULL at the crasher. Hook PCs are fixed-VA ROM-DLL
   addresses (touch.dll @ 0x01650000), so unambiguous. */
constexpr uint32_t kGwesSlot          = 0x0A000000u;  /* GWES process_id, slot 5 */
constexpr uint32_t kUcbPtrVa          = 0x01654110u;  /* off_1654110 */

constexpr uint32_t kInitEntry         = 0x0165173Cu;  /* sub_165173C UCB init */
constexpr uint32_t kPostVCopyUcb      = 0x01651766u;  /* after VirtualCopy(0xB000A000); R0=ret */
constexpr uint32_t kPostVCopyAc       = 0x016517A6u;  /* after VirtualCopy(0xAC020000); R0=ret */
constexpr uint32_t kCleanupZero       = 0x01651858u;  /* sub_1651858 zeroes off_1654110 (init FAIL) */
constexpr uint32_t kTeardown          = 0x0165189Cu;  /* sub_165189C teardown (caller LR names trigger) */
constexpr uint32_t kCrasher           = 0x01651500u;  /* sub_1651500 UCB-register access */

class TraceOdoTouchUcbCrash : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kOdoBundleCrc32, [&tm] {
            auto pid = [](const TraceContext& c) {
                return c.emu.Get<ArmMmu>().State()->process_id;
            };

            tm.OnPc(kInitEntry, [pid](const TraceContext& c) {
                auto cur = c.ReadVa32(kUcbPtrVa);
                LOG(Trace, "[TCH] sub_165173C UCB-init ENTER off_1654110(pre)=%s%08X "
                           "pid=%08X LR=%08X\n",
                    cur ? "" : "(unmapped)", cur.value_or(0), pid(c), c.regs[14]);
            });

            tm.OnPc(kPostVCopyUcb, [](const TraceContext& c) {
                LOG(Trace, "[TCH] VirtualCopy(0xB000A000,30) ret R0=%08X "
                           "(0=FAIL -> pointer will be zeroed)\n", c.regs[0]);
            });

            tm.OnPc(kPostVCopyAc, [](const TraceContext& c) {
                LOG(Trace, "[TCH] VirtualCopy(0xAC020000,4096) ret R0=%08X\n",
                    c.regs[0]);
            });

            tm.OnPc(kCleanupZero, [pid](const TraceContext& c) {
                LOG(Trace, "[TCH] sub_1651858 CLEANUP (zeroes off_1654110 — UCB init "
                           "FAILED) pid=%08X LR=%08X\n", pid(c), c.regs[14]);
            });

            tm.OnPc(kTeardown, [pid](const TraceContext& c) {
                /* LR names the caller: TouchPanelDisable=~0x1652CE6,
                   DllEntryPoint(THREAD_DETACH)=~0x1652804, TouchPanelEnable
                   error paths=0x165294A/0x165296A/0x165299E/0x1652A2C. */
                LOG(Trace, "[TCH] sub_165189C TEARDOWN (will zero off_1654110) "
                           "caller LR=%08X pid=%08X\n", c.regs[14], pid(c));
            });

            tm.OnPc(kCrasher, [pid](const TraceContext& c) {
                auto cur = c.ReadVa32(kUcbPtrVa);
                LOG(Trace, "[TCH] sub_1651500 ENTER off_1654110=%s%08X pid=%08X "
                           "LR=%08X %s\n",
                    cur ? "" : "(unmapped)", cur.value_or(0), pid(c), c.regs[14],
                    (cur && *cur == 0) ? "<<< NULL — about to Data Abort" : "");
            });
        });
    }
};

REGISTER_SERVICE(TraceOdoTouchUcbCrash);

}  /* namespace */
