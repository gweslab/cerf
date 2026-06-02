#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcEnsureSipEnvReady       = 0x40777E1Cu;
constexpr uint32_t kPcSoftKeySipEnvInitialize = 0x40777BFCu;
constexpr uint32_t kPcPostCreateThread        = 0x40777C60u;
constexpr uint32_t kPcPostWaitThreadReady     = 0x40777C74u;
constexpr uint32_t kPcSipThreadFunc           = 0x40777BDCu;
constexpr uint32_t kPcInternalThreadFunc      = 0x407777E0u;
constexpr uint32_t kPcMessageLoop             = 0x407773A4u;
constexpr uint32_t kPcProcessThreadEvent      = 0x40776A74u;

constexpr uint32_t kVaPCurThd = 0xFFFFC824u;

class TraceCe7SipThreadBisect : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto user_proc_only = [](const TraceContext& c) -> bool {
                return (c.emu.Get<ArmMmu>()
                            .State()
                            ->translation_table_base.word
                        & 0xFFFFC000u) != 0u;
            };

            tm.OnPcFiltered(kPcEnsureSipEnvReady, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 20 && (n % 100u) != 0u) return;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t ttbr =
                        c.emu.Get<ArmMmu>()
                            .State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[sip-bs] #1 EnsureSipEnvReady #%u "
                        "this=0x%08X pTh=0x%08X TTBR0=0x%08X LR=0x%08X\n",
                        n, c.regs[0], pcurthd, ttbr, c.regs[14]);
                });

            tm.OnPcFiltered(kPcSoftKeySipEnvInitialize, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[sip-bs] #2 SoftKeySipEnvInitialize #%u ENTRY "
                        "this=0x%08X pTh=0x%08X LR=0x%08X\n",
                        n, c.regs[0], pcurthd, c.regs[14]);
                });

            tm.OnPcFiltered(kPcPostCreateThread, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[sip-bs] #3 post-CreateThread #%u "
                        "hThread(R0)=0x%08X pTh=0x%08X LR=0x%08X\n",
                        n, c.regs[0], pcurthd, c.regs[14]);
                });

            tm.OnPcFiltered(kPcPostWaitThreadReady, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[sip-bs] #4 post-WaitForSingleObject(hThreadReady) #%u "
                        "ret(R0)=0x%08X pTh=0x%08X LR=0x%08X\n",
                        n, c.regs[0], pcurthd, c.regs[14]);
                });

            tm.OnPcFiltered(kPcSipThreadFunc, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t ttbr =
                        c.emu.Get<ArmMmu>()
                            .State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[sip-bs] #5 SipThreadFunc #%u ENTRY "
                        "pvParam=0x%08X pTh=0x%08X TTBR0=0x%08X LR=0x%08X "
                        "CPSR=0x%08X\n",
                        n, c.regs[0], pcurthd, ttbr, c.regs[14], c.cpsr);
                });

            tm.OnPcFiltered(kPcInternalThreadFunc, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t ttbr =
                        c.emu.Get<ArmMmu>()
                            .State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[sip-bs] #6 InternalThreadFunc #%u ENTRY "
                        "this=0x%08X pTh=0x%08X TTBR0=0x%08X LR=0x%08X\n",
                        n, c.regs[0], pcurthd, ttbr, c.regs[14]);
                });

            tm.OnPcFiltered(kPcMessageLoop, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t ttbr =
                        c.emu.Get<ArmMmu>()
                            .State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[sip-bs] #7 MessageLoop #%u ENTRY "
                        "this=0x%08X pTh=0x%08X TTBR0=0x%08X LR=0x%08X\n",
                        n, c.regs[0], pcurthd, ttbr, c.regs[14]);
                });

            tm.OnPcFiltered(kPcProcessThreadEvent, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 20 && (n % 100u) != 0u) return;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[sip-bs] #8 ProcessThreadEvent #%u "
                        "this=0x%08X pTh=0x%08X LR=0x%08X\n",
                        n, c.regs[0], pcurthd, c.regs[14]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7SipThreadBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
