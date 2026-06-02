#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"
#include "ce7_process_resolver.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* Coredll PCs inside compositor's death window. All high-VA (shared
   coredll image), so filtered by ttbr0 == compositor's. */
constexpr uint32_t kPcInitCsEntry        = 0x4002FBACu;  /* InitializeCriticalSection */
constexpr uint32_t kPcInitCsBeforeBlx    = 0x4002FBE0u;  /* BLX R3 (PSL trap target) */
constexpr uint32_t kPcInitCsAfterBlx     = 0x4002FBE4u;  /* STR R0, [R4,#8] */
constexpr uint32_t kPcRtlLookupFnEntry   = 0x4002E788u;  /* RtlLookupFunctionEntry */
constexpr uint32_t kPcThumbUnwindProlog  = 0x40079558u;  /* ThumbUnwindProlog */
constexpr uint32_t kPcReadCode16Entry    = 0x40079044u;  /* ReadCode16 entry */

class TraceCe7CompositorDeathProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto cmp_only = ce7_resolver::PidPredicateForName("compositor.exe");

            tm.OnPcFiltered(kPcInitCsEntry, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] InitCS ENTRY (cmp-filtered)  lpcs=0x%08X "
                        "R14=0x%08X SP=0x%08X cpsr=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13], c.cpsr);
                });

            tm.OnPcFiltered(kPcInitCsBeforeBlx, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] InitCS pre-BLX  R3=0x%08X (PSL trap target) "
                        "R0=0x%08X R4=0x%08X cpsr=0x%08X\n",
                        c.regs[3], c.regs[0], c.regs[4], c.cpsr);
                });

            tm.OnPcFiltered(kPcInitCsAfterBlx, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] InitCS post-BLX  R0(hCrit)=0x%08X R4=0x%08X "
                        "R14=0x%08X cpsr=0x%08X\n",
                        c.regs[0], c.regs[4], c.regs[14], c.cpsr);
                });

            tm.OnPcFiltered(kPcRtlLookupFnEntry, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] RtlLookupFunctionEntry  R0(tbl)=0x%08X "
                        "R1(size)=0x%08X R2(ControlPc)=0x%08X R3(prf)=0x%08X "
                        "R14=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(kPcThumbUnwindProlog, cmp_only,
                [](const TraceContext& c) {
                    uint32_t ctxR0 = c.ReadVa32(c.regs[3] +  0u).value_or(0xDEAD0000);
                    uint32_t ctxLr = c.ReadVa32(c.regs[3] + 0x38u).value_or(0xDEAD0038);
                    uint32_t ctxPc = c.ReadVa32(c.regs[3] + 0x3Cu).value_or(0xDEAD003C);
                    LOG(Trace,
                        "[death] ThumbUnwindProlog  R0(Prolog)=0x%08X "
                        "R1(PrologBytes)=0x%08X R2(PrologPc)=0x%08X "
                        "R3(ContextRecord)=0x%08X  ctx[0]=0x%08X "
                        "ctx.LR(+0x38)=0x%08X ctx.PC(+0x3C)=0x%08X  "
                        "R14=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        ctxR0, ctxLr, ctxPc, c.regs[14]);
                });

            tm.OnPcFiltered(kPcReadCode16Entry, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] ReadCode16  R0(Address)=0x%08X R14=0x%08X "
                        "SP=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(0x00011A90u, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] cmp_thunk_RegOpenKeyExW ENTRY  R0=0x%08X "
                        "R1=0x%08X R14=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14]);
                });
            tm.OnPcFiltered(0x00011A98u, cmp_only,
                [](const TraceContext& c) {
                    auto slot = c.ReadVa32(0x00011A9Cu);
                    LOG(Trace,
                        "[death] cmp_thunk_RegOpenKeyExW BX  R12=0x%08X "
                        "IAT[0x11A9C]=0x%08X R14=0x%08X\n",
                        c.regs[12], slot.value_or(0xDEADBEEF), c.regs[14]);
                });
            tm.OnPcFiltered(0x000115BCu, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] LoadConfiguration after-BL R0(ret)=0x%08X "
                        "R14=0x%08X\n",
                        c.regs[0], c.regs[14]);
                });
            tm.OnPcFiltered(0x000115B8u, cmp_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[death] LoadConfiguration pre-BL_RegOpen R0=0x%08X "
                        "R1=0x%08X R14=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(0x40055D58u, cmp_only,
                [](const TraceContext& c) {
                    uint32_t code  = c.ReadVa32(c.regs[0] +  0u).value_or(0xDEAD0000);
                    uint32_t flags = c.ReadVa32(c.regs[0] +  4u).value_or(0xDEAD0004);
                    uint32_t addr  = c.ReadVa32(c.regs[0] + 12u).value_or(0xDEAD000C);
                    uint32_t np    = c.ReadVa32(c.regs[0] + 16u).value_or(0xDEAD0010);
                    uint32_t info0 = c.ReadVa32(c.regs[0] + 20u).value_or(0xDEAD0014);
                    uint32_t info1 = c.ReadVa32(c.regs[0] + 24u).value_or(0xDEAD0018);
                    LOG(Trace,
                        "[death] xxRtlDispatchException  pExr=0x%08X pCtx=0x%08X  "
                        "code=0x%08X flags=0x%08X addr=0x%08X numparams=%u "
                        "info0=0x%08X info1=0x%08X  R14=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[1], code, flags, addr, np,
                        info0, info1, c.regs[14], c.regs[13]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7CompositorDeathProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
