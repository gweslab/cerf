#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "wm5_bundle.h"

namespace {

class TraceWm5PslDispatcher : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kWm5BundleCrc32, [&] {
            /* sub_80077290 entry window (PUSH {R0-R3}, PUSH {LR},
               SUB SP, etc.). Capture full reg state at every block-start
               in the entry sequence. */
            for (uint32_t pc = 0x80077290u; pc <= 0x800772C0u; pc += 4) {
                tm.OnPc(pc, [pc](const TraceContext& c) {
                    DumpFullRegs(c, "[PSL_ENTRY]", pc);
                });
            }
            for (uint32_t pc = 0x800773D0u; pc <= 0x800773F0u; pc += 4) {
                tm.OnPc(pc, [pc](const TraceContext& c) {
                    DumpFullRegs(c, "[PSL_BL_SETUP]", pc);
                });
            }
            /* PSL handler return: STR at PC=0x800773F4 saves R0 (=
               handler return) to [SP+0x10]. Correlate R4 (=trap addr)
               with the return value to identify which PSL returned
               what status. */
            tm.OnPc(0x800773F4u, [](const TraceContext& c) {
                LOG(Trace, "[PSL_RET] R4_trap=0x%08X handler_retval=R0=0x%08X "
                           "R1=0x%08X R2=0x%08X R3=0x%08X SP=0x%08X\n",
                    c.regs[4], c.regs[0], c.regs[1], c.regs[2],
                    c.regs[3], c.regs[13]);
            });

            /* sub_800B3A0C Duff-device LDR table — captures R4..R11
               to detect host-register mapping off-by-one. R0 in
               [0x01FFF000..0x01FFFFFF) (coredll per-process .data). */
            for (uint32_t pc = 0x800B3AA4u; pc <= 0x800B3AC0u; pc += 4) {
                tm.OnPc(pc, [pc](const TraceContext& c) {
                    if (c.regs[0] < 0x01FFF000u || c.regs[0] >= 0x02000000u)
                        return;
                    LOG(Trace, "[LDR_DIAG] PC=0x%08X "
                               "R0=0x%08X R1=0x%08X R3=0x%08X R12=0x%08X "
                               "R4=0x%08X R5=0x%08X R6=0x%08X R7=0x%08X "
                               "R8=0x%08X R9=0x%08X R10=0x%08X R11=0x%08X\n",
                        pc, c.regs[0], c.regs[1], c.regs[3], c.regs[12],
                        c.regs[4], c.regs[5], c.regs[6], c.regs[7],
                        c.regs[8], c.regs[9], c.regs[10], c.regs[11]);
                });
            }
            /* sub_800B3A0C Duff-device STR table — captures stored
               value + R4..R11 to detect divergence. */
            for (uint32_t pc = 0x800B3ACCu; pc <= 0x800B3AE8u; pc += 4) {
                tm.OnPc(pc, [pc](const TraceContext& c) {
                    LOG(Trace, "[STR_DIAG] PC=0x%08X "
                               "R0=0x%08X R4=0x%08X R5=0x%08X R6=0x%08X "
                               "R7=0x%08X R8=0x%08X R9=0x%08X R10=0x%08X R11=0x%08X\n",
                        pc, c.regs[0],
                        c.regs[4], c.regs[5], c.regs[6], c.regs[7],
                        c.regs[8], c.regs[9], c.regs[10], c.regs[11]);
                });
            }

            /* Kernel's MOVS PC, R12 at 0x80077458 returns to user mode.
               R12 = user-resume PC. If R12 == 0x03F5842C (DllEntryPoint),
               kernel jumps user there directly — loop sustainer. */
            tm.OnPc(0x80077458u, [](const TraceContext& c) {
                LOG(Trace, "[KERN_MOVS_PC] at 0x80077458 R12=0x%08X "
                           "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                           "LR=0x%08X SP=0x%08X CPSR=0x%08X\n",
                    c.regs[12], c.regs[0], c.regs[1], c.regs[2],
                    c.regs[3], c.regs[14], c.regs[13], c.cpsr);
            });
        });
    }

private:
    static void DumpFullRegs(const TraceContext& c, const char* tag, uint32_t pc) {
        LOG(Trace, "%s PC=0x%08X "
                   "R0=%X R1=%X R2=%X R3=%X R4=%X R5=%X R6=%X R7=%X "
                   "R8=%X R9=%X R10=%X R11=%X R12=%X SP=%X LR=%X\n",
            tag, pc,
            c.regs[0], c.regs[1], c.regs[2], c.regs[3],
            c.regs[4], c.regs[5], c.regs[6], c.regs[7],
            c.regs[8], c.regs[9], c.regs[10], c.regs[11],
            c.regs[12], c.regs[13], c.regs[14]);
    }
};

REGISTER_SERVICE(TraceWm5PslDispatcher);

}  /* namespace */

