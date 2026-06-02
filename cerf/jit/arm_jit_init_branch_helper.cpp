#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstring>
#include <intrin.h>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "arm_cpu_exceptions.h"
#include "arm_cpu_ops.h"
#include "arm_jit_runtime.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "place_fns.h"
#include "x86_emit.h"

void ArmJit::InitializeBranchHelper() {
    branch_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!branch_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(BranchHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = branch_helper_;

    /* MOV [ESI + R15_offset], ECX */
    EmitMovBaseDisp32Reg(p, kStateReg,
                         static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15 * 4),
                         kEcx);

    /* Lookup helper call — returns the destination's native_start (via the
       VA jump cache) directly in EAX, or null. */
    EmitPushReg(p, kEcx);                                         /* arg2: guest_pc */
    EmitPush32(p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
                                                                   /* arg1: jit */
    EmitCall(p, reinterpret_cast<void*>(&ArmJit::FindBlockNativeStartHelper));
    EmitAddRegImm32(p, kEsp, 8);

    EmitTestRegReg(p, kEax, kEax);
    EmitPopReg(p, kEcx);
    uint8_t* must_compile = EmitJzLabel(p);

    /* Hit path: EAX is native_start. Self-patch the 10-byte MOV+CALL at the
       call site into JMP rel32 — reached only for same-page targets (chosen
       in PlaceBranch), so the baked JMP is phys-stable across context switch. */
    EmitMovRegReg(p, kEdi, kEax);
    /* EAX = EDI - 5 (computed via MOV+SUB since no LEA primitive). */
    EmitMovRegReg(p, kEax, kEdi);
    EmitSubRegImm32(p, kEax, 5);
    /* ECX -= 10 (back up to MOV-CALL patch site). */
    EmitSubRegImm32(p, kEcx, 10);
    /* EAX -= ECX (rel32). */
    EmitSubReg32Reg32(p, kEax, kEcx);

    /* Write JMP opcode (0xE9) at [ECX+0]. MOV [base+disp8], imm8
       form: C6 [mod=01 reg=0 r/m=ECX(1)] disp8 imm8. */
    Emit8(p, 0xC6);
    EmitModRmReg(p, 1, kEcx, 0);
    Emit8(p, 0);     /* disp8 = 0 */
    Emit8(p, 0xE9);  /* JMP rel32 opcode */

    /* Write rel32 (EAX) at [ECX+1]. MOV [base+disp8], r32:
       89 [mod=01 reg=EAX(0) r/m=ECX(1)] disp8. */
    Emit8(p, 0x89);
    EmitModRmReg(p, 1, kEcx, kEax);
    Emit8(p, 1);     /* disp8 = 1 */

    /* FlushInstructionCache(-1, ECX, 5). */
    EmitPush32(p, 5);
    EmitPushReg(p, kEcx);
    EmitPush32(p, 0xFFFFFFFFu);
    EmitCall(p, reinterpret_cast<void*>(&FlushInstructionCache));

    /* JMP EDI to enter the destination block. */
    EmitJmpReg(p, kEdi);

    /* must_compile: RETN to dispatcher. */
    FixupLabel(must_compile, p);
    EmitRetn(p, 0);

    FlushInstructionCache(GetCurrentProcess(), branch_helper_,
                          static_cast<SIZE_T>(p - branch_helper_));
}
