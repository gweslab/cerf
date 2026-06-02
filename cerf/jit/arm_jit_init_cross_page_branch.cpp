#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstring>
#include <intrin.h>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "arm_cpu_ops.h"
#include "arm_jit_runtime.h"
#include "cpu_state.h"
#include "x86_emit.h"

/* DO NOT bake or self-patch a direct JMP to the dest here (as branch_helper
   does for same-page): a cross-page dest's VA remaps to a different phys on a
   context switch, so a baked JMP lands in the prior process's stale block.
   Resolve via the jump cache (flushed on context switch) and indirect-JMP. */
void ArmJit::InitializeCrossPageBranchHelper() {
    cross_page_branch_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!cross_page_branch_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(CrossPageBranchHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = cross_page_branch_helper_;

    /* ECX = dest VA on entry. Set R15 so a lookup miss dispatches dest. */
    EmitMovBaseDisp32Reg(p, kStateReg,
                         static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15 * 4),
                         kEcx);

    EmitPushReg(p, kEcx);                                          /* arg2: guest_pc */
    EmitPush32(p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
                                                                   /* arg1: jit */
    EmitCall(p, reinterpret_cast<void*>(&ArmJit::FindBlockNativeStartHelper));
    EmitAddRegImm32(p, kEsp, 8);

    EmitTestRegReg(p, kEax, kEax);
    /* Discard the call-site return address so a miss RETN unwinds past the
       dead trailing PlaceEntrypointEnd to the dispatcher, and a hit JMP keeps
       the stack at the dispatcher's frame (chained blocks return there). */
    EmitPopReg(p, kEcx);
    uint8_t* must_compile = EmitJzLabel(p);

    EmitJmpReg(p, kEax);                    /* hit → JMP native (stay in generated code) */

    FixupLabel(must_compile, p);
    EmitRetn(p, 0);                         /* miss → RETN to dispatcher (R15 = dest) */

    FlushInstructionCache(GetCurrentProcess(), cross_page_branch_helper_,
                          static_cast<SIZE_T>(p - cross_page_branch_helper_));
}
