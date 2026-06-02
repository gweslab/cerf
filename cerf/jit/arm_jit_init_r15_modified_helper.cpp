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

void ArmJit::InitializeR15ModifiedHelper() {
    /* One PAGE_EXECUTE_READWRITE page, same shape as
       InitializeInterruptCheck. Trampoline body fits in well under
       100 bytes; the spare room leaves headroom for future helper
       additions on the same page. */
    r15_modified_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!r15_modified_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(R15ModifiedHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = r15_modified_helper_;

    /* MOV ECX, [ESI + offsetof(ArmCpuState, gprs[15])] */
    EmitMovRegBaseDisp32(p, kEcx, kStateReg,
                         static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15 * 4));

    /* CALL interrupt_check_ (rel32). interrupt_check_ was allocated
       earlier in OnReady so its address is fixed; CALL rel32 reaches
       anywhere in the 32-bit address space. */
    EmitCall(p, interrupt_check_);

    /* TEST byte ptr [EBX + offsetof(control_register)], 1 — SCTLR.M
       (bit 0) is the LSB of the first byte at offset 0 of
       ArmCp15ControlRegister. */
    EmitTestByteBaseDisp32Imm8(p, kMmuReg,
        static_cast<int32_t>(offsetof(ArmMmuState, control_register)), 1);
    uint8_t* jz_to_pid_not_needed_a = EmitJzLabel(p);

    /* TEST ECX, 0xFE000000 — high 7 bits already set means address
       already has a process ID encoded; skip fold. */
    EmitTestRegImm32(p, kEcx, 0xFE000000u);
    uint8_t* jnz_to_pid_not_needed_b = EmitJnzLabel(p);

    /* OR ECX, [EBX + offsetof(process_id)] — apply FCSE fold. */
    EmitOrRegBaseDisp32(p, kEcx, kMmuReg,
        static_cast<int32_t>(offsetof(ArmMmuState, process_id)));

    /* ProcessIDNotNeeded: */
    FixupLabel(jz_to_pid_not_needed_a, p);
    FixupLabel(jnz_to_pid_not_needed_b, p);

    /* Resolve through the VA jump cache (flushed on every context switch).
       A per-site cache here would survive an address-space change un-flushed
       and JMP a stale native after FCSE PID reuse. ECX folded; helper re-folds. */
    EmitPushReg(p, kEcx);                  /* arg2: guest PC */
    EmitPush32 (p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
                                            /* arg1: jit baked here */
    EmitCall   (p, reinterpret_cast<void*>(&ArmJit::FindBlockNativeStartHelper));
    EmitAddRegImm32(p, kEsp, 8);

    EmitTestRegReg(p, kEax, kEax);
    uint8_t* jz_to_not_compiled = EmitJzLabel(p);

    EmitJmpReg(p, kEax);                    /* hit → JMP native */

    /* NotCompiled: */
    FixupLabel(jz_to_not_compiled, p);
    EmitRetn(p, 0);

    FlushInstructionCache(GetCurrentProcess(), r15_modified_helper_,
                          static_cast<SIZE_T>(p - r15_modified_helper_));
}
