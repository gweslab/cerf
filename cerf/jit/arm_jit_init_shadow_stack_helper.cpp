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

void ArmJit::InitializeShadowStackHelper() {
    shadow_stack_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!shadow_stack_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(ShadowStackHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = shadow_stack_helper_;

    void* shadow_stack_base   = static_cast<void*>(&shadow_stack_[0]);
    void* shadow_stack_count  = static_cast<void*>(&shadow_stack_count_);
    void* not_jitted_addr     = reinterpret_cast<void*>(&ArmJit::NotJittedHelper);

    /* CMP [EDI], 0 — short form 83 /7 ib mod=00 r/m=7 imm8=0. */
    Emit8(p, 0x83); EmitModRmReg(p, 0, kEdi, 7); Emit8(p, 0);
    uint8_t* jz_perform_lookup = EmitJzLabel(p);

    /* StartPush: */
    uint8_t* start_push = p;

    EmitMovRegBaseDisp32(p, kEcx, kStateReg,
                         static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 14 * 4));

    EmitTestByteBaseDisp32Imm8(p, kMmuReg,
        static_cast<int32_t>(offsetof(ArmMmuState, control_register)), 1);
    uint8_t* jz_pid_a = EmitJzLabel(p);

    EmitTestRegImm32(p, kEcx, 0xFE000000u);
    uint8_t* jnz_pid_b = EmitJnzLabel(p);

    EmitOrRegBaseDisp32(p, kEcx, kMmuReg,
        static_cast<int32_t>(offsetof(ArmMmuState, process_id)));

    /* ProcessIDNotNeeded: */
    FixupLabel(jz_pid_a, p);
    FixupLabel(jnz_pid_b, p);

    EmitMovzxRegBytePtrAbs(p, kEax, shadow_stack_count);
    EmitShlReg32Imm(p, kEax, 3);

    EmitMovAbsIndexedReg(p,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(shadow_stack_base)),
        kEax, kEcx);
    EmitMovRegBaseDisp32(p, kEdx, kEdi, 0);
    EmitMovAbsIndexedReg(p,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(shadow_stack_base)) + 4u,
        kEax, kEdx);

    EmitIncBytePtrAbs(p, shadow_stack_count);
    EmitRetn(p, 0);

    /* PerformLookup: */
    FixupLabel(jz_perform_lookup, p);
    EmitMovRegBaseDisp32(p, kEcx, kStateReg,
                         static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 14 * 4));
    EmitAndRegImm32(p, kEcx, 0xFFFFFFFEu);

    EmitPushReg(p, kEcx);
    EmitPush32(p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
    EmitCall(p, reinterpret_cast<void*>(&ArmJit::FindBlockNativeStartHelper));
    EmitAddRegImm32(p, kEsp, 8);

    EmitTestRegReg(p, kEax, kEax);
    uint8_t* jz_not_jitted = EmitJzLabel(p);

    /* Found: EAX is native_start (from the VA jump cache). Cache it in [EDI]
       and JMP back to StartPush to push (LR, native_start). */
    EmitMovBaseDisp32Reg(p, kEdi, 0, kEax);
    /* JMP rel32 back to start_push. */
    EmitJmp32(p, start_push);

    /* NotJitted: cache NotJittedHelper address; JMP StartPush. */
    FixupLabel(jz_not_jitted, p);
    EmitMovRegImm32(p, kEax,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(not_jitted_addr)));
    EmitMovBaseDisp32Reg(p, kEdi, 0, kEax);
    EmitJmp32(p, start_push);

    FlushInstructionCache(GetCurrentProcess(), shadow_stack_helper_,
                          static_cast<SIZE_T>(p - shadow_stack_helper_));
}
