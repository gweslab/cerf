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

void ArmJit::InitializePopShadowStackHelper() {
    pop_shadow_stack_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!pop_shadow_stack_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(PopShadowStackHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = pop_shadow_stack_helper_;

    void* shadow_stack_count = static_cast<void*>(&shadow_stack_count_);
    uint32_t shadow_stack_base_addr =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&shadow_stack_[0]));

    /* MOV AL, [<count addr>] — A0 disp32. */
    EmitMovRegBytePtr(p, kAl, shadow_stack_count);
    /* TEST AL, AL — 0x84 ModRM. */
    Emit8(p, 0x84); EmitModRmReg(p, 3, kAl, kAl);
    uint8_t* jz_stack_empty_a = EmitJzLabel(p);

    /* SUB AL, 1 — 0x2C ib. */
    Emit8(p, 0x2C); Emit8(p, 1);
    /* MOV [<count addr>], AL — A2 disp32. */
    Emit8(p, 0xA2); EmitPtr(p, shadow_stack_count);

    /* MOVZX EAX, AL — 0F B6 ModRM(3, AL, EAX). */
    Emit16(p, 0xB60F); EmitModRmReg(p, 3, kAl, kEax);
    EmitShlReg32Imm(p, kEax, 3);

    EmitMovRegBaseDisp32(p, kEcx, kStateReg,
                         static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15 * 4));

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

    Emit8(p, 0x8B);
    EmitModRmReg(p, 0, 4, kEdx);
    EmitSib(p, 0, kEax, 5);
    Emit32(p, shadow_stack_base_addr);

    EmitAndRegImm32(p, kEdx, 0xFFFFFFFEu);

    Emit8(p, 0x3B); EmitModRmReg(p, 3, kEdx, kEcx);
    uint8_t* jnz_stack_empty_b = EmitJnzLabel(p);

    Emit8(p, 0xFF);
    EmitModRmReg(p, 0, 4, 4);
    EmitSib(p, 0, kEax, 5);
    Emit32(p, shadow_stack_base_addr + 4u);

    /* StackEmpty: */
    FixupLabel(jz_stack_empty_a, p);
    FixupLabel(jnz_stack_empty_b, p);
    EmitRetn(p, 0);

    FlushInstructionCache(GetCurrentProcess(), pop_shadow_stack_helper_,
                          static_cast<SIZE_T>(p - pop_shadow_stack_helper_));
}
