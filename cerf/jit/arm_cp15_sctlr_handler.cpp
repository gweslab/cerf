#include "arm_cp15_sctlr_handler.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "arm_cpu.h"
#include "arm_jit.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "arm_pte.h"
#include "cpu_state.h"
#include "x86_emit.h"

REGISTER_SERVICE(ArmCp15SctlrHandler);

ArmCp15SctlrHandler::~ArmCp15SctlrHandler() {
    if (trampoline_) {
        VirtualFree(trampoline_, 0, MEM_RELEASE);
        trampoline_ = nullptr;
    }
}

void ArmCp15SctlrHandler::OnReady() {
    mmu_    = &emu_.Get<ArmMmu>();
    memory_ = &emu_.Get<EmulatedMemory>();
}

int ArmCp15SctlrHandler::HandleWrite(ArmJit*  jit,
                                     uint32_t new_value,
                                     uint32_t guest_addr) {
    ArmMmuState* state = mmu_->State();
    ArmCpuState* cpu_state = jit->CpuState();

    ArmCp15ControlRegister reg;
    reg.word = new_value;

    /* v4/v5 only — ARMv7 SCTLR has different reserved/fixed bits;
       applying ARM920T constraints to a v7 SCTLR write would UND
       or silently rewrite v7-specific bits the kernel just set. */
    if (!jit->ProcessorConfig()->HasCp15V6() &&
        !jit->ProcessorConfig()->HasCp15V7()) {
        if (reg.bits.reserved2 != 0 ||
            (reg.bits.reserved3 != 0xC000u && reg.bits.reserved3 != 0u)) {
            (void)jit->Cpu()->RaiseUndefinedException(guest_addr);
            return 0;
        }
        reg.bits.c  = 1;
        reg.bits.w  = 1;
        reg.bits.p  = 1;
        reg.bits.d  = 1;
        reg.bits.l  = 1;
        reg.bits.z  = 1;
        reg.bits.i  = 1;
        reg.bits.b  = 0;
        reg.bits.rr = 0;
        reg.bits.l4 = 0;
    }

    const bool enabling_mmu = reg.bits.m && !state->control_register.bits.m;

    if (enabling_mmu) {
        /* Seed ITLB[0] for guest_addr+4 — kernel prefetched the
           next instruction before MCR and expects it executable
           under MMU-on without a page-table walk first. */
        const uint32_t actual_guest_addr = ((guest_addr & 0xFE000000u) == 0u)
            ? (guest_addr | state->process_id)
            : guest_addr;

        /* Identity PA at this transition (pre-MMU VA == PA); global so the
           seed matches under any ASID. A present ITLB entry is executable —
           the fast-path fetch skips the permission re-check the walk did. */
        const uint32_t seed_va_page = (actual_guest_addr + 4u) & 0xFFFFF000u;
        const uint32_t seed_pa_page = (guest_addr + 4u) & 0xFFFFF000u;
        uint8_t* host_page = memory_->TryTranslate(seed_pa_page);

        if (host_page) {
            ArmTlbEntry& e = ArmTlbInsertSlot(&state->instruction_tlb,
                                              ArmTlbSetBase(seed_va_page));
            e.tag       = seed_va_page;
            e.va_addend = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(host_page) - seed_va_page);
            e.pa_page   = seed_pa_page;
            e.asid      = static_cast<uint8_t>(state->contextidr & 0xFFu);
            e.global    = 1u;
            e.writable  = 0u;
        }

        jit->FlushTranslationCache(0, 0xFFFFFFFFu);
        state->control_register.word    = reg.word;
        cpu_state->gprs[ArmGpr::kR15]   = guest_addr + 4u;
        /* Return 0 so the trampoline pops the JIT block ret addr
           and escapes the freed block, re-entering the dispatcher
           which will retranslate R15 under the new MMU regime. */
        return 0;
    }

    state->control_register.word = reg.word;
    return 1;
}

int __cdecl ArmCp15SctlrHandler::HandleWriteStaticHelper(
        ArmCp15SctlrHandler* self,
        ArmJit*              jit,
        uint32_t             new_value,
        uint32_t             guest_addr) {
    return self->HandleWrite(jit, new_value, guest_addr);
}

void ArmCp15SctlrHandler::InitializeTrampoline(ArmJit* jit) {
    if (trampoline_) {
        return;
    }

    /* One PAGE_EXECUTE_READWRITE page; trampoline body is well under
       64 bytes but VirtualAlloc's minimum granularity is one page. */
    trampoline_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!trampoline_) {
        LOG(Caution, "ArmCp15SctlrHandler: VirtualAlloc(trampoline) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = trampoline_;

    /* Caller-set: ECX=new_value, EDX=guest_addr. HandleWrite
       returns 0 to escape via dispatcher (cache-flush path),
       non-zero to RETN into the JIT block (no flush). */
    EmitPushReg(p, kEdx);
    EmitPushReg(p, kEcx);
    EmitPush32 (p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
    EmitPush32 (p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
    EmitCall   (p, reinterpret_cast<void*>(&ArmCp15SctlrHandler::HandleWriteStaticHelper));
    EmitAddRegImm32(p, kEsp, 16);
    EmitTestRegReg (p, kEax, kEax);
    /* JNZ short — skip exactly the POP EAX (1 byte). */
    Emit8(p, 0x75);
    Emit8(p, 0x01);
    /* POP EAX (1 byte) — discards JIT block ret addr when EAX==0. */
    Emit8(p, 0x58);
    /* RETN. */
    Emit8(p, 0xC3);

    FlushInstructionCache(GetCurrentProcess(), trampoline_,
                          static_cast<SIZE_T>(p - trampoline_));
}
