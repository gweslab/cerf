#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>

#include "../core/log.h"
#include "cpu_state.h"
#include "x86_emit.h"

void ArmJit::InitializeBlockUsermodeHelper() {
    block_usermode_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!block_usermode_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(BlockUsermodeHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = block_usermode_helper_;

    const auto bake = [](void* ptr) {
        return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ptr));
    };
    ArmCpuState* s = cpu_->State();
    const uint32_t addr_cpsr     = bake(&s->cpsr);
    const uint32_t addr_gprs     = bake(&s->gprs[0]);
    const uint32_t addr_gprs_svc = bake(&s->gprs_svc[0]);
    const uint32_t addr_gprs_abt = bake(&s->gprs_abt[0]);
    const uint32_t addr_gprs_irq = bake(&s->gprs_irq[0]);
    const uint32_t addr_gprs_und = bake(&s->gprs_und[0]);

    /* Emit "LEA ECX, [<imm32> + ECX*4]; RETN". 8 bytes. */
    auto emit_lea_ret = [&](uint32_t base_addr) {
        Emit8(p, 0x8D);  /* LEA */
        Emit8(p, 0x0C);  /* ModRM: mod=00 reg=ECX(1) r/m=4 (SIB) */
        Emit8(p, 0x8D);  /* SIB:   ss=2 (*4) index=ECX(1) base=5 (disp32) */
        Emit32(p, base_addr);
        EmitRetn(p, 0);
    };

    /* MOV EAX, [addr_cpsr]  (5 bytes via the A1 short form for EAX). */
    EmitMovRegDwordPtr(p, kEax, reinterpret_cast<void*>(addr_cpsr));

    /* AND EAX, 0x1F  — encode imm8 form (83 /4 ib) for compactness. */
    Emit8(p, 0x83);
    EmitModRmReg(p, 3, kEax, 4);
    Emit8(p, 0x1F);

    /* 6× CMP EAX, <mode>; JZ <case-label>. Use rel32 JZs so we
       don't have to worry about short-vs-near forwards. */
    EmitCmpRegImm32(p, kEax, ArmMode::kSystem);
    uint8_t* jz_system     = EmitJzLabel(p);
    EmitCmpRegImm32(p, kEax, ArmMode::kIrq);
    uint8_t* jz_irq        = EmitJzLabel(p);
    EmitCmpRegImm32(p, kEax, ArmMode::kSupervisor);
    uint8_t* jz_supervisor = EmitJzLabel(p);
    EmitCmpRegImm32(p, kEax, ArmMode::kAbort);
    uint8_t* jz_abort      = EmitJzLabel(p);
    EmitCmpRegImm32(p, kEax, ArmMode::kUndefined);
    uint8_t* jz_undefined  = EmitJzLabel(p);
    EmitCmpRegImm32(p, kEax, ArmMode::kUser);
    uint8_t* jz_user       = EmitJzLabel(p);

    /* InUserMode (and FIQ fallthrough — FIQ not modelled). */
    uint8_t* in_user_label = p;
    FixupLabel(jz_user, p);
    FixupLabel(jz_system, p);
    emit_lea_ret(addr_gprs);

    /* InIRQMode: */
    FixupLabel(jz_irq, p);
    EmitCmpRegImm32(p, kEcx, 13);
    /* JB rel32 → InUserMode. 0x0F 0x82 imm32 (6 bytes). */
    Emit8(p, 0x0F);
    Emit8(p, 0x82);
    {
        const int32_t rel = static_cast<int32_t>(in_user_label - (p + 4));
        Emit32(p, static_cast<uint32_t>(rel));
    }
    EmitSubRegImm32(p, kEcx, 13);
    emit_lea_ret(addr_gprs_irq);

    /* InSupervisorMode: */
    FixupLabel(jz_supervisor, p);
    EmitCmpRegImm32(p, kEcx, 13);
    Emit8(p, 0x0F);
    Emit8(p, 0x82);
    {
        const int32_t rel = static_cast<int32_t>(in_user_label - (p + 4));
        Emit32(p, static_cast<uint32_t>(rel));
    }
    EmitSubRegImm32(p, kEcx, 13);
    emit_lea_ret(addr_gprs_svc);

    /* InAbortMode: */
    FixupLabel(jz_abort, p);
    EmitCmpRegImm32(p, kEcx, 13);
    Emit8(p, 0x0F);
    Emit8(p, 0x82);
    {
        const int32_t rel = static_cast<int32_t>(in_user_label - (p + 4));
        Emit32(p, static_cast<uint32_t>(rel));
    }
    EmitSubRegImm32(p, kEcx, 13);
    emit_lea_ret(addr_gprs_abt);

    /* InUndefinedMode: */
    FixupLabel(jz_undefined, p);
    EmitCmpRegImm32(p, kEcx, 13);
    Emit8(p, 0x0F);
    Emit8(p, 0x82);
    {
        const int32_t rel = static_cast<int32_t>(in_user_label - (p + 4));
        Emit32(p, static_cast<uint32_t>(rel));
    }
    EmitSubRegImm32(p, kEcx, 13);
    emit_lea_ret(addr_gprs_und);

    FlushInstructionCache(GetCurrentProcess(), block_usermode_helper_,
                          static_cast<SIZE_T>(p - block_usermode_helper_));
}
