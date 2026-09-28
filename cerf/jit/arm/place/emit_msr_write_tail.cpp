#include <cstddef>
#include <cstdint>

#include "../arm_cpu.h"
#include "../arm_emit_services.h"
#include "../arm_mmu_state.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../../x86_emit_alu.h"
#include "../../../cpu/arm_processor_config.h"

/* ARM DDI 0406C.c B9.3.8 (p. B9-1990), B9.3.11 (p. B9-1996), B9.3.12
   (p. B9-1998): SPSR access in User or System mode is UNPREDICTABLE;
   UNPREDICTABLE may be implemented as UNDEFINED (p. Glossary-2737). */
uint8_t* EmitSpsrModeGuard(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx,
                           uint8_t** system_mode) {
    using namespace x86;
    EmitMovRegBaseDisp32(cursor, kEcx, kStateReg,
        static_cast<int32_t>(offsetof(ArmCpuState, cpsr)));
    EmitAndRegImm32(cursor, kEcx, 0x1Fu);
    EmitCmpRegImm32(cursor, kEcx, ArmMode::kUser);
    uint8_t* und = EmitJzLabel32(cursor);
    EmitCmpRegImm32(cursor, kEcx, ArmMode::kSystem);
    uint8_t* ok = nullptr;
    if (system_mode != nullptr) {
        *system_mode = EmitJzLabel32(cursor);
        ok = EmitJmpLabel32(cursor);
    } else {
        ok = EmitJnzLabel32(cursor);
    }
    FixupLabel32(und, cursor);
    cursor = EmitRaiseUndTail(cursor, d, ctx);
    FixupLabel32(ok, cursor);
    return cursor;
}

uint8_t* EmitMsrWriteTail(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) {
    using namespace x86;
    const ArmProcessorConfig* config = ctx->emit->ProcessorConfig();

    /* ARM DDI 0100I A4.1.39 (p. A4-77): field_mask bit 0 -> 0x000000FF,
       1 -> 0x0000FF00, 2 -> 0x00FF0000, 3 -> 0xFF000000. */
    uint32_t byte_mask = 0;
    if (d->crn & 1u) byte_mask |= 0x000000FFu;
    if (d->crn & 2u) byte_mask |= 0x0000FF00u;
    if (d->crn & 4u) byte_mask |= 0x00FF0000u;
    if (d->crn & 8u) byte_mask |= 0xFF000000u;

    if (d->n != 0u) {
        /* ARM DDI 0406C.c SPSRWriteByInstr (p. B1-1154): lanes 31:24,
           19:16 (23:20 SBZP), 15:8, 7:0. Pre-v7: byte_mask AND (UserMask
           OR PrivMask OR StateMask), Table A4-1 (DDI 0100I p. A4-77);
           A [8] joins PrivMask on v6 only, A2.5.1 (p. A2-11). */
        uint32_t spsr_mask = 0;
        if (config->HasCp15V7()) {
            if (d->crn & 1u) spsr_mask |= 0x000000FFu;
            if (d->crn & 2u) spsr_mask |= 0x0000FF00u;
            if (d->crn & 4u) spsr_mask |= 0x000F0000u;
            if (d->crn & 8u) spsr_mask |= 0xFF000000u;
        } else if (config->HasCp15V6()) {
            spsr_mask = byte_mask & 0xF90F03FFu;
        } else if (config->HasDsp()) {
            spsr_mask = byte_mask & 0xF80000FFu;
        } else if (config->HasThumb()) {
            spsr_mask = byte_mask & 0xF00000FFu;
        } else {
            spsr_mask = byte_mask & 0xF00000DFu;
        }
        uint8_t* system_mode = nullptr;
        cursor = EmitSpsrModeGuard(cursor, d, ctx,
            config->AccessesSpsrInSystemMode() ? &system_mode : nullptr);
        EmitPush32(cursor, spsr_mask);
        EmitPushReg(cursor, kEax);
        EmitPush32(cursor,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->emit->Cpu())));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmCpu::WriteSpsrByInstrHelper));
        EmitAddRegImm32(cursor, kEsp, 12);
        if (system_mode != nullptr) FixupLabel32(system_mode, cursor);
        return cursor;
    }

    /* UserMask / StateMask rows: ARM DDI 0100I Table A4-1 (p. A4-77);
       PrivMask = I/F/M[4:0] = 0xDF pre-v6, A [8] joins on v6 per A2.5.1
       (p. A2-11). ARMv7 lanes: ARM DDI 0406C.c CPSRWriteByInstr
       (p. B1-1153) with is_excpt_return FALSE. */
    uint32_t mask_user, mask_priv, trip;
    bool nmfi_gate = false;
    if (config->HasCp15V7()) {
        mask_user = byte_mask & 0xF80F0200u;
        mask_priv = byte_mask & 0xF80F03DFu;
        trip      = 0;
        nmfi_gate = true;
    } else if (config->HasCp15V6()) {
        mask_user = byte_mask & 0xF80F0200u;
        mask_priv = byte_mask & 0xF80F03DFu;
        trip      = 0x01000020u;
    } else if (config->HasDsp()) {
        mask_user = byte_mask & 0xF8000000u;
        mask_priv = byte_mask & 0xF80000DFu;
        trip      = 0x00000020u;
    } else if (config->HasThumb()) {
        mask_user = byte_mask & 0xF0000000u;
        mask_priv = byte_mask & 0xF00000DFu;
        trip      = 0x00000020u;
    } else {
        mask_user = byte_mask & 0xF0000000u;
        mask_priv = byte_mask & 0xF00000DFu;
        trip      = 0;
    }

    if (nmfi_gate) {
        EmitPushBaseDisp32(cursor, kMmuReg,
            static_cast<int32_t>(offsetof(ArmMmuState, effective_control_register)));
    } else {
        EmitPush32(cursor, 0);
    }
    EmitPush32(cursor, trip);
    EmitPush32(cursor, mask_priv);
    EmitPush32(cursor, mask_user);
    EmitPushReg(cursor, kEax);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->emit->Cpu())));
    EmitCall(cursor,
        reinterpret_cast<void*>(&ArmCpu::WriteCpsrByInstrHelper));
    EmitAddRegImm32(cursor, kEsp, 24);
    return cursor;
}
