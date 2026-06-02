#include <cstddef>
#include <cstdint>

#include "../../cpu/arm_processor_config.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../arm_mmu_state.h"
#include "../arm_tlb_ops.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

namespace {

/* Store Rd into the cp15 field at mmu_disp; on a real change drop the VA-keyed
   native caches via ContextSwitchFlush. NOT a translation-cache flush — blocks
   are phys-keyed so they survive an address-space change; a TC flush here would
   reinstate the per-context-switch storm. `mask` is ANDed in (0xFFFFFFFF=none). */
uint8_t* EmitFieldWriteContextSwitch(uint8_t* cursor, ArmJit* jit,
                                     int32_t rd_disp, int32_t mmu_disp,
                                     uint32_t mask) {
    using namespace x86;
    EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
    if (mask != 0xFFFFFFFFu) EmitAndRegImm32(cursor, kEax, mask);
    EmitCmpRegBaseDisp32(cursor, kEax, kMmuReg, mmu_disp);
    EmitMovBaseDisp32Reg(cursor, kMmuReg, mmu_disp, kEax);   /* store (keeps flags) */
    uint8_t* same = EmitJzLabel(cursor);                     /* unchanged → no flush */
    EmitMovRegImm32(cursor, kEcx,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::ContextSwitchFlushHelper));
    FixupLabel(same, cursor);
    return cursor;
}

}  // namespace

/* Shared cp15 MRC / MCR emit body — CRn dispatch common across the
   ARMv4T..v7 cores supported today. Per-CPU concretes intercept any
   register whose semantics diverge before delegating here. */
uint8_t* EmitCp15RegisterTransfer(uint8_t*      cursor,
                                  DecodedInsn*  d,
                                  BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    const int32_t rd_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u);

    switch (d->crn) {
    case 0:
        if (jit->ProcessorConfig()->HasCp15V7() && d->cp_opc == 1 &&
            d->crm == 0 && d->l) {
            /* MRC p15, 1, Rt, c0, c0, {0,1}. op2=0 → CCSIDR (depends
               on current CSSELR, dispatch through ArmMmu helper);
               op2=1 → CLIDR (constant baked from ProcessorConfig). */
            if (d->cp == 0) {
                /* CcsidrLookupHelper __fastcall(ArmMmu*) — ECX = the
                   ArmMmu service pointer, NOT kMmuReg (which holds
                   ArmMmuState* and would make mmu->emu_ read garbage). */
                EmitMovRegImm32(cursor, kEcx,
                    static_cast<uint32_t>(
                        reinterpret_cast<uintptr_t>(jit->Mmu())));
                EmitCall(cursor,
                    reinterpret_cast<void*>(&ArmMmu::CcsidrLookupHelper));
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else if (d->cp == 1) {
                EmitMovBaseDisp32Imm32(cursor, kStateReg, rd_disp,
                    jit->ProcessorConfig()->Clidr());
            } else {
                cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
            }
        } else if (jit->ProcessorConfig()->HasCp15V7() && d->cp_opc == 2 &&
                   d->crm == 0 && d->cp == 0) {
            /* MRC/MCR p15, 2, Rt, c0, c0, 0 — CSSELR R/W. Per-CPU
               mutable state stored in ArmMmuState::cssel_register.
               Source: QEMU helper.c:948-955 (PL1_RW, .resetvalue=0,
               banked storage). */
            const int32_t csselr_disp =
                static_cast<int32_t>(offsetof(ArmMmuState, cssel_register));
            if (d->l) {
                EmitMovRegBaseDisp32(cursor, kEax, kMmuReg, csselr_disp);
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                EmitMovBaseDisp32Reg(cursor, kMmuReg, csselr_disp, kEax);
            }
        } else if (d->cp_opc == 0 && d->crm == 0) {
            /* Legacy MIDR/CTR path. Both read-only constants pulled
               from ArmProcessorConfig so the per-SoC strategy owns
               them rather than the JIT body. */
            if (d->l) {
                if (d->cp == 0) {
                    EmitMovBaseDisp32Imm32(cursor, kStateReg, rd_disp,
                        jit->ProcessorConfig()->Midr());
                } else if (d->cp == 1) {
                    EmitMovBaseDisp32Imm32(cursor, kStateReg, rd_disp,
                        jit->ProcessorConfig()->Ctr());
                } else {
                    cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
                }
            } else {
                /* Writes to op1=0/CP=0/CP=1 are silently ignored on
                   real hardware; CP>1 UND-faults. */
                if (d->cp > 1) {
                    cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
                }
            }
        } else {
            /* Anything not covered above (e.g. op1=3/4/5/6/7 reads,
               or a v7-only op1 on a pre-v7 chip) raises UND. */
            cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        }
        break;

    case 1:
        if (d->l) {
            if (d->cp == 0) {
                EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
                    static_cast<int32_t>(offsetof(ArmMmuState, control_register)));
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else if (d->cp == 1) {
                EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
                    static_cast<int32_t>(offsetof(ArmMmuState, aux_control_register)));
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else if (d->cp == 2 && jit->ProcessorConfig()->HasCp15V6() &&
                       d->cp_opc == 0 && d->crm == 0) {
                EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
                    static_cast<int32_t>(offsetof(ArmMmuState, coprocessor_access)));
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else {
                cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
                break;
            }
        } else {
            if (d->cp == 0) {
                EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, rd_disp);
                EmitMovRegImm32(cursor, kEdx, d->guest_address);
                EmitCall(cursor, ctx->sctlr_write_target);
            } else if (d->cp == 1) {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                EmitMovBaseDisp32Reg(cursor, kMmuReg,
                    static_cast<int32_t>(offsetof(ArmMmuState, aux_control_register)), kEax);
            } else if (d->cp == 2 && jit->ProcessorConfig()->HasCp15V6() &&
                       d->cp_opc == 0 && d->crm == 0) {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                EmitMovBaseDisp32Reg(cursor, kMmuReg,
                    static_cast<int32_t>(offsetof(ArmMmuState, coprocessor_access)), kEax);
            } else {
                cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
            }
        }
        break;

    case 2: {
        /* Register 2 — Translation Table Base 0/1 + control. v7 adds TTBR1
           (op2=1) and TTBCR (op2=2) at the same CRn=2. */
        const int32_t ttbr0_disp =
            static_cast<int32_t>(offsetof(ArmMmuState, translation_table_base));
        if (jit->ProcessorConfig()->HasCp15V6() &&
            (d->cp == 1 || d->cp == 2)) {
            const int32_t disp = (d->cp == 1)
                ? static_cast<int32_t>(offsetof(ArmMmuState, ttbr1))
                : static_cast<int32_t>(offsetof(ArmMmuState, ttbcr));
            if (d->l) {
                EmitMovRegBaseDisp32(cursor, kEax, kMmuReg, disp);
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                EmitMovBaseDisp32Reg(cursor, kMmuReg, disp, kEax);
            }
            break;
        }
        /* TTBR0 write accepts any value; the walker masks to bits[31:14] on
           use. Do NOT re-tighten here — it UND-faults legitimate kernel
           sentinel writes (observed R1=0xFFFFFFFF). A TTBR0 change is a
           process switch → flush the VA-keyed caches (not the TC). */
        if (d->l) {
            EmitMovRegBaseDisp32(cursor, kEax, kMmuReg, ttbr0_disp);
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
        } else if (jit->ProcessorConfig()->HasCp15V7()) {
            cursor = EmitFieldWriteContextSwitch(cursor, jit, rd_disp, ttbr0_disp,
                                                 0xFFFFFFFFu);
        } else {
            EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, rd_disp);
            EmitMovRegReg(cursor, kEax, kEcx);
            EmitAndRegImm32(cursor, kEax, 0x00003FFFu);
            uint8_t* raise_label = EmitJnzLabel(cursor);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
            EmitCall(cursor,
                reinterpret_cast<void*>(&ArmJit::MapGuestPhysicalToHostRamHelper));
            EmitTestRegReg(cursor, kEax, kEax);
            uint8_t* store_label = EmitJnzLabel(cursor);
            FixupLabel(raise_label, cursor);
            cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
            FixupLabel(store_label, cursor);
            cursor = EmitFieldWriteContextSwitch(cursor, jit, rd_disp, ttbr0_disp,
                                                 0xFFFFFFFFu);
        }
        break;
    }

    case 3: {
        /* DACR domain-0 field must be Client(0b01) or Manager(0b11): the
           walker enforces AP for Client and skips it for Manager. bit0
           clear = No-access/reserved → UND (can't be honored). Other
           domains' fields are unused (the walk faults non-zero domains). */
        if (d->l) {
            EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, domain_access_control)));
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
        } else {
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
            EmitTestRegImm32(cursor, kEax, 1u);
            uint8_t* store_label = EmitJnzLabel(cursor);
            cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
            FixupLabel(store_label, cursor);
            EmitMovBaseDisp32Reg(cursor, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, domain_access_control)), kEax);
            /* Flush both TLBs: a DACR change alters live AP enforcement, but the
               inline fast path trusts the install-time permission, so a stale
               entry would keep using the old domain access. */
            EmitLeaRegBaseDisp32(cursor, kEax, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, data_tlb)));
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmTlbFlushAll));
            EmitAddRegImm32(cursor, kEsp, 4);
            EmitLeaRegBaseDisp32(cursor, kEax, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, instruction_tlb)));
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmTlbFlushAll));
            EmitAddRegImm32(cursor, kEsp, 4);
        }
        break;
    }

    case 4:
        cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        break;

    case 5:
        /* Register 5 — Fault Status Register. Direct read/write. */
        if (d->l) {
            EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, fault_status)));
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
        } else {
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
            EmitMovBaseDisp32Reg(cursor, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, fault_status)), kEax);
        }
        break;

    case 6:
        /* Register 6 — Fault Address Register. Direct read/write. */
        if (d->l) {
            EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, fault_address)));
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
        } else {
            EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
            EmitMovBaseDisp32Reg(cursor, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, fault_address)), kEax);
        }
        break;

    case 7:
        cursor = EmitCp15CacheOp(cursor, d, ctx);
        break;

    case 8:
        cursor = EmitCp15TlbOp(cursor, d, ctx);
        break;

    case 9:
        /* Cache / TLB lockdown — not modeled. */
        cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        break;

    case 10: {
        /* PRRR/NMRR storage only valid while SCTLR.TRE=0 — if TRE
           becomes 1, walker must consult these or attributes diverge. */
        if (jit->ProcessorConfig()->HasCp15V6() && d->cp_opc == 0 &&
            d->crm == 2 && (d->cp == 0 || d->cp == 1)) {
            const int32_t disp = (d->cp == 0)
                ? static_cast<int32_t>(offsetof(ArmMmuState, prrr))
                : static_cast<int32_t>(offsetof(ArmMmuState, nmrr));
            if (d->l) {
                EmitMovRegBaseDisp32(cursor, kEax, kMmuReg, disp);
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                EmitMovBaseDisp32Reg(cursor, kMmuReg, disp, kEax);
            }
        } else {
            cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        }
        break;
    }

    case 11:
    case 12:
        cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        break;

    case 13: {
        if (jit->ProcessorConfig()->HasCp15V6() &&
            d->cp >= 1 && d->cp <= 4) {
            int32_t disp = 0;
            switch (d->cp) {
            case 1: disp = static_cast<int32_t>(offsetof(ArmMmuState, contextidr)); break;
            case 2: disp = static_cast<int32_t>(offsetof(ArmMmuState, tpidrurw));   break;
            case 3: disp = static_cast<int32_t>(offsetof(ArmMmuState, tpidruro));   break;
            case 4: disp = static_cast<int32_t>(offsetof(ArmMmuState, tpidrprw));   break;
            }
            if (d->l) {
                EmitMovRegBaseDisp32(cursor, kEax, kMmuReg, disp);
                EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
            } else if (d->cp == 1) {
                /* CONTEXTIDR[7:0] is the ASID — an address-space switch. */
                cursor = EmitFieldWriteContextSwitch(cursor, jit, rd_disp, disp,
                                                     0xFFFFFFFFu);
            } else {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
                EmitMovBaseDisp32Reg(cursor, kMmuReg, disp, kEax);
            }
            break;
        }
        if (d->l) {
            EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, process_id)));
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
        } else {
            /* FCSE PID = bits[31:25] (ARM1136 TRM §3.3.35); [24:0] SBZ, ignored
               not faulted. Mask so the walker's `p |= process_id` fold is right.
               PID reuse is the stale-block trigger → context-switch flush. */
            cursor = EmitFieldWriteContextSwitch(cursor, jit, rd_disp,
                static_cast<int32_t>(offsetof(ArmMmuState, process_id)),
                0xFE000000u);
        }
        break;
    }

    case 14:
        /* Breakpoint registers — not modeled. */
        cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        break;

    case 15:
    default:
        cursor = EmitRaiseUndAndReturn(cursor, d, ctx);
        break;
    }

    return cursor;
}
