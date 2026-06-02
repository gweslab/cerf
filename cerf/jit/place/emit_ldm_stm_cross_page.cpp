#include <cstddef>

#include "../arm_cpu.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* EmitLdmStmCrossPage(uint8_t*                    cursor,
                             DecodedInsn*                d,
                             BlockContext*               ctx,
                             const PbdtCrossPageInputs&  in,
                             PbdtCrossPageOutputs*       out) {
    using namespace x86;

    ArmJit* jit = ctx->jit;
    ArmMmu* mmu = jit->Mmu();

    FixupLabel32(in.possibly_two_pages, cursor);
    /* On entry: EAX = BytesOnStartPage, EBP = StartHostAddress,
       EDX = EffectiveAddress. */

    /* LEA ECX, [EBP + EAX] — EBP-as-base requires mod>=01, so use
       mod=01 disp8=0. */
    Emit8(cursor, 0x8D);
    EmitModRmReg(cursor, 1, 4, kEcx);
    EmitSib(cursor, 0, kEax, kEbp);
    Emit8(cursor, 0);
    EmitMovDwordPtrReg(cursor, jit->StartPageHostAddressEndPtr(), kEcx);
    EmitMovRegDwordPtr(cursor, kEcx, jit->StartIoAddressPtr());
    /* ADD ECX, EAX — 03 /r mod=11. */
    Emit8(cursor, 0x03); EmitModRmReg(cursor, 3, kEax, kEcx);
    EmitMovDwordPtrReg(cursor, jit->StartPageIoAddressEndPtr(), kEcx);
    /* LEA ECX, [EDX + EAX] — SIB ss=00 index=EAX base=EDX. */
    Emit8(cursor, 0x8D);
    EmitModRmReg(cursor, 0, 4, kEcx);
    EmitSib(cursor, 0, kEax, kEdx);
    EmitPushReg(cursor, kEdx);  /* preserve EDX = EA across C call */
    if (!in.alignment_check_on) {
        EmitAndRegImm32(cursor, kEcx, ~uint32_t{3});
    }

    cursor = EmitTlbFastPath(cursor, ctx,
                             d->l ? TlbAccess::kRead : TlbAccess::kWrite);

    EmitPopReg(cursor, kEdx);
    EmitTestRegReg(cursor, kEax, kEax);
    EmitMovDwordPtrReg(cursor, jit->NextPageHostAddressPtr(), kEax);
    uint8_t* no_abort_two_page = EmitJnzLabel(cursor);
    EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
    EmitTestRegReg(cursor, kEax, kEax);
    EmitJzBack(cursor, in.abort_destination);
    EmitMovDwordPtrReg(cursor, jit->NextPageIoAddressPtr(), kEax);
    FixupLabel(no_abort_two_page, cursor);

    if (in.alignment_check_on) {
        EmitTestRegImm32(cursor, kEdx, 3);
        EmitJnzBack(cursor, in.raise_unaligned);
    }

    /* TEST EBP, EBP — Is StartHostAddress == 0 (IO path)? */
    Emit8(cursor, 0x85); EmitModRmReg(cursor, 3, kEbp, kEbp);
    /* MOV EDX, StartPageHostAddressEnd (for the CMOVE below). */
    EmitMovRegDwordPtr(cursor, kEdx, jit->StartPageHostAddressEndPtr());
    out->perform_io_transfer_multiple = EmitJzLabel32(cursor);

    bool first_register = true;
    bool first_store    = true;
    for (int reg_num = 0; reg_num <= 15; ++reg_num) {
        if ((d->register_list & (1u << reg_num)) == 0) continue;

        if (first_register) {
            first_register = false;
        } else {
            EmitAddRegImm32(cursor, kEbp, 4);
        }
        /* CMP EDX, EBP — 3B /r mod=11 reg=EDX rm=EBP. Computes EDX-EBP;
           only ZF is consumed by the next CMOVE, but the byte form
           matches the reference's CMP r32, r/m32 encoding. */
        Emit8(cursor, 0x3B); EmitModRmReg(cursor, 3, kEbp, kEdx);
        /* CMOVE EBP, [&NextPageHostAddress] — 0F 44 mod=00 r/m=5
           (disp32) reg=EBP, then disp32. */
        Emit8(cursor, 0x0F); Emit8(cursor, 0x44);
        EmitModRmReg(cursor, 0, 5, kEbp);
        EmitPtr(cursor, jit->NextPageHostAddressPtr());

        if (d->l) {
            if (d->s && (d->register_list & 0x8000u) == 0 &&
                reg_num >= 8 && reg_num < 15) {
                EmitMovRegImm32(cursor, kEcx, static_cast<uint32_t>(reg_num));
                EmitCall(cursor, ctx->block_usermode_helper_target);
                Emit8(cursor, 0x8B); EmitModRmReg(cursor, 1, kEbp, kEax); Emit8(cursor, 0);
                Emit8(cursor, 0x89); EmitModRmReg(cursor, 0, kEcx, kEax);
            } else if (reg_num == 15) {
                if (d->s) {
                    EmitPushBaseDisp32(cursor, kStateReg,
                        static_cast<int32_t>(offsetof(ArmCpuState, spsr)));
                    EmitPush32(cursor,
                        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Cpu())));
                    EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::UpdateCpsrWithFlagsHelper));
                    EmitAddRegImm32(cursor, kEsp, 8);
                }
                Emit8(cursor, 0x8B); EmitModRmReg(cursor, 1, kEbp, kEax); Emit8(cursor, 0);
                EmitMovRegImm32(cursor, kEdx, ~uint32_t{1});
                EmitMovRegImm32(cursor, kEcx, ~uint32_t{3});
                Emit8(cursor, 0xF7);
                EmitModRmReg(cursor, 2, kStateReg, 0);
                Emit32(cursor,
                    static_cast<uint32_t>(offsetof(ArmCpuState, cpsr)));
                Emit32(cursor, 0x20u);
                Emit8(cursor, 0x0F); Emit8(cursor, 0x45);
                EmitModRmReg(cursor, 3, kEdx, kEcx);
                Emit8(cursor, 0x23);
                EmitModRmReg(cursor, 3, kEcx, kEax);
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u),
                    kEax);
                if (d->rn == ArmGpr::kR13 && d->p == 0 && d->w && d->u) {
                    EmitJmp32(cursor, ctx->pop_shadow_stack_helper_target);
                } else {
                    cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
                }
            } else {
                Emit8(cursor, 0x8B); EmitModRmReg(cursor, 1, kEbp, kEax); Emit8(cursor, 0);
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + reg_num * 4),
                    kEax);
            }
        } else {
            /* Store */
            if (d->s && reg_num >= 8 && reg_num < 15) {
                EmitMovRegImm32(cursor, kEcx, static_cast<uint32_t>(reg_num));
                EmitCall(cursor, ctx->block_usermode_helper_target);
                Emit8(cursor, 0x8B); EmitModRmReg(cursor, 0, kEcx, kEax);
            } else if (reg_num == 15) {
                EmitMovRegImm32(cursor, kEax,
                    d->guest_address + in.pc_store_offset);
            } else {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + reg_num * 4));
            }
            Emit8(cursor, 0x89); EmitModRmReg(cursor, 1, kEbp, kEax); Emit8(cursor, 0);
            if (first_store && d->w) {
                /* In-loop writeback commit on first store iteration —
                   commits gprs[Rn] = EndEffectiveAddress so STMDB SP!,{regs}
                   landing across a 1KB host-page boundary still updates SP
                   to its post-instruction value. */
                EmitMovRegDwordPtr(cursor, kEax, jit->EndEffectiveAddressPtr());
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                    kEax);
                first_store = false;
            }
        }
    }
    out->done_instruction_2 = EmitJmpLabel32(cursor);
    return cursor;
}
