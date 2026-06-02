#include <cstddef>

#include "../../core/log.h"
#include "../../cpu/arm_processor_config.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

namespace {

/* Count set bits in the LDM/STM RegisterList. */
inline uint8_t PopCount16(uint16_t bits) {
    uint8_t count = 0;
    for (; bits; bits >>= 1) count += static_cast<uint8_t>(bits & 1u);
    return count;
}

}  /* namespace */

uint8_t* PlaceBlockDataTransfer(uint8_t*      cursor,
                                DecodedInsn*  d,
                                BlockContext* ctx) {
    using namespace x86;

    ArmJit*               jit         = ctx->jit;
    ArmMmu*               mmu         = jit->Mmu();
    ArmProcessorConfig*   cfg         = jit->ProcessorConfig();

    const bool fBaseRestoredAbortModel = cfg->BaseRestoredAbortModel();
    const uint32_t pc_store_offset     = cfg->PcStoreOffset();
    const bool mmu_on                  = mmu->State()->control_register.bits.m;
    const bool alignment_check_on      = mmu->State()->control_register.bits.a;

    if (d->rn == ArmGpr::kR15) {
        LOG(Caution,
            "PlaceBlockDataTransfer: Rn == R15 at guest pc=0x%08X\n",
            d->guest_address);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    const uint8_t block_size =
        static_cast<uint8_t>(PopCount16(d->register_list) * 4u);


    uint8_t* abort_destination       = nullptr;
    uint8_t* raise_unaligned         = nullptr;

    /* Phase 1: compute StartAddress into EBP and (when writeback)
       the EndEffectiveAddress value into EAX. */
    if (d->u) {
        EmitMovRegBaseDisp32(cursor, kEbp, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4));
        if (d->p) {
            /* Increment-Before: Start = Rn+4, End = Rn+blocksize. */
            if (d->w) {
                /* LEA EAX, [EBP + blocksize] — 8D /r mod=01 r/m=EBP(5) reg=EAX disp8. */
                Emit8(cursor, 0x8D);
                EmitModRmReg(cursor, 1, kEbp, kEax);
                Emit8(cursor, block_size);
            }
            EmitAddRegImm32(cursor, kEbp, 4);
        } else {
            /* Increment-After: Start = Rn, End = Rn+blocksize-4. */
            if (d->w) {
                Emit8(cursor, 0x8D);
                EmitModRmReg(cursor, 1, kEbp, kEax);
                Emit8(cursor, block_size);
            }
        }
    } else {
        EmitMovRegBaseDisp32(cursor, kEbp, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4));
        if (d->p) {
            /* Decrement-Before: Start = Rn-blocksize, End = Rn-4. */
            EmitAddRegImm32(cursor, kEbp, static_cast<uint32_t>(-static_cast<int32_t>(block_size)));
            if (d->w) {
                EmitMovRegReg(cursor, kEax, kEbp);
            }
        } else {
            /* Decrement-After: Start = Rn-blocksize+4, End = Rn. */
            EmitAddRegImm32(cursor, kEbp,
                static_cast<uint32_t>(-static_cast<int32_t>(block_size) + 4));
            if (d->w) {
                /* LEA EAX, [EBP - 4] — 8D /r mod=01 r/m=EBP(5) reg=EAX disp8=-4. */
                Emit8(cursor, 0x8D);
                EmitModRmReg(cursor, 1, kEbp, kEax);
                Emit8(cursor, static_cast<uint8_t>(-4));
            }
        }
    }

    if (d->w) {
        if (fBaseRestoredAbortModel) {
            EmitMovRegBaseDisp32(cursor, kEdx, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4));
            EmitMovDwordPtrReg(cursor, jit->BaseAbortValuePtr(), kEdx);
        } else {
            EmitMovDwordPtrReg(cursor, jit->BaseAbortValuePtr(), kEax);
        }
        if (d->l) {
            EmitMovBaseDisp32Reg(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                kEax);
        }
        EmitMovDwordPtrReg(cursor, jit->EndEffectiveAddressPtr(), kEax);
    } else {
        /* Even without writeback we stash the original Rn so the
           abort path restores it. */
        EmitMovRegBaseDisp32(cursor, kEdx, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4));
        EmitMovDwordPtrReg(cursor, jit->BaseAbortValuePtr(), kEdx);
    }

    /* MOV ECX, EBP (copy effective address to the helper-call
       argument register). */
    EmitMovRegReg(cursor, kEcx, kEbp);
    if (!alignment_check_on) {
        EmitAndRegImm32(cursor, kEcx, ~uint32_t{3});
    }
    if (mmu_on) {
        cursor = EmitTlbFastPath(cursor, ctx,
                                 d->l ? TlbAccess::kRead : TlbAccess::kWrite);
    } else {
        /* MMU off — direct PA→host. ECX holds the PA. */
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::MapGuestPhysicalToHostHelper));
    }

    /* TEST EAX, EAX; JNZ NoAbort (MMU translation succeeded). */
    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* no_abort_1 = EmitJnzLabel(cursor);

    /* MMU returned null. Check &io_pending_address_ — if non-zero,
       this is a peripheral access (route through IO path); if
       zero, this is a real abort (restore Rn + raise data abort). */
    EmitMovRegDwordPtr(cursor, kEcx, mmu->IoPendingAddressPtr());
    EmitMovDwordPtrReg(cursor, jit->StartIoAddressPtr(), kEcx);
    EmitTestRegReg(cursor, kEcx, kEcx);
    uint8_t* no_abort_2 = EmitJnzLabel(cursor);

    /* AbortDestination: restore Rn from BaseAbortValue + raise. */
    abort_destination = cursor;
    EmitMovRegDwordPtr(cursor, kEax, jit->BaseAbortValuePtr());
    EmitMovBaseDisp32Reg(cursor, kStateReg,
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
        kEax);
    EmitMovRegImm32(cursor, kEcx, d->guest_address);
    EmitJmp32(cursor, ctx->raise_abort_data_helper_target);

    /* RaiseUnaligned: alignment fault path. EDX holds EA on entry
       (set by the cross-page branch below; for the single-page
       case, no EA arrives here). */
    if (alignment_check_on) {
        raise_unaligned = cursor;
        EmitMovRegDwordPtr(cursor, kEax, jit->BaseAbortValuePtr());
        EmitMovBaseDisp32Reg(cursor, kStateReg,
            static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
            kEax);
        EmitMovRegReg(cursor, kEcx, kEdx);
        /* CALL RaiseAlignmentExceptionHelper(jit, va). cdecl, push
           args right-to-left, helper cleans 8 stack bytes. */
        EmitPushReg(cursor, kEcx);
        EmitPush32(cursor,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::RaiseAlignmentExceptionHelper));
        EmitAddRegImm32(cursor, kEsp, 8);
        EmitMovRegImm32(cursor, kEcx, d->guest_address);
        EmitJmp32(cursor, ctx->raise_abort_data_helper_target);
    }

    /* NoAbort labels — translation either succeeded (EAX !=0) or
       gave us an IO address in StartIOAddress. */
    FixupLabel(no_abort_1, cursor);
    FixupLabel(no_abort_2, cursor);

    uint8_t* possibly_two_pages = nullptr;
    if (mmu_on && block_size > 4u) {
        EmitMovRegReg(cursor, kEdx, kEbp);  /* EDX = EA */
        EmitMovRegReg(cursor, kEbp, kEax);  /* EBP = StartHostAddress */
        EmitMovRegReg(cursor, kEax, kEdx);  /* EAX = EA copy */
        EmitAndRegImm32(cursor, kEax, 1023);
        /* NEG EAX — F7 /3 ModRM(3, EAX, 3). */
        Emit8(cursor, 0xF7); EmitModRmReg(cursor, 3, kEax, 3);
        EmitAddRegImm32(cursor, kEax, 1024);
        EmitCmpRegImm32(cursor, kEax, block_size);
        possibly_two_pages = EmitJbLabel32(cursor);
    } else {
        EmitMovRegReg(cursor, kEbp, kEax);  /* EBP = StartHostAddress */
    }

    /* TEST EBP, EBP — Is StartHostAddress == 0 (IO path)?
       JZ rel32 to PerformIOBasedTransfer; the target sits past the
       full STM loop body + (if MMU on + block_size > 4) the cross-
       page emit, which routinely exceeds rel8 range. */
    Emit8(cursor, 0x85); EmitModRmReg(cursor, 3, kEbp, kEbp);
    uint8_t* perform_io_transfer = EmitJzLabel32(cursor);

    /* Memory-based LDM/STM single-page loop. EBP holds the start
       host address; we walk it +4 per included register. */
    uint8_t register_offset = 0;
    auto emit_register_pass = [&](int reg_num) {
        if (d->l) {
            /* Load */
            if (d->s && (d->register_list & 0x8000u) == 0 &&
                reg_num >= 8 && reg_num < 15) {
                EmitMovRegImm32(cursor, kEcx, static_cast<uint32_t>(reg_num));
                EmitCall(cursor, ctx->block_usermode_helper_target);
                /* MOV EAX, [EBP + register_offset] */
                Emit8(cursor, 0x8B);
                if (register_offset) {
                    EmitModRmReg(cursor, 1, kEbp, kEax);
                    Emit8(cursor, register_offset);
                } else {
                    EmitModRmReg(cursor, 1, kEbp, kEax);
                    Emit8(cursor, 0);
                }
                /* MOV [ECX], EAX */
                Emit8(cursor, 0x89);
                EmitModRmReg(cursor, 0, kEcx, kEax);
            } else if (reg_num == 15) {
                if (d->s) {
                    /* PUSH [ESI + offsetof(spsr)] */
                    EmitPushBaseDisp32(cursor, kStateReg,
                        static_cast<int32_t>(offsetof(ArmCpuState, spsr)));
                    EmitPush32(cursor,
                        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Cpu())));
                    EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::UpdateCpsrWithFlagsHelper));
                    EmitAddRegImm32(cursor, kEsp, 8);
                }
                /* MOV EAX, [EBP + register_offset] */
                Emit8(cursor, 0x8B);
                EmitModRmReg(cursor, 1, kEbp, kEax);
                Emit8(cursor, register_offset);
                /* MOV EDX, ~1; MOV ECX, ~3; TEST [ESI+cpsr], 0x20;
                   CMOVNZ ECX, EDX; AND EAX, ECX. Pick the PC mask
                   based on CPSR.T. */
                EmitMovRegImm32(cursor, kEdx, ~uint32_t{1});
                EmitMovRegImm32(cursor, kEcx, ~uint32_t{3});
                /* TEST DWORD PTR [ESI + offsetof(cpsr)], 0x20  —
                   F7 /0 mod=10 r/m=ESI(6) reg=0 disp32 imm32. */
                Emit8(cursor, 0xF7);
                EmitModRmReg(cursor, 2, kStateReg, 0);
                Emit32(cursor,
                    static_cast<uint32_t>(offsetof(ArmCpuState, cpsr)));
                Emit32(cursor, 0x20u);
                /* CMOVNZ ECX, EDX — 0F 45 mod=11 r/m=EDX reg=ECX. */
                Emit8(cursor, 0x0F); Emit8(cursor, 0x45);
                EmitModRmReg(cursor, 3, kEdx, kEcx);
                /* AND EAX, ECX — 23 mod=11 r/m=ECX reg=EAX. */
                Emit8(cursor, 0x23);
                EmitModRmReg(cursor, 3, kEcx, kEax);
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + 15u * 4u),
                    kEax);
                if (d->rn == ArmGpr::kR13 && d->p == 0 && d->w && d->u) {
                    /* LDM R13!, {... R15} up — likely a return. */
                    EmitJmp32(cursor, ctx->pop_shadow_stack_helper_target);
                } else {
                    cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
                }
            } else {
                /* MOV EAX, [EBP + register_offset] */
                Emit8(cursor, 0x8B);
                EmitModRmReg(cursor, 1, kEbp, kEax);
                Emit8(cursor, register_offset);
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + reg_num * 4),
                    kEax);
            }
        } else {
            /* Store */
            if (d->s && reg_num >= 8 && reg_num < 15) {
                EmitMovRegImm32(cursor, kEcx, static_cast<uint32_t>(reg_num));
                EmitCall(cursor, ctx->block_usermode_helper_target);
                /* MOV EAX, [ECX] — 8B /r mod=00 r/m=ECX reg=EAX. */
                Emit8(cursor, 0x8B);
                EmitModRmReg(cursor, 0, kEcx, kEax);
            } else if (reg_num == 15) {
                EmitMovRegImm32(cursor, kEax,
                    d->guest_address + pc_store_offset);
            } else {
                EmitMovRegBaseDisp32(cursor, kEax, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + reg_num * 4));
            }
            /* MOV [EBP + register_offset], EAX */
            Emit8(cursor, 0x89);
            EmitModRmReg(cursor, 1, kEbp, kEax);
            Emit8(cursor, register_offset);
            if (register_offset == 0 && d->w) {
                EmitMovRegDwordPtr(cursor, kEax, jit->EndEffectiveAddressPtr());
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                    kEax);
            }
        }
    };

    for (int reg_num = 0; reg_num <= 15; ++reg_num) {
        if (d->register_list & (1u << reg_num)) {
            emit_register_pass(reg_num);
            register_offset = static_cast<uint8_t>(register_offset + 4);
        }
    }
    uint8_t* done_instruction_1 = EmitJmpLabel32(cursor);

    /* Cross-page (PossiblyTwoPages) handler. Emitted only when MMU
       is on and we have more than one register. The handler issues
       a second MMU call for the next page and re-emits the
       register walk with CMOVE EBP between the two host pages. */
    uint8_t* done_instruction_2           = nullptr;
    uint8_t* perform_io_transfer_multiple = nullptr;
    if (mmu_on && block_size > 4u) {
        PbdtCrossPageInputs in;
        in.possibly_two_pages     = possibly_two_pages;
        in.abort_destination      = abort_destination;
        in.raise_unaligned        = raise_unaligned;
        in.block_size             = block_size;
        in.pc_store_offset        = pc_store_offset;
        in.alignment_check_on     = alignment_check_on;

        PbdtCrossPageOutputs out{};
        cursor = EmitLdmStmCrossPage(cursor, d, ctx, in, &out);
        perform_io_transfer_multiple = out.perform_io_transfer_multiple;
        done_instruction_2           = out.done_instruction_2;
    }

    /* PerformIOBasedTransfer: route through the IO helpers. */
    FixupLabel32(perform_io_transfer, cursor);
    if (d->w || d->s || (d->register_list & (1u << 15))) {
        /* Slow IO helper required. */
        uint32_t register_list_and_flags = d->register_list;
        if (d->s) register_list_and_flags |= kLdmStmS;
        if (d->l) register_list_and_flags |= kLdmStmLoad;
        if (d->w) register_list_and_flags |= kLdmStmW | (static_cast<uint32_t>(d->rn) << 24);
        EmitMovRegImm32(cursor, kEcx, register_list_and_flags);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        if (d->register_list & (1u << 15)) {
            /* Pass instruction_address on the stack (3rd __fastcall arg). */
            EmitPush32(cursor, d->guest_address);
        } else {
            EmitPush32(cursor, 0);
        }
        EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::BlockDataTransferIOHelperSlow));
        if (d->l && (d->register_list & (1u << 15))) {
            if (d->rn == ArmGpr::kR13 && d->p == 0 && d->w && d->u) {
                EmitJmp32(cursor, ctx->pop_shadow_stack_helper_target);
            } else {
                cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
            }
        }
    } else if (d->l) {
        EmitMovRegImm32(cursor, kEcx, d->register_list);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::BlockDataTransferIOLoadHelper));
    } else {
        EmitMovRegImm32(cursor, kEcx, d->register_list);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::BlockDataTransferIOStoreHelper));
    }
    uint8_t* done_instruction_3 = EmitJmpLabel32(cursor);

    /* PerformIOBasedTransferMultiple: cross-page IO. */
    if (mmu_on && block_size > 4u) {
        FixupLabel32(perform_io_transfer_multiple, cursor);
        uint32_t flags = d->register_list | kLdmStmSpans;
        if (d->s) flags |= kLdmStmS;
        if (d->l) flags |= kLdmStmLoad;
        EmitMovRegImm32(cursor, kEcx, flags);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        if (d->register_list & (1u << 15)) {
            EmitPush32(cursor, d->guest_address);
        } else {
            EmitPush32(cursor, 0);
        }
        EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::BlockDataTransferIOHelperSlow));
        if (d->l && (d->register_list & (1u << 15))) {
            if (d->rn == ArmGpr::kR13 && d->p == 0 && d->w && d->u) {
                EmitJmp32(cursor, ctx->pop_shadow_stack_helper_target);
            } else {
                cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
            }
        }
    }

    FixupLabel32(done_instruction_1, cursor);
    FixupLabel32(done_instruction_3, cursor);
    if (mmu_on && block_size > 4u) {
        FixupLabel32(done_instruction_2, cursor);
    }
    return cursor;
}
