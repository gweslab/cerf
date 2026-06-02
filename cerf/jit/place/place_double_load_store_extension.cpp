#include <cstddef>
#include <cstdint>
#include <cstring>

#include "../../cpu/arm_processor_config.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"
#include "../x86_emit_mmx.h"

uint8_t* PlaceDoubleLoadStoreExtension(uint8_t*      cursor,
                                       DecodedInsn*  d,
                                       BlockContext* ctx) {
    using namespace x86;
    ArmJit*               jit        = ctx->jit;
    ArmMmu*               mmu        = jit->Mmu();
    ArmProcessorConfig*   cfg        = jit->ProcessorConfig();
    PeripheralDispatcher* peripheral = jit->Peripheral();

    const bool     mmu_on             = mmu->State()->control_register.bits.m;
    const bool     alignment_check_on = mmu->State()->control_register.bits.a;
    const bool     base_restored      = cfg->BaseRestoredAbortModel();
    const bool     mem_before_wb      = cfg->MemoryBeforeWritebackModel();
    const bool     thumb              = jit->CpuState()->cpsr.bits.thumb_mode;

    const int32_t rn_disp    =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4u);
    const int32_t rm_disp    =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rm * 4u);
    const int32_t rd_disp    =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u);
    const int32_t rd1_disp   =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + (d->rd + 1u) * 4u);

    bool needs_alignment_check = true;

    /* === EA compute === */
    if (d->i == 0) {
        /* Register offset. */
        const uint32_t pc_val = d->guest_address + (thumb ? 4u : 8u);
        if (d->rn == ArmGpr::kR15) {
            EmitMovRegImm32(cursor, kEcx, pc_val);
        } else {
            EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, rn_disp);
        }
        if (d->p) {  /* Pre-index */
            if (d->u) {
                if (d->rm == ArmGpr::kR15) {
                    EmitAddRegImm32(cursor, kEcx, pc_val);
                } else {
                    EmitAddRegBaseDisp32(cursor, kEcx, kStateReg, rm_disp);
                }
            } else {
                if (d->rm == ArmGpr::kR15) {
                    EmitSubRegImm32(cursor, kEcx, pc_val);
                } else {
                    EmitSubRegBaseDisp32(cursor, kEcx, kStateReg, rm_disp);
                }
            }
        }
    } else {
        /* Immediate offset. */
        if (d->rn == ArmGpr::kR15) {
            uint32_t inst_ptr = d->guest_address + (thumb ? 4u : 8u);
            if (d->p) {
                inst_ptr = d->u ? (inst_ptr + d->offset)
                                : (inst_ptr - d->offset);
            }
            EmitMovRegImm32(cursor, kEcx, inst_ptr);
            if ((inst_ptr & 7u) == 0u) {
                /* Statically 8-byte-aligned — drop the runtime check. */
                needs_alignment_check = false;
            }
        } else {
            EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, rn_disp);
            if (d->p) {
                if (d->u) {
                    EmitAddRegImm32(cursor, kEcx, static_cast<uint32_t>(d->offset));
                } else {
                    EmitSubRegImm32(cursor, kEcx, static_cast<uint32_t>(d->offset));
                }
            }
        }
    }

    /* Preserve EA in EBP for writeback (EBP survives the MMU CALL). */
    if (d->w) {
        EmitMovRegReg(cursor, kEbp, kEcx);
    }

    if (needs_alignment_check && !alignment_check_on) {
        /* SCTLR.A off — round EA down to 8-byte alignment so STRD
           matches the reference's chosen behavior. AND ECX, ~7. */
        EmitAndRegImm32(cursor, kEcx, ~uint32_t{7});
    }

    /* === MMU translate === */
    if (mmu_on) {
        cursor = EmitTlbFastPath(cursor, ctx,
                                 d->l ? TlbAccess::kRead : TlbAccess::kWrite);
    } else {
        /* MMU off — direct PA→host. ECX holds the PA. */
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmJit::MapGuestPhysicalToHostHelper));
    }

    /* === Post-index writeback compute === */
    if (d->w && d->p == 0) {
        const uint32_t pc_val = d->guest_address + (thumb ? 4u : 8u);
        if (d->i == 0) {
            if (d->u) {
                if (d->rm == ArmGpr::kR15) {
                    EmitAddRegImm32(cursor, kEbp, pc_val);
                } else {
                    EmitAddRegBaseDisp32(cursor, kEbp, kStateReg, rm_disp);
                }
            } else {
                if (d->rm == ArmGpr::kR15) {
                    EmitSubRegImm32(cursor, kEbp, pc_val);
                } else {
                    EmitSubRegBaseDisp32(cursor, kEbp, kStateReg, rm_disp);
                }
            }
        } else {
            if (d->u) {
                EmitAddRegImm32(cursor, kEbp, static_cast<uint32_t>(d->offset));
            } else {
                EmitSubRegImm32(cursor, kEbp, static_cast<uint32_t>(d->offset));
            }
        }
    }

    /* Base-Updated abort model: writeback BEFORE the abort test. */
    if (!base_restored) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
        }
    }

    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* abort_or_io = EmitJzLabel(cursor);

    /* === Memory fast path (MMX MOVQ + EMMS) === */
    uint8_t* raise_alignment_mem = nullptr;
    if (needs_alignment_check && alignment_check_on) {
        EmitTestRegImm32(cursor, kEax, 7u);
        raise_alignment_mem = EmitJnzLabel(cursor);
    }

    if (base_restored && !mem_before_wb) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
        }
    }

    if (d->l) {
        /* MOVQ MM0, [EAX]; MOVQ [ESI + gprs[Rd]], MM0; EMMS. */
        EmitMovqMmRegRegPtr(cursor, kMm0, kEax);
        EmitMovqBaseDisp32MmReg(cursor, kStateReg, rd_disp, kMm0);
    } else {
        /* MOVQ MM0, [ESI + gprs[Rd]]; MOVQ [EAX], MM0; EMMS. */
        EmitMovqMmRegBaseDisp32(cursor, kMm0, kStateReg, rd_disp);
        EmitMovqRegPtrMmReg(cursor, kEax, kMm0);
    }
    EmitEmms(cursor);
    uint8_t* load_store_done_mem = EmitJmpLabel(cursor);

    /* === IO fallback (two paired 32-bit transfers) === */
    FixupLabel(abort_or_io, cursor);
    EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* abort_label = EmitJzLabel(cursor);

    uint8_t* raise_alignment_io = nullptr;
    if (needs_alignment_check && alignment_check_on) {
        EmitTestRegImm32(cursor, kEax, 7u);
        raise_alignment_io = EmitJnzLabel(cursor);
    }

    if (base_restored && !mem_before_wb) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
        }
    }

    uint8_t* io_hint_imm_location1 = nullptr;
    uint8_t* io_hint_imm_location2 = nullptr;
    if (d->l) {
        /* First word into Rd. */
#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location1 = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadWord));
        EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
        /* ADD io_pending_address, 4 — advance to the second word. */
        EmitAddDwordPtrImm8(cursor, mmu->IoPendingAddressPtr(), 4);
        /* Second word into Rd+1. */
#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location2 = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadWord));
        EmitMovBaseDisp32Reg(cursor, kStateReg, rd1_disp, kEax);
    } else {
        /* First word from Rd — JitIoWriteWord(hint, peripheral, value)
           cdecl-on-stack value, fastcall ECX=hint EDX=peripheral. */
        EmitPushBaseDisp32(cursor, kStateReg, rd_disp);
#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location1 = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoWriteWord));
        /* Second word from Rd+1 — reference does NOT advance
           io_pending_address on the store path; matching verbatim. */
        EmitPushBaseDisp32(cursor, kStateReg, rd1_disp);
#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location2 = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoWriteWord));
    }

    uint8_t* load_store_done_io = EmitJmpLabel(cursor);

    /* IO hint cache slot inline — both back-patched to one byte. */
    {
        const uint32_t slot_addr =
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cursor));
        std::memcpy(io_hint_imm_location1, &slot_addr, 4);
        std::memcpy(io_hint_imm_location2, &slot_addr, 4);
        Emit8(cursor, 0);
    }

    /* AbortException. */
    FixupLabel(abort_label, cursor);
    EmitMovRegImm32(cursor, kEcx, d->guest_address);
    EmitJmp32(cursor, ctx->raise_abort_data_helper_target);


    /* === UnalignedAccess tail === */
    if (needs_alignment_check && alignment_check_on) {
        FixupLabel(raise_alignment_mem, cursor);
        FixupLabel(raise_alignment_io,  cursor);
        /* RaiseAlignmentExceptionHelper is __cdecl(jit, va). The
           reference passes d->GuestAddress as the va arg here (the
           halfword path passes the EA; the Double path's choice
           diverges and CERF matches it verbatim). */
        EmitPush32(cursor, d->guest_address);
        EmitPush32(cursor,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmJit::RaiseAlignmentExceptionHelper));
        EmitAddRegImm32(cursor, kEsp, 8);
        EmitMovRegImm32(cursor, kEcx, d->guest_address);
        EmitJmp32(cursor, ctx->raise_abort_data_helper_target);
    }

    FixupLabel(load_store_done_mem, cursor);
    FixupLabel(load_store_done_io,  cursor);

    /* Final Base-Restored + MemoryBeforeWriteback writeback hook. */
    if (base_restored && mem_before_wb) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
        }
    }

    return cursor;
}
