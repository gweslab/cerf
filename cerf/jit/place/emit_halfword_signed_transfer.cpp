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

uint8_t* EmitHalfwordSignedTransfer(uint8_t*      cursor,
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
    const uint32_t pc_store_offset    = cfg->PcStoreOffset();
    const bool     thumb              = jit->CpuState()->cpsr.bits.thumb_mode;

    const int32_t rn_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4u);
    const int32_t rm_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rm * 4u);
    const int32_t rd_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u);

    /* LDRH / STRH need alignment check (halfword-aligned). LDRSB
       does not (single-byte). */
    bool needs_alignment_check = (d->h != 0);

    /* === EA compute === */
    if (d->reserved3 == 0) {
        /* Register offset: ECX = Rn (or PC+8) ± Rm (or PC+8). */
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
            if ((inst_ptr & 1u) == 0u) {
                /* Statically halfword-aligned — alignment fault
                   cannot fire, drop the runtime check. */
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
        /* SCTLR.A off — the reference rounds the EA down to halfword
           alignment (AND ECX, ~1) so STRH matches STR's byte sequence.
           Matching the reference's chosen behavior. */
        EmitAndRegImm32(cursor, kEcx, ~uint32_t{1});
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

    /* === Post-index writeback compute (still in EBP) === */
    if (d->w && d->p == 0) {
        const uint32_t pc_val = d->guest_address + (thumb ? 4u : 8u);
        if (d->reserved3 == 0) {
            /* Register-offset post-index. */
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
            /* Immediate-offset post-index. */
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

    /* === Memory fast path === */
    uint8_t* raise_alignment_mem = nullptr;
    if (needs_alignment_check && alignment_check_on) {
        EmitTestRegImm32(cursor, kEax, 1u);
        raise_alignment_mem = EmitJnzLabel32(cursor);
    }

    if (base_restored && !mem_before_wb) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
        }
    }

    if (d->l) {
        /* === Load === */
        if (d->h) {
            /* LDRH / LDRSH — halfword load. */
            if (d->s) {
                /* MOVSX EAX, WORD PTR [EAX] — 0F BF /r mod=00 r/m=EAX. */
                Emit8(cursor, 0x0F); Emit8(cursor, 0xBF);
                EmitModRmReg(cursor, 0, kEax, kEax);
            } else {
                /* MOVZX EAX, WORD PTR [EAX] — 0F B7 /r. */
                Emit8(cursor, 0x0F); Emit8(cursor, 0xB7);
                EmitModRmReg(cursor, 0, kEax, kEax);
            }
        } else {
            /* LDRSB — signed byte load. Decoder enforces d->s == 1
               for this encoding combination. */
            /* MOVSX EAX, BYTE PTR [EAX] — 0F BE /r. */
            Emit8(cursor, 0x0F); Emit8(cursor, 0xBE);
            EmitModRmReg(cursor, 0, kEax, kEax);
        }
        /* MOV [ESI + gprs[Rd]], EAX. */
        EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
    } else {
        /* === Store === */
        if (d->h) {
            /* STRH — halfword store. */
            if (d->rd == ArmGpr::kR15) {
                const uint16_t value = static_cast<uint16_t>(
                    d->guest_address + pc_store_offset);
                /* 66 C7 /0 mod=00 r/m=EAX imm16. */
                EmitSize16(cursor);
                Emit8(cursor, 0xC7);
                EmitModRmReg(cursor, 0, kEax, 0);
                Emit16(cursor, value);
            } else {
                /* MOV CX, WORD PTR [ESI + gprs[Rd]] — 0x66 prefix forces
                   a 16-bit load so the upper half of ECX stays zero
                   (matches the reference's byte-level encoding; the
                   store below writes only the low 16 bits anyway). */
                EmitSize16(cursor);
                EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, rd_disp);
                /* 66 89 /r mod=00 r/m=EAX reg=ECX — MOV WORD [EAX], CX. */
                EmitSize16(cursor);
                Emit8(cursor, 0x89);
                EmitModRmReg(cursor, 0, kEax, kEcx);
            }
        } else {
            /* Byte store path (mirror reference's handling of the
               L=0,H=0 encoding combination). */
            if (d->rd == ArmGpr::kR15) {
                const uint8_t value = static_cast<uint8_t>(
                    d->guest_address + pc_store_offset);
                /* MOV BYTE [EAX], imm8 — C6 /0 mod=00 r/m=EAX. */
                Emit8(cursor, 0xC6);
                EmitModRmReg(cursor, 0, kEax, 0);
                Emit8(cursor, value);
            } else {
                /* MOV CL, BYTE PTR [ESI + gprs[Rd]]. */
                EmitMovByteRegBaseDisp32(cursor, kCl, kStateReg, rd_disp);
                /* MOV BYTE [EAX], CL — 88 /r mod=00 r/m=EAX. */
                Emit8(cursor, 0x88);
                EmitModRmReg(cursor, 0, kEax, kCl);
            }
        }
    }

    uint8_t* load_store_done_mem = nullptr;
    if (d->r15_modified) {
        if (base_restored && mem_before_wb) {
            if (d->w) {
                EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
            }
        }
        cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
    } else {
        load_store_done_mem = EmitJmpLabel(cursor);
    }

    /* === IO fallback === */
    FixupLabel(abort_or_io, cursor);
    EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* abort_label = EmitJzLabel(cursor);

    uint8_t* raise_alignment_io = nullptr;
    if (needs_alignment_check && alignment_check_on) {
        EmitTestRegImm32(cursor, kEax, 1u);
        /* rel32: same span budget as the mem-path JNZ above. */
        raise_alignment_io = EmitJnzLabel32(cursor);
    }

    if (base_restored && mem_before_wb) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
        }
    }

    uint8_t* io_hint_imm_location = nullptr;
    if (d->l) {
        /* IO load. */
        if (d->h) {
            /* JitIoReadHalf(hint, peripheral) — fastcall, returns AX. */
#if CERF_DEV_MODE
            EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
            Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
            io_hint_imm_location = cursor;
            Emit32(cursor, 0);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
            EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadHalf));
            if (d->s) {
                /* MOVSX ECX, AX — 0F BF /r mod=11 r/m=EAX reg=ECX. */
                Emit8(cursor, 0x0F); Emit8(cursor, 0xBF);
                EmitModRmReg(cursor, 3, kEax, kEcx);
            } else {
                /* MOVZX ECX, AX — 0F B7 /r mod=11. */
                Emit8(cursor, 0x0F); Emit8(cursor, 0xB7);
                EmitModRmReg(cursor, 3, kEax, kEcx);
            }
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEcx);
        } else {
            /* JitIoReadByte returns AL. */
#if CERF_DEV_MODE
            EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
            Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
            io_hint_imm_location = cursor;
            Emit32(cursor, 0);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
            EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadByte));
            /* MOVSX ECX, AL — 0F BE /r mod=11 r/m=EAX reg=ECX. */
            Emit8(cursor, 0x0F); Emit8(cursor, 0xBE);
            EmitModRmReg(cursor, 3, kEax, kEcx);
            EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEcx);
        }
    } else {
        /* IO store. */
        if (d->h) {
            /* JitIoWriteHalf(hint, peripheral, value). */
            if (d->rd == ArmGpr::kR15) {
                const uint16_t value = static_cast<uint16_t>(
                    d->guest_address + pc_store_offset);
                EmitMovRegImm32(cursor, kEcx, value);
            } else {
                /* MOVZX ECX, WORD PTR [ESI + gprs[Rd]] — 0F B7 /r
                   mod=10 (base+disp32) r/m=ESI reg=ECX. */
                Emit8(cursor, 0x0F); Emit8(cursor, 0xB7);
                EmitModRmReg(cursor, 2, kStateReg, kEcx);
                Emit32(cursor, static_cast<uint32_t>(rd_disp));
            }
            EmitPushReg(cursor, kEcx);
#if CERF_DEV_MODE
            EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
            Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
            io_hint_imm_location = cursor;
            Emit32(cursor, 0);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
            EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoWriteHalf));
        } else {
            /* JitIoWriteByte. */
            if (d->rd == ArmGpr::kR15) {
                const uint8_t value = static_cast<uint8_t>(
                    d->guest_address + pc_store_offset);
                EmitMovRegImm32(cursor, kEcx, value);
            } else {
                /* MOVZX ECX, BYTE PTR [ESI + gprs[Rd]] — 0F B6 /r mod=10. */
                Emit8(cursor, 0x0F); Emit8(cursor, 0xB6);
                EmitModRmReg(cursor, 2, kStateReg, kEcx);
                Emit32(cursor, static_cast<uint32_t>(rd_disp));
            }
            EmitPushReg(cursor, kEcx);
#if CERF_DEV_MODE
            EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
            Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
            io_hint_imm_location = cursor;
            Emit32(cursor, 0);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
            EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoWriteByte));
        }
    }

    uint8_t* load_store_done_io = nullptr;
    if (d->r15_modified) {
        if (base_restored && mem_before_wb) {
            if (d->w) {
                EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
            }
        }
        cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
    } else {
        load_store_done_io = EmitJmpLabel(cursor);
    }

    /* AbortException — MOV ECX, guest_pc; JMP raise_abort_data_helper. */
    FixupLabel(abort_label, cursor);
    EmitMovRegImm32(cursor, kEcx, d->guest_address);
    EmitJmp32(cursor, ctx->raise_abort_data_helper_target);

    /* IO hint cache slot inline. */
    {
        const uint32_t slot_addr =
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cursor));
        std::memcpy(io_hint_imm_location, &slot_addr, 4);
        Emit8(cursor, 0);
    }

    /* === UnalignedAccess tail === */
    if (needs_alignment_check && alignment_check_on) {
        FixupLabel32(raise_alignment_mem, cursor);
        FixupLabel32(raise_alignment_io,  cursor);
        EmitPushReg(cursor, kEbp);
        EmitPush32(cursor,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmJit::RaiseAlignmentExceptionHelper));
        EmitAddRegImm32(cursor, kEsp, 8);
        EmitMovRegImm32(cursor, kEcx, d->guest_address);
        EmitJmp32(cursor, ctx->raise_abort_data_helper_target);
    }

    if (!d->r15_modified) {
        FixupLabel(load_store_done_mem, cursor);
        FixupLabel(load_store_done_io,  cursor);
    }

    /* Final Base-Restored + MemoryBeforeWriteback writeback hook. */
    if (base_restored && mem_before_wb) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg, rn_disp, kEbp);
        }
    }

    return cursor;
}
