#include <cstddef>

#include "../../cpu/arm_processor_config.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceSingleDataTransfer(uint8_t*      cursor,
                                 DecodedInsn*  d,
                                 BlockContext* ctx) {
    using namespace x86;

    ArmJit*               jit           = ctx->jit;
    ArmMmu*               mmu           = jit->Mmu();
    ArmProcessorConfig*   cfg           = jit->ProcessorConfig();
    PeripheralDispatcher* peripheral    = jit->Peripheral();

    const bool fBaseRestoredAbortModel       = cfg->BaseRestoredAbortModel();
    const bool fMemoryBeforeWritebackModel   = cfg->MemoryBeforeWritebackModel();
    const uint32_t pc_store_offset           = cfg->PcStoreOffset();
    const bool thumb                         = jit->CpuState()->cpsr.bits.thumb_mode;
    const bool mmu_on                        = mmu->State()->control_register.bits.m;
    const bool alignment_check_on            = mmu->State()->control_register.bits.a;

    /* The IO helper emits "MOV ECX, <imm32>" inline; the imm32 is back-patched
       to point at the 1-byte IO-hint cache slot at the end of the block. */
    uint8_t* io_hint_imm_location = nullptr;

    uint8_t* abort_exception_or_io      = nullptr;
    uint8_t* abort_exception            = nullptr;
    uint8_t* raise_alignment_exception  = nullptr;
    uint8_t* raise_alignment_exception2 = nullptr;
    bool fNeedsAlignmentCheck = false;
    bool fCacheHit            = false;

    /* Fast path: unconditional "LDR Rd, [PC + immediate]" within
       the same 1 KB page as a previous PC-relative LDR in this
       block. The previous LDR cached its resolved host EA in EDI;
       reuse it with only an ADD for the address delta. */
    if (d->rn == ArmGpr::kR15 && ctx->pc_cache_valid && d->cond == 14 &&
        d->p && d->b == 0 && d->w == 0 && d->l && d->i == 0) {
        const uint32_t inst_ptr = d->reserved3;
        if ((inst_ptr & ~uint32_t{0x3FF}) ==
            (ctx->pc_cache_guest_va & ~uint32_t{0x3FF})) {
            fCacheHit = true;
            /* MOV EAX, EDI  (cached PC host EA) */
            EmitMovRegReg(cursor, kEax, kEdi);
            EmitAddRegImm32(cursor, kEax, inst_ptr - ctx->pc_cache_guest_va);
            if (inst_ptr & 3u) {
                /* Address bits[1:0] non-zero — store the unaligned
                   guest EA in ECX for the post-load rotation path. */
                EmitMovRegImm32(cursor, kEcx, inst_ptr);
            }
        }
    }

    if (!fCacheHit) {
        cursor = PlaceSingleDataTransferOffset(cursor, d, ctx, &fNeedsAlignmentCheck);
        /* On return:
             ECX = EA for the load/store
             EBP = writeback EA (only when d->w or post-indexed) */

        if (fNeedsAlignmentCheck && !alignment_check_on) {
            /* Alignment check is off — for LDR, stash the unaligned
               EA so the post-load rotation can recover bits[1:0],
               then AND ECX to dword-align. */
            if (d->l) {
                /* MOV [&ldr_unaligned_guest_address_], ECX */
                EmitMovDwordPtrReg(cursor,
                    jit->LdrUnalignedGuestAddressPtr(), kEcx);
            }
            EmitAndRegImm32(cursor, kEcx, ~uint32_t{3});
        }

        if (mmu_on) {
            cursor = EmitTlbFastPath(cursor, ctx,
                                     d->l ? TlbAccess::kRead : TlbAccess::kWrite);
        } else {
            /* MMU off — direct PA→host. ECX already holds the PA
               (no virtual-to-physical translation needed); EDX
               carries jit per MapGuestPhysicalToHostHelper's
               __fastcall(paddr, jit) convention. */
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
            EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::MapGuestPhysicalToHostHelper));
        }

        if (!fBaseRestoredAbortModel) {
            /* Base-Updated abort model: writeback happens before
               testing for aborts. */
            if (d->w) {
                /* d->rn != R15 — writeback to R15 is unencoded
                   under ARM single-data-transfer writeback. */
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                    kEbp);
            }
        }

        /* TEST EAX, EAX — was the translation successful (returned
           a non-null host pointer)? */
        EmitTestRegReg(cursor, kEax, kEax);
        abort_exception_or_io = EmitJzLabel(cursor);

        /* Translation succeeded (EAX is a real host pointer).
           Alignment check if MMU.A is on (raise alignment fault if
           the EA is misaligned). */
        if (fNeedsAlignmentCheck && alignment_check_on) {
            EmitTestRegImm32(cursor, kEax, 3);
            raise_alignment_exception = EmitJnzLabel(cursor);
        }

        /* Cache the resolved host EA in EDI if this is the first
           unconditional "LDR Rd, [PC+immediate]" in the block —
           subsequent same-page PC-relative LDRs reuse it via the
           fast path at the top. */
        if (d->w == 0 && d->cond == 14 && d->b == 0 && d->l &&
            d->i == 0 && d->rn == ArmGpr::kR15) {
            EmitMovRegReg(cursor, kEdi, kEax);
            ctx->pc_cache_guest_va = d->reserved3;
            ctx->pc_cache_valid    = true;
        }
    }

    /* Base-Restored + !MemoryBeforeWriteback: writeback after the
       MMU translation succeeded but BEFORE the actual load/store. */
    if (fBaseRestoredAbortModel && !fMemoryBeforeWritebackModel) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                kEbp);
        }
    }

    if (d->l) {
        /* === LOAD === */
        if (d->b) {
            /* LDRB — single-byte zero-extended load. */
            uint8_t* load_byte_done1 = nullptr;
            uint8_t* load_byte_done2 = nullptr;

            /* MOVZX EAX, BYTE PTR [EAX] — 0F B6 mod=00 r/m=EAX reg=EAX. */
            Emit8(cursor, 0x0F);
            Emit8(cursor, 0xB6);
            EmitModRmReg(cursor, 0, kEax, kEax);
            load_byte_done1 = EmitJmpLabel(cursor);

            /* AbortExceptionOrIO: EAX == 0. Could be IO (peripheral
               PA) or genuine abort (translation fault). Check
               &io_pending_address: non-zero means IO. */
            FixupLabel(abort_exception_or_io, cursor);
            EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
            EmitTestRegReg(cursor, kEax, kEax);
            abort_exception = EmitJzLabel(cursor);

            if (fBaseRestoredAbortModel && !fMemoryBeforeWritebackModel) {
                if (d->w) {
                    EmitMovBaseDisp32Reg(cursor, kStateReg,
                        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                        kEbp);
                }
            }

            /* IO read byte. CERF helper is __fastcall(hint, d):
               ECX = hint slot pointer (back-patched imm32),
               EDX = peripheral dispatcher pointer. */
#if CERF_DEV_MODE
            EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
            Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
            io_hint_imm_location = cursor;
            Emit32(cursor, 0);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
            EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadByte));
            /* MOVZX EAX, AL — zero-extend byte result to 32-bit. */
            Emit8(cursor, 0x0F);
            Emit8(cursor, 0xB6);
            EmitModRmReg(cursor, 3, kEax, kEax);
            load_byte_done2 = EmitJmpLabel(cursor);

            /* Store IO hint cache slot inline — back-patch the
               MOV ECX imm32 to point at this byte. */
            {
                const uint32_t slot_addr =
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cursor));
                std::memcpy(io_hint_imm_location, &slot_addr, 4);
                Emit8(cursor, 0);
            }

            /* AbortException: peripheral check failed, raise data
               abort. MOV ECX, guest_pc; JMP raise_abort_data_helper. */
            FixupLabel(abort_exception, cursor);
            EmitMovRegImm32(cursor, kEcx, d->guest_address);
            EmitJmp32(cursor, ctx->raise_abort_data_helper_target);

            FixupLabel(load_byte_done1, cursor);
            FixupLabel(load_byte_done2, cursor);
            /* MOV [ESI + offsetof(gprs[Rd])], EAX — store loaded
               value into Rd. */
            EmitMovBaseDisp32Reg(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4),
                kEax);
        } else {
            SdtLdrWordInputs in;
            in.abort_exception_or_io          = abort_exception_or_io;
            in.raise_alignment_exception      = raise_alignment_exception;
            in.needs_alignment_check          = fNeedsAlignmentCheck;
            in.alignment_check_on             = alignment_check_on;
            in.base_restored_abort_model      = fBaseRestoredAbortModel;
            in.memory_before_writeback_model  = fMemoryBeforeWritebackModel;
            in.cache_hit                      = fCacheHit;
            cursor = EmitLdrWord(cursor, d, ctx, in);
        }
    } else {
        /* === STORE === */
        if (d->b) {
            /* STRB — single-byte store. */
            uint8_t* store_byte_done1 = nullptr;
            uint8_t* store_byte_done2 = nullptr;

            if (d->rd == ArmGpr::kR15) {
                const uint32_t inst_ptr = d->guest_address +
                    (thumb ? 4u : pc_store_offset);
                /* MOV BYTE PTR [EAX], imm8 — 0xC6 mod=00 r/m=EAX /0 imm8. */
                Emit8(cursor, 0xC6);
                EmitModRmReg(cursor, 0, kEax, 0);
                Emit8(cursor, static_cast<uint8_t>(inst_ptr));
            } else {
                /* MOV CL, BYTE PTR [ESI + gprs[Rd]*4] — load source
                   byte from the ARM register file via the pinned
                   ArmCpuState base. */
                EmitMovByteRegBaseDisp32(cursor, kCl, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4));
                /* MOV BYTE PTR [EAX], CL — store CL to the host
                   pointer the MMU translate returned. */
                Emit8(cursor, 0x88);
                EmitModRmReg(cursor, 0, kEax, kCl);
            }
            store_byte_done1 = EmitJmpLabel(cursor);

            FixupLabel(abort_exception_or_io, cursor);
            EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
            EmitTestRegReg(cursor, kEax, kEax);
            abort_exception = EmitJzLabel(cursor);

            if (fBaseRestoredAbortModel && !fMemoryBeforeWritebackModel) {
                if (d->w) {
                    EmitMovBaseDisp32Reg(cursor, kStateReg,
                        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                        kEbp);
                }
            }

            /* IO write byte. CERF helper is __fastcall(hint, d, value):
               value pushed on stack, ECX=hint, EDX=peripheral. */
            if (d->rd == ArmGpr::kR15) {
                const uint32_t inst_ptr = d->guest_address +
                    (thumb ? 4u : pc_store_offset);
                /* Push the byte value sign/zero-extended to dword. */
                EmitPush32(cursor, static_cast<uint8_t>(inst_ptr));
            } else {
                /* PUSH DWORD PTR [ESI + offsetof(gprs[Rd])] — the
                   callee reads only the low byte. */
                EmitPushBaseDisp32(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4));
            }
#if CERF_DEV_MODE
            EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
            Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
            io_hint_imm_location = cursor;
            Emit32(cursor, 0);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
            EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoWriteByte));
            store_byte_done2 = EmitJmpLabel(cursor);

            {
                const uint32_t slot_addr =
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cursor));
                std::memcpy(io_hint_imm_location, &slot_addr, 4);
                Emit8(cursor, 0);
            }

            FixupLabel(abort_exception, cursor);
            EmitMovRegImm32(cursor, kEcx, d->guest_address);
            EmitJmp32(cursor, ctx->raise_abort_data_helper_target);

            FixupLabel(store_byte_done1, cursor);
            FixupLabel(store_byte_done2, cursor);
        } else {
            /* STR — word store. */
            uint8_t* store_word_done1 = nullptr;
            uint8_t* store_word_done2 = nullptr;

            if (d->rd == ArmGpr::kR15) {
                /* MOV DWORD PTR [EAX], imm32 — 0xC7 mod=00 r/m=EAX /0 imm32. */
                Emit8(cursor, 0xC7);
                EmitModRmReg(cursor, 0, kEax, 0);
                Emit32(cursor, d->guest_address +
                    (thumb ? 4u : pc_store_offset));
            } else {
                /* MOV ECX, DWORD PTR [ESI + offsetof(gprs[Rd])]. */
                EmitMovRegBaseDisp32(cursor, kEcx, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4));
                /* MOV DWORD PTR [EAX], ECX — 0x89 mod=00 r/m=EAX reg=ECX. */
                Emit8(cursor, 0x89);
                EmitModRmReg(cursor, 0, kEax, kEcx);
            }
            store_word_done1 = EmitJmpLabel(cursor);

            FixupLabel(abort_exception_or_io, cursor);
            EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
            EmitTestRegReg(cursor, kEax, kEax);
            abort_exception = EmitJzLabel(cursor);

            if (fNeedsAlignmentCheck && alignment_check_on) {
                EmitTestRegImm32(cursor, kEax, 3);
                raise_alignment_exception2 = EmitJnzLabel(cursor);
            }

            if (fBaseRestoredAbortModel && !fMemoryBeforeWritebackModel) {
                if (d->w) {
                    EmitMovBaseDisp32Reg(cursor, kStateReg,
                        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                        kEbp);
                }
            }

            /* IO write word. */
            if (d->rd == ArmGpr::kR15) {
                EmitPush32(cursor, d->guest_address +
                    (thumb ? 4u : pc_store_offset));
            } else {
                EmitPushBaseDisp32(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4));
            }
#if CERF_DEV_MODE
            EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
            Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
            io_hint_imm_location = cursor;
            Emit32(cursor, 0);
            EmitMovRegImm32(cursor, kEdx,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
            EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoWriteWord));
            store_word_done2 = EmitJmpLabel(cursor);

            {
                const uint32_t slot_addr =
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cursor));
                std::memcpy(io_hint_imm_location, &slot_addr, 4);
                Emit8(cursor, 0);
            }

            FixupLabel(abort_exception, cursor);
            EmitMovRegImm32(cursor, kEcx, d->guest_address);
            EmitJmp32(cursor, ctx->raise_abort_data_helper_target);

            if (alignment_check_on && fNeedsAlignmentCheck) {
                FixupLabel(raise_alignment_exception, cursor);
                FixupLabel(raise_alignment_exception2, cursor);
                EmitPush32(cursor, d->guest_address);
                EmitPush32(cursor,
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
                EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::RaiseAlignmentExceptionHelper));
                EmitAddRegImm32(cursor, kEsp, 8);
                EmitMovRegImm32(cursor, kEcx, d->guest_address);
                EmitJmp32(cursor, ctx->raise_abort_data_helper_target);
            }
            FixupLabel(store_word_done1, cursor);
            FixupLabel(store_word_done2, cursor);
        }
    }

    if (fBaseRestoredAbortModel && fMemoryBeforeWritebackModel) {
        if (d->w) {
            EmitMovBaseDisp32Reg(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                kEbp);
        }
    }

    if (d->r15_modified) {
        cursor = PlaceR15ModifiedHelper(cursor, d, ctx);
    }
    return cursor;
}
