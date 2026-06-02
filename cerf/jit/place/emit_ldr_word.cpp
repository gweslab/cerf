#include <cstddef>
#include <cstring>

#include "../../peripherals/peripheral_dispatcher.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* EmitLdrWord(uint8_t*                  cursor,
                     DecodedInsn*              d,
                     BlockContext*             ctx,
                     const SdtLdrWordInputs&   in) {
    using namespace x86;

    ArmJit*               jit        = ctx->jit;
    ArmMmu*               mmu        = jit->Mmu();
    PeripheralDispatcher* peripheral = jit->Peripheral();

    uint8_t* load_word_done1            = nullptr;
    uint8_t* load_word_done2            = nullptr;
    uint8_t* abort_exception            = nullptr;
    uint8_t* raise_alignment_exception2 = nullptr;
    uint8_t* io_hint_imm_location       = nullptr;

    /* MOV EAX, DWORD PTR [EAX] — 0x8B mod=00 r/m=EAX reg=EAX. */
    Emit8(cursor, 0x8B);
    EmitModRmReg(cursor, 0, kEax, kEax);

    if (!in.cache_hit) {
        load_word_done1 = EmitJmpLabel(cursor);

        FixupLabel(in.abort_exception_or_io, cursor);
        EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
        EmitTestRegReg(cursor, kEax, kEax);
        abort_exception = EmitJzLabel(cursor);

        if (in.needs_alignment_check && in.alignment_check_on) {
            EmitTestRegImm32(cursor, kEax, 3);
            raise_alignment_exception2 = EmitJnzLabel(cursor);
        }

        if (in.base_restored_abort_model && !in.memory_before_writeback_model) {
            if (d->w) {
                EmitMovBaseDisp32Reg(cursor, kStateReg,
                    static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4),
                    kEbp);
            }
        }

#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadWord));
        load_word_done2 = EmitJmpLabel(cursor);

        {
            const uint32_t slot_addr =
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cursor));
            std::memcpy(io_hint_imm_location, &slot_addr, 4);
            Emit8(cursor, 0);
        }

        FixupLabel(abort_exception, cursor);
        EmitMovRegImm32(cursor, kEcx, d->guest_address);
        EmitJmp32(cursor, ctx->raise_abort_data_helper_target);

        if (in.needs_alignment_check && in.alignment_check_on) {
            FixupLabel(in.raise_alignment_exception, cursor);
            FixupLabel(raise_alignment_exception2, cursor);
            /* RaiseAlignmentExceptionHelper takes __cdecl(jit,
               guest_pc) — load FAR/FSR with the alignment fault
               status. The actual EA is no longer in a register (was
               ANDed earlier); guest_pc is what the helper records. */
            EmitPush32(cursor, d->guest_address);
            EmitPush32(cursor,
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
            EmitCall(cursor, reinterpret_cast<void*>(&ArmJit::RaiseAlignmentExceptionHelper));
            EmitAddRegImm32(cursor, kEsp, 8);
            EmitMovRegImm32(cursor, kEcx, d->guest_address);
            EmitJmp32(cursor, ctx->raise_abort_data_helper_target);
        }
        FixupLabel(load_word_done1, cursor);
        FixupLabel(load_word_done2, cursor);
    }

    if (in.needs_alignment_check && !in.alignment_check_on) {
        /* Unaligned word load with alignment check off: rotate the
           loaded value right by (EA bits[1:0]) * 8 so the byte at
           the requested EA is in the low byte of the result. */
        EmitMovRegDwordPtr(cursor, kEcx,
            jit->LdrUnalignedGuestAddressPtr());
        EmitAndRegImm32(cursor, kEcx, 3);
        EmitShlReg32Imm(cursor, kEcx, 3);
        /* ROR EAX, CL — 0xD3 /1 ModRM(3, EAX, 1). */
        Emit8(cursor, 0xD3);
        EmitModRmReg(cursor, 3, kEax, 1);
    }
    EmitMovBaseDisp32Reg(cursor, kStateReg,
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4),
        kEax);

    return cursor;
}
