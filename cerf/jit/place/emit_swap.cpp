#include <cstddef>
#include <cstdint>
#include <cstring>

#include "../../peripherals/peripheral_dispatcher.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* EmitSwap(uint8_t*      cursor,
                  DecodedInsn*  d,
                  BlockContext* ctx) {
    using namespace x86;
    ArmJit*               jit        = ctx->jit;
    ArmMmu*               mmu        = jit->Mmu();
    PeripheralDispatcher* peripheral = jit->Peripheral();

    const bool mmu_on = mmu->State()->control_register.bits.m;
    const bool is_byte = d->b != 0;

    const int32_t rn_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rn * 4u);
    const int32_t rm_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rm * 4u);
    const int32_t rd_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u);

    uint8_t* io_hint_imm_location1  = nullptr;
    uint8_t* io_hint_imm_location2  = nullptr;

    /* MOV ECX, [ESI + gprs[Rn]] — load effective address. */
    EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, rn_disp);

    if (mmu_on) {
        cursor = EmitTlbFastPath(cursor, ctx, TlbAccess::kReadWrite);
    } else {
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
        EmitCall(cursor,
            reinterpret_cast<void*>(&ArmJit::MapGuestPhysicalToHostHelper));
    }

    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* abort_or_io = EmitJzLabel(cursor);

    /* === Memory fast path === */
    if (is_byte) {
        /* MOV DL, [ESI + gprs[Rm]] — load Rm byte into DL. */
        EmitMovByteRegBaseDisp32(cursor, kDl, kStateReg, rm_disp);
        /* MOVZX EBP, BYTE PTR [EAX] — load+zero-extend memory byte. */
        Emit8(cursor, 0x0F); Emit8(cursor, 0xB6);
        EmitModRmReg(cursor, 0, kEax, kEbp);
        /* MOV BYTE PTR [EAX], DL — store Rm byte to memory. */
        Emit8(cursor, 0x88);
        EmitModRmReg(cursor, 0, kEax, kDl);
    } else {
        /* MOV EBP, [ESI + gprs[Rm]] — load Rm word into EBP. */
        EmitMovRegBaseDisp32(cursor, kEbp, kStateReg, rm_disp);
        /* XCHG EBP, DWORD PTR [EAX] — atomic swap (LOCK implicit). */
        Emit8(cursor, 0x87);
        EmitModRmReg(cursor, 0, kEax, kEbp);
    }
    uint8_t* swap_done_mem = EmitJmpLabel(cursor);

    /* === IO path === */
    FixupLabel(abort_or_io, cursor);
    /* MOV EAX, [&io_pending_address] — zero means genuine abort,
       non-zero means peripheral IO. */
    EmitMovRegDwordPtr(cursor, kEax, mmu->IoPendingAddressPtr());
    EmitTestRegReg(cursor, kEax, kEax);
    uint8_t* abort_label = EmitJzLabel(cursor);

    if (is_byte) {
        /* IO read byte. CERF helper __fastcall(hint, peripheral):
           ECX=hint slot (back-patched below to point at the inline
           hint byte), EDX=peripheral. Result in AL. */
#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location1 = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadByte));
        /* MOVZX EBP, AL — preserve loaded byte across next CALL. */
        Emit8(cursor, 0x0F); Emit8(cursor, 0xB6);
        EmitModRmReg(cursor, 3, kEax, kEbp);
        /* IO write byte. PUSH Rm dword (callee reads only low byte). */
        EmitPushBaseDisp32(cursor, kStateReg, rm_disp);
#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location2 = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoWriteByte));
    } else {
        /* IO read word. */
#if CERF_DEV_MODE
        EmitMovDwordPtrImm32(cursor, peripheral->LastGuestPcPtr(), d->guest_address);
#endif
        Emit8(cursor, static_cast<uint8_t>(0xB8 + kEcx));
        io_hint_imm_location1 = cursor;
        Emit32(cursor, 0);
        EmitMovRegImm32(cursor, kEdx,
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peripheral)));
        EmitCall(cursor, reinterpret_cast<void*>(&PeripheralDispatcher::JitIoReadWord));
        /* MOV EBP, EAX — preserve loaded word across next CALL. */
        EmitMovRegReg(cursor, kEbp, kEax);
        /* IO write word. */
        EmitPushBaseDisp32(cursor, kStateReg, rm_disp);
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
    uint8_t* swap_done_io = EmitJmpLabel(cursor);

    /* IO hint cache slots inline — back-patched once cursor is here. */
    {
        const uint32_t slot_addr =
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cursor));
        std::memcpy(io_hint_imm_location1, &slot_addr, 4);
        std::memcpy(io_hint_imm_location2, &slot_addr, 4);
        Emit8(cursor, 0);
    }

    /* AbortException — MOV ECX, guest_pc; JMP raise_abort_data_helper. */
    FixupLabel(abort_label, cursor);
    EmitMovRegImm32(cursor, kEcx, d->guest_address);
    EmitJmp32(cursor, ctx->raise_abort_data_helper_target);

    FixupLabel(swap_done_mem, cursor);
    FixupLabel(swap_done_io, cursor);
    /* MOV [ESI + gprs[Rd]], EBP — store loaded value into Rd. */
    EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEbp);

    return cursor;
}
