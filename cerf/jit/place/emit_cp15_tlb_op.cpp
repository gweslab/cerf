#include <cstddef>
#include <cstdint>

#include "../../core/log.h"
#include "../arm_mmu_state.h"
#include "../arm_tlb_ops.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* EmitCp15TlbOp(uint8_t*      cursor,
                       DecodedInsn*  d,
                       BlockContext* ctx) {
    using namespace x86;

    /* Loads from cp15 c8 are architecturally undefined (write-only). */
    if (d->l) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const int32_t dtlb_disp =
        static_cast<int32_t>(offsetof(ArmMmuState, data_tlb));
    const int32_t itlb_disp =
        static_cast<int32_t>(offsetof(ArmMmuState, instruction_tlb));

    switch (d->cp_opc) {
    case 0:
        switch (d->crm) {
        case 7:
            /* Flush both TLBs. */
            EmitLeaRegBaseDisp32(cursor, kEax, kMmuReg, dtlb_disp);
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmTlbFlushAll));
            EmitAddRegImm32(cursor, kEsp, 4);
            EmitLeaRegBaseDisp32(cursor, kEax, kMmuReg, itlb_disp);
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmTlbFlushAll));
            EmitAddRegImm32(cursor, kEsp, 4);
            break;
        case 5:
            /* Flush ITLB. */
            EmitLeaRegBaseDisp32(cursor, kEax, kMmuReg, itlb_disp);
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmTlbFlushAll));
            EmitAddRegImm32(cursor, kEsp, 4);
            break;
        case 6:
            /* Flush DTLB. */
            EmitLeaRegBaseDisp32(cursor, kEax, kMmuReg, dtlb_disp);
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmTlbFlushAll));
            EmitAddRegImm32(cursor, kEsp, 4);
            break;
        default:
            LOG(Caution,
                "EmitCp15TlbOp: unimplemented c8 maintenance op "
                "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
                static_cast<unsigned>(d->cp_opc),
                static_cast<unsigned>(d->crm),
                static_cast<unsigned>(d->cp), d->guest_address);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            break;
        }
        break;

    case 1:
        if (d->crm == 5 || d->crm == 6) {
            /* Invalidate ITLB (CRm=5) or DTLB (CRm=6) entry by VA.
               cdecl ArmTlbInvalidateByVa(unit, process_id, va); PUSH
               right-to-left: va, process_id, unit. */
            const int32_t unit_disp = (d->crm == 5) ? itlb_disp : dtlb_disp;
            EmitPushBaseDisp32(cursor, kStateReg,
                static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u));
            EmitPushBaseDisp32(cursor, kMmuReg,
                static_cast<int32_t>(offsetof(ArmMmuState, process_id)));
            EmitLeaRegBaseDisp32(cursor, kEax, kMmuReg, unit_disp);
            EmitPushReg(cursor, kEax);
            EmitCall(cursor, reinterpret_cast<void*>(&ArmTlbInvalidateByVa));
            EmitAddRegImm32(cursor, kEsp, 12);
        } else {
            LOG(Caution,
                "EmitCp15TlbOp: unimplemented c8 maintenance op "
                "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
                static_cast<unsigned>(d->cp_opc),
                static_cast<unsigned>(d->crm),
                static_cast<unsigned>(d->cp), d->guest_address);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        break;

    default:
        LOG(Caution,
            "EmitCp15TlbOp: unimplemented c8 maintenance op "
            "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
            static_cast<unsigned>(d->cp_opc),
            static_cast<unsigned>(d->crm),
            static_cast<unsigned>(d->cp), d->guest_address);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        break;
    }

    return cursor;
}
