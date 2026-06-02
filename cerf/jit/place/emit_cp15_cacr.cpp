#include <cstddef>
#include <cstdint>

#include "../arm_mmu_state.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* EmitCp15Cacr(uint8_t*      cursor,
                      DecodedInsn*  d,
                      BlockContext* /* ctx */) {
    using namespace x86;

    const int32_t rd_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + d->rd * 4u);

    if (d->l) {
        EmitMovRegBaseDisp32(cursor, kEax, kMmuReg,
            static_cast<int32_t>(offsetof(ArmMmuState, coprocessor_access)));
        EmitMovBaseDisp32Reg(cursor, kStateReg, rd_disp, kEax);
    } else {
        EmitMovRegBaseDisp32(cursor, kEax, kStateReg, rd_disp);
        EmitMovBaseDisp32Reg(cursor, kMmuReg,
            static_cast<int32_t>(offsetof(ArmMmuState, coprocessor_access)), kEax);
    }
    return cursor;
}
