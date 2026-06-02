#include <cstddef>

#include "../arm_jit.h"
#include "../arm_mmu_state.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* PlaceCoprocessorPermissionCheck(uint8_t*      cursor,
                                         DecodedInsn*  d,
                                         BlockContext* ctx) {
    using namespace x86;

    /* Above the kernel split, the guest is already privileged and
       all coprocessor accesses are permitted. */
    if (d->actual_guest_address >= 0x80000000u) {
        return cursor;
    }

    ArmJit* jit = ctx->jit;

    /* MOV AL, BYTE PTR [ESI + offsetof(cpsr)] — low byte of CPSR
       holds the mode field in bits[4:0]. Per-instance via pinned
       ESI (instead of an absolute disp32 form). */
    EmitMovByteRegBaseDisp32(cursor, kAl, kStateReg,
        static_cast<int32_t>(offsetof(ArmCpuState, cpsr)));

    /* AND AL, 0x1F — mask off the mode field. */
    Emit8(cursor, 0x24); Emit8(cursor, 0x1F);

    /* CMP AL, UserModeValue. */
    Emit8(cursor, 0x3C);
    Emit8(cursor, static_cast<uint8_t>(ArmMode::kUser));

    uint8_t* permission_granted_1 = EmitJnzLabel(cursor);

    /* cp_n access lives at CPACR bits[2n+1:2n] (see
       references/arm/cpacr_excerpt.txt); `1 << cp_num` reads
       cp(n/2)'s low bit and would UND every user-mode VFP op
       despite correct CPACR programming. */
    Emit8(cursor, 0xF7);
    EmitModRmReg(cursor, 2, kMmuReg, 0);
    Emit32(cursor,
        static_cast<uint32_t>(offsetof(ArmMmuState, coprocessor_access)));
    Emit32(cursor, 0x3u << (2u * d->cp_num));

    uint8_t* permission_granted_2 = EmitJnzLabel(cursor);

    /* Permission denied — raise UND. PUSH guest_pc, PUSH cpu, CALL
       RaiseUndefinedExceptionHelper, ADD ESP, 8, RETN. */
    EmitPush32(cursor, d->guest_address);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Cpu())));
    EmitCall(cursor, reinterpret_cast<void*>(&ArmCpu::RaiseUndefinedExceptionHelper));
    EmitAddRegImm32(cursor, kEsp, 8);
    EmitRetn(cursor, 0);

    FixupLabel(permission_granted_1, cursor);
    FixupLabel(permission_granted_2, cursor);
    return cursor;
}
