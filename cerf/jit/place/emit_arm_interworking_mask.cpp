#include <cstddef>

#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

uint8_t* EmitArmInterworkingMaskEax(uint8_t* cursor) {
    using namespace x86;

    /* TEST EAX, 1 — bit 0 selects new ISA state. */
    EmitTestRegImm32(cursor, kEax, 1);
    uint8_t* jz_to_rejoin = EmitJzLabel(cursor);

    /* OR DWORD PTR [ESI + cpsr], 0x20 — set CPSR.T (bit 5) for Thumb target.
       81 /1 mod=10 r/m=ESI disp32 imm32. */
    Emit8(cursor, 0x81);
    EmitModRmReg(cursor, 2, kStateReg, 1);
    Emit32(cursor, static_cast<uint32_t>(offsetof(ArmCpuState, cpsr)));
    Emit32(cursor, 0x00000020u);
    /* AND EAX, 0xFFFFFFFE — drop interworking bit. */
    EmitAndRegImm32(cursor, kEax, 0xFFFFFFFEu);

    FixupLabel(jz_to_rejoin, cursor);
    return cursor;
}
