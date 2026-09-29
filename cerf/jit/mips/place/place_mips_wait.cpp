#include "../mips_place_fns.h"

#include <cstdint>

#include "../mips_block_context.h"
#include "../mips_emit_services.h"
#include "../mips_interrupt_channel.h"
#include "../mips_opcode.h"
#include "../../x86_emit.h"

/* VR4102 UM ch.27 STANDBY p643, SUSPEND p646. */
uint8_t* PlaceMipsWait(uint8_t* cursor, MipsDecodedInsn* d, MipsBlockContext* ctx) {
    using namespace x86;
    EmitMovRegImm32(cursor, kEcx,
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->emit->InterruptChannel())));
    EmitMovRegImm32(cursor, kEdx, d->guest_address + d->length);
    EmitCall(cursor, d->funct == MipsCop0Funct::kSUSPEND
                         ? reinterpret_cast<void*>(&MipsInterruptChannel::SuspendInsnHelper)
                         : reinterpret_cast<void*>(&MipsInterruptChannel::StandbyInsnHelper));
    return cursor;
}
