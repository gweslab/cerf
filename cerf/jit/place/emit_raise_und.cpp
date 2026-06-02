#include <cstdint>
#include <cstring>

#include "../arm_cpu.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../place_fns.h"
#include "../x86_emit.h"
#include "../../core/log.h"

uint8_t* EmitRaiseUndAndReturn(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;
    /* Re-read the guest word the decoder choked on (read-only MMU peek, same
       page the fetch used) so the log distinguishes corrupt/poison bytes from a
       genuine unsupported encoding. */
    uint32_t word = 0xFFFFFFFFu;
    bool word_ok = false;
    if (uint8_t* p = jit->Mmu()->PeekVaToHost(d->actual_guest_address)) {
        std::memcpy(&word, p, sizeof(word));
        word_ok = true;
    }
    LOG(Jit, "EmitRaiseUndAndReturn: UNDEFINED encoding at pc=0x%08X (actual=0x%08X) "
             "word=%s0x%08X\n",
        d->guest_address, d->actual_guest_address,
        word_ok ? "" : "UNMAPPED:", word);
    EmitPush32(cursor, d->guest_address);
    EmitPush32(cursor,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit->Cpu())));
    EmitCall(cursor,
        reinterpret_cast<void*>(&ArmCpu::RaiseUndefinedExceptionHelper));
    EmitAddRegImm32(cursor, kEsp, 8);
    EmitRetn(cursor, 0);
    return cursor;
}
