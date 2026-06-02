#include <cstddef>
#include <cstdint>

#include "../block_context.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"

namespace {

constexpr int32_t GprDisp(uint32_t n) {
    return static_cast<int32_t>(offsetof(ArmCpuState, gprs) + n * 4u);
}

constexpr int32_t MonitorAddrDisp() {
    return static_cast<int32_t>(offsetof(ArmCpuState, ldrex_monitor_addr));
}

constexpr int32_t MonitorArmedDisp() {
    return static_cast<int32_t>(offsetof(ArmCpuState, ldrex_monitor_armed));
}

uint8_t* EmitTranslatePrefix(uint8_t*& cursor, DecodedInsn* d,
                             BlockContext* ctx, bool is_write) {
    using namespace x86;
    EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, GprDisp(d->rn));
    cursor = EmitTlbFastPath(cursor, ctx,
                             is_write ? TlbAccess::kWrite : TlbAccess::kRead);
    EmitTestRegReg(cursor, kEax, kEax);
    return EmitJzLabel32(cursor);
}

/* Emit the abort tail: MOV ECX, guest_pc; JMP abort trampoline.
   Caller has already FixupLabel32'd its abort jump to this point. */
void EmitAbortTail(uint8_t*& cursor, DecodedInsn* d, BlockContext* ctx) {
    using namespace x86;
    EmitMovRegImm32(cursor, kEcx, d->guest_address);
    EmitJmp32(cursor, ctx->raise_abort_data_helper_target);
}

}  /* namespace */

uint8_t* PlaceLdrex(uint8_t*      cursor,
                    DecodedInsn*  d,
                    BlockContext* ctx) {
    using namespace x86;

    uint8_t* abort_label = EmitTranslatePrefix(cursor, d, ctx, /*is_write=*/false);

    /* Success path. Load 32-bit value from translated host pointer.
       MOV ECX, [EAX] — 0x8B with ModR/M mod=00 r/m=EAX reg=ECX. */
    Emit8(cursor, 0x8B);
    EmitModRmReg(cursor, /*mod=*/0, /*rm=*/kEax, /*reg=*/kEcx);

    /* Store loaded value to Rt. */
    EmitMovBaseDisp32Reg(cursor, kStateReg, GprDisp(d->rd), kEcx);

    /* Arm exclusive monitor: monitor_addr = guest VA (re-loaded
       from Rn since EAX held the host pointer), monitor_armed = 1. */
    EmitMovRegBaseDisp32 (cursor, kEax, kStateReg, GprDisp(d->rn));
    EmitMovBaseDisp32Reg (cursor, kStateReg, MonitorAddrDisp(),  kEax);
    EmitMovBaseDisp32Imm32(cursor, kStateReg, MonitorArmedDisp(), 1u);

    /* JMP .done */
    uint8_t* done_label = EmitJmpLabel32(cursor);

    /* .abort: */
    FixupLabel32(abort_label, cursor);
    EmitAbortTail(cursor, d, ctx);

    /* .done: */
    FixupLabel32(done_label, cursor);
    return cursor;
}

uint8_t* PlaceStrex(uint8_t*      cursor,
                    DecodedInsn*  d,
                    BlockContext* ctx) {
    using namespace x86;

    /* Check monitor armed. */
    EmitMovRegBaseDisp32(cursor, kEax, kStateReg, MonitorArmedDisp());
    EmitTestRegReg      (cursor, kEax, kEax);
    uint8_t* fail_label_a = EmitJzLabel32(cursor);

    /* Check address match — CMP ECX (VA from Rn), [ESI + monitor_addr]. */
    EmitMovRegBaseDisp32 (cursor, kEcx, kStateReg, GprDisp(d->rn));
    EmitCmpRegBaseDisp32 (cursor, kEcx, kStateReg, MonitorAddrDisp());
    uint8_t* fail_label_b = EmitJnzLabel32(cursor);

    /* Monitor armed and address matches. Now translate the write. */
    uint8_t* abort_label = EmitTranslatePrefix(cursor, d, ctx, /*is_write=*/true);

    /* Translation succeeded. Load Rt source value, write to host ptr. */
    EmitMovRegBaseDisp32(cursor, kEcx, kStateReg, GprDisp(d->rm));
    Emit8(cursor, 0x89);                                  /* MOV [EAX], ECX */
    EmitModRmReg(cursor, /*mod=*/0, /*rm=*/kEax, /*reg=*/kEcx);

    /* Rd = 0 (success), clear monitor. */
    EmitMovBaseDisp32Imm32(cursor, kStateReg, GprDisp(d->rd),     0u);
    EmitMovBaseDisp32Imm32(cursor, kStateReg, MonitorArmedDisp(), 0u);

    /* JMP .done */
    uint8_t* done_label = EmitJmpLabel32(cursor);

    /* .fail: Rd = 1, monitor stays armed (kernel retry). */
    FixupLabel32(fail_label_a, cursor);
    FixupLabel32(fail_label_b, cursor);
    EmitMovBaseDisp32Imm32(cursor, kStateReg, GprDisp(d->rd), 1u);
    uint8_t* done_label_b = EmitJmpLabel32(cursor);

    /* .abort: */
    FixupLabel32(abort_label, cursor);
    EmitAbortTail(cursor, d, ctx);

    /* .done: */
    FixupLabel32(done_label,   cursor);
    FixupLabel32(done_label_b, cursor);
    return cursor;
}
