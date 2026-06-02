#include <cstddef>
#include <cstdint>

#include "../../core/log.h"
#include "../../cpu/arm_processor_config.h"
#include "../arm_jit.h"
#include "../arm_mmu.h"
#include "../cpu_state.h"
#include "../place_fns.h"
#include "../x86_emit.h"
#include "emit_full_flush_escape.h"

namespace {

/* MMU on → targeted dirty-page block removal (no whole-cache flush — that
   was the storm). MMU off → whole flush + escape: early-boot fetch/store
   bypass the page walker so there is no dirty-page tracking, and a stale
   MMU-off translation would otherwise execute. */
uint8_t* EmitICacheInvalidate(uint8_t* cursor, ArmJit* jit,
                              int32_t r15_disp, uint32_t pc_resume) {
    using namespace x86;
    ArmMmuState* st = jit->Mmu()->State();
    EmitMovRegDwordPtr(cursor, kEax, &st->control_register.word);
    EmitTestRegImm32(cursor, kEax, 1u);                /* SCTLR.M */
    uint8_t* mmu_on = EmitJnzLabel(cursor);
    cursor = EmitFullFlushAndEscape(cursor, jit, r15_disp, pc_resume);
    FixupLabel(mmu_on, cursor);
    EmitMovRegImm32(cursor, kEcx,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(jit)));
    EmitCall(cursor,
        reinterpret_cast<void*>(&ArmJit::InvalidateDirtyCodePagesHelper));
    return cursor;
}

}  // namespace

uint8_t* EmitCp15CacheOp(uint8_t*      cursor,
                         DecodedInsn*  d,
                         BlockContext* ctx) {
    using namespace x86;
    ArmJit* jit = ctx->jit;

    /* Loads from cp15 c7 are architecturally undefined (the register
       is write-only). */
    if (d->l) {
        return EmitRaiseUndAndReturn(cursor, d, ctx);
    }

    const uint32_t pc_resume_plus_4 = d->guest_address + 4u;
    const uint32_t pc_resume_plus10 = d->guest_address + 0x10u;

    const int32_t r15_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + ArmGpr::kR15 * 4u);
    const int32_t r1_disp =
        static_cast<int32_t>(offsetof(ArmCpuState, gprs) + ArmGpr::kR1 * 4u);

    switch (d->cp_opc) {
    case 0:
        switch (d->crm) {
        case 0:
            /* CP=4 wait-for-interrupt; CP=others architecturally
               undefined but treated as no-op emit per reference. */
            break;

        case 5:
            switch (d->cp) {
            case 0:
                /* Invalidate entire I-cache → flush only dirtied code. */
                cursor = EmitICacheInvalidate(cursor, jit, r15_disp,
                                              pc_resume_plus_4);
                break;
            case 1:
                if (d->operand2 == 0xFFFFFFFFu) {
                    /* operand2==0xFFFFFFFF marks a collapsed I-cache range-clean
                       loop; it would leave its counter R1 = 0 — preserve that
                       side effect, then targeted dirty-page invalidation. */
                    EmitMovBaseDisp32Imm32(cursor, kStateReg, r1_disp, 0u);
                    cursor = EmitICacheInvalidate(cursor, jit, r15_disp,
                                                  pc_resume_plus10);
                } else {
                    cursor = EmitICacheInvalidate(cursor, jit, r15_disp,
                                                  pc_resume_plus_4);
                }
                break;
            case 2:
                /* Set/index invalidate not modeled — halt. */
                LOG(Caution,
                    "EmitCp15CacheOp: c7 CRm=5 CP=2 (set/index I-cache invalidate) not supported, pc=0x%08X\n",
                    d->guest_address);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                break;
            case 4:  /* Flush Prefetch Buffer  — no-op. */
            case 6:  /* Flush Entire BTB        — no-op. */
            case 7:  /* Flush BTB entry         — no-op. */
                break;
            default:
                LOG(Caution,
                    "EmitCp15CacheOp: c7 CRm=5 CP=%u (unsupported I-cache op), pc=0x%08X\n",
                    d->cp, d->guest_address);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                break;
            }
            break;

        case 6:
            /* D-cache invalidate. CERF has no D-cache, so all the
               documented sub-encodings are no-ops; unknown CPs halt. */
            switch (d->cp) {
            case 0:  /* Flush entire D-cache             */
            case 1:  /* Invalidate D-cache line by VA    */
            case 2:  /* Invalidate D-cache line by S/I   */
            case 4:
                break;
            default:
                LOG(Caution,
                    "EmitCp15CacheOp: c7 CRm=6 CP=%u (unsupported D-cache op), pc=0x%08X\n",
                    d->cp, d->guest_address);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                break;
            }
            break;

        case 7:
            switch (d->cp) {
            case 0:
                /* Invalidate entire unified cache → flush only dirtied code. */
                cursor = EmitICacheInvalidate(cursor, jit, r15_disp,
                                              pc_resume_plus_4);
                break;
            case 1:
                /* Invalidate unified-cache line → targeted dirty-page invalidation. */
                cursor = EmitICacheInvalidate(cursor, jit, r15_disp,
                                              pc_resume_plus_4);
                break;
            case 2:
            default:
                LOG(Caution,
                    "EmitCp15CacheOp: c7 CRm=7 CP=%u (unsupported unified cache op), pc=0x%08X\n",
                    d->cp, d->guest_address);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                break;
            }
            break;

        case 8:   /* wait-for-interrupt   */
        case 10:  /* clean D-cache line   */
        case 11:  /* clean unified line   */
        case 13:  /* prefetch I-cache     */
        case 14:  /* clean+invalidate     */
        case 15:  /* clean+invalidate U   */
            /* No-ops on CERF — no D-cache, no prefetcher, no
               write buffer to drain. */
            break;

        default:
            /* Unimplemented c7 maintenance encoding — halt loudly
               instead of a silent guest UND cascade. */
            LOG(Caution,
                "EmitCp15CacheOp: unimplemented c7 maintenance op "
                "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
                static_cast<unsigned>(d->cp_opc),
                static_cast<unsigned>(d->crm),
                static_cast<unsigned>(d->cp), d->guest_address);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            break;
        }
        break;

    case 1:
        /* "Flush" / "clean" D-cache entry by VA — documented
           sub-cases are no-ops on CERF; any other encoding UNDs. */
        switch (d->crm) {
        case 6:
        case 10:
            break;
        default:
            LOG(Caution,
                "EmitCp15CacheOp: unimplemented c7 maintenance op "
                "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
                static_cast<unsigned>(d->cp_opc),
                static_cast<unsigned>(d->crm),
                static_cast<unsigned>(d->cp), d->guest_address);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            break;
        }
        break;

    case 4:
        /* Drain Write Buffer (CRm=10) — no-op (no write buffer on
           CERF). All other CRm values are unimplemented — halt. */
        if (d->crm != 10) {
            LOG(Caution,
                "EmitCp15CacheOp: unimplemented c7 maintenance op "
                "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
                static_cast<unsigned>(d->cp_opc),
                static_cast<unsigned>(d->crm),
                static_cast<unsigned>(d->cp), d->guest_address);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        break;

    case 6:
        /* Invalidate Branch Target Buffer (CRm=5) — no-op (no BTB
           on CERF). All other CRm values are unimplemented — halt. */
        if (d->crm != 5) {
            LOG(Caution,
                "EmitCp15CacheOp: unimplemented c7 maintenance op "
                "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
                static_cast<unsigned>(d->cp_opc),
                static_cast<unsigned>(d->crm),
                static_cast<unsigned>(d->cp), d->guest_address);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        break;

    default:
        LOG(Caution,
            "EmitCp15CacheOp: unimplemented c7 maintenance op "
            "(opc1=%u CRm=%u opc2=%u) at pc=0x%08X\n",
            static_cast<unsigned>(d->cp_opc),
            static_cast<unsigned>(d->crm),
            static_cast<unsigned>(d->cp), d->guest_address);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        break;
    }

    return cursor;
}
