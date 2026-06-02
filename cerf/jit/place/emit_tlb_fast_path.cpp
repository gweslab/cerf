#include <cstddef>

#include "../arm_jit.h"
#include "../arm_mmu_state.h"
#include "../block_context.h"
#include "../place_fns.h"
#include "../x86_emit.h"

/* In: ECX = guest EA. Out: EAX = host pointer (null fault from the helper on a
   miss). ECX must survive for the caller's merged load/store; EBX/ESI are the
   pinned MMU/CPU bases — this body uses only EAX/EDX as scratch. */
uint8_t* EmitTlbFastPath(uint8_t* cursor, BlockContext* ctx, TlbAccess access) {
    using namespace x86;
    const bool is_write = (access != TlbAccess::kRead);

    const int32_t tlb     = static_cast<int32_t>(offsetof(ArmMmuState, data_tlb));
    const int32_t pid     = static_cast<int32_t>(offsetof(ArmMmuState, process_id));
    const int32_t ctxid   = static_cast<int32_t>(offsetof(ArmMmuState, contextidr));
    const int32_t cwbase  = static_cast<int32_t>(offsetof(ArmMmuState, code_word_base));
    const int32_t cwtop   = static_cast<int32_t>(offsetof(ArmMmuState, code_word_top));
    const int32_t xlat    = static_cast<int32_t>(offsetof(ArmMmuState, code_xlat_bitmap));
    const int32_t dirty   = static_cast<int32_t>(offsetof(ArmMmuState, code_page_dirty));
    const int32_t e_tag   = tlb + static_cast<int32_t>(offsetof(ArmTlbEntry, tag));
    const int32_t e_add   = tlb + static_cast<int32_t>(offsetof(ArmTlbEntry, va_addend));
    const int32_t e_pa    = tlb + static_cast<int32_t>(offsetof(ArmTlbEntry, pa_page));
    const int32_t e_asid  = tlb + static_cast<int32_t>(offsetof(ArmTlbEntry, asid));
    const int32_t e_glob  = tlb + static_cast<int32_t>(offsetof(ArmTlbEntry, global));
    const int32_t e_wr    = tlb + static_cast<int32_t>(offsetof(ArmTlbEntry, writable));

    uint8_t* miss[3];
    int      nmiss = 0;

    /* EAX = FCSE-folded VA. */
    EmitMovRegReg     (cursor, kEax, kEcx);
    EmitTestRegImm32  (cursor, kEax, 0xFE000000u);
    uint8_t* nf1 = EmitJnzLabel(cursor);
    EmitOrRegBaseDisp32(cursor, kEax, kMmuReg, pid);
    FixupLabel(nf1, cursor);

    /* EDX = EBX + way0-of-set offset. set = (foldedVA >> 12) & kArmTlbSetMask;
       byte offset = set * (kArmTlbWays * 16) = set << kArmTlbSetShift. The probe
       reads only way 0; a miss (incl. a hit cached in another way) falls to the
       slow path, which scans every way and promotes a hit back to way 0. */
    EmitMovRegReg   (cursor, kEdx, kEax);
    EmitShrReg32Imm (cursor, kEdx, 12);
    EmitAndRegImm32 (cursor, kEdx, kArmTlbSetMask);
    EmitShlReg32Imm (cursor, kEdx, kArmTlbSetShift);
    EmitAddReg32Reg32(cursor, kEdx, kMmuReg);

    /* (foldedVA & ~0xFFF) == entry.tag ? */
    EmitAndRegImm32     (cursor, kEax, 0xFFFFF000u);
    EmitCmpRegBaseDisp32(cursor, kEax, kEdx, e_tag);
    miss[nmiss++] = EmitJnzLabel32(cursor);

    /* entry.global || entry.asid == CONTEXTIDR[7:0]. */
    EmitMovRegBaseDisp32      (cursor, kEax, kMmuReg, ctxid);   /* AL = current ASID */
    EmitTestByteBaseDisp32Imm8(cursor, kEdx, e_glob, 0xFF);
    uint8_t* ctx_ok = EmitJnzLabel(cursor);
    EmitCmpReg8BaseDisp32     (cursor, kAl, kEdx, e_asid);
    miss[nmiss++] = EmitJnzLabel32(cursor);
    FixupLabel(ctx_ok, cursor);

    if (is_write) {
        /* Read-only cached page → slow path re-checks write permission. */
        EmitTestByteBaseDisp32Imm8(cursor, kEdx, e_wr, 0xFF);
        miss[nmiss++] = EmitJzLabel32(cursor);

        /* Inline SMC (mirrors NoteCodeTracking<kWrite>): if PA is a marked code
           word, set its page's code_page_dirty bit so the next I-cache
           invalidate evicts the block. PA = entry.pa_page | (EA & 0xFFF). */
        EmitMovRegReg      (cursor, kEax, kEcx);
        EmitAndRegImm32    (cursor, kEax, 0xFFFu);
        EmitOrRegBaseDisp32(cursor, kEax, kEdx, e_pa);

        EmitCmpRegBaseDisp32(cursor, kEax, kMmuReg, cwbase);
        uint8_t* smc_done_a = EmitJbLabel32(cursor);
        EmitCmpRegBaseDisp32(cursor, kEax, kMmuReg, cwtop);
        uint8_t* smc_done_b = EmitJaeLabel32(cursor);

        EmitSubRegBaseDisp32(cursor, kEax, kMmuReg, cwbase);   /* EAX = PA - base */
        EmitPushReg         (cursor, kEcx);                     /* spill EA */
        EmitMovRegBaseDisp32(cursor, kEcx, kMmuReg, xlat);      /* ECX = code_xlat_bitmap */
        EmitShrReg32Imm     (cursor, kEax, 2);                  /* EAX = word index */
        EmitBtMemReg        (cursor, kEcx, kEax);               /* CF = code bit */
        uint8_t* smc_restore = EmitJncLabel32(cursor);
        EmitShrReg32Imm     (cursor, kEax, 10);                 /* EAX = page index */
        EmitMovRegBaseDisp32(cursor, kEcx, kMmuReg, dirty);     /* ECX = code_page_dirty */
        EmitBtsMemReg       (cursor, kEcx, kEax);
        FixupLabel32(smc_restore, cursor);
        EmitPopReg          (cursor, kEcx);                     /* restore EA */
        FixupLabel32(smc_done_a, cursor);
        FixupLabel32(smc_done_b, cursor);
    }

    /* Hit: host = foldedVA + entry.va_addend (re-fold EA — EAX was clobbered). */
    EmitMovRegReg      (cursor, kEax, kEcx);
    EmitTestRegImm32   (cursor, kEax, 0xFE000000u);
    uint8_t* nf2 = EmitJnzLabel(cursor);
    EmitOrRegBaseDisp32(cursor, kEax, kMmuReg, pid);
    FixupLabel(nf2, cursor);
    EmitAddRegBaseDisp32(cursor, kEax, kEdx, e_add);
    uint8_t* hit_done = EmitJmpLabel32(cursor);

    /* Miss: slow path. ECX = EA already; EDX = jit (helper's __fastcall arg2). */
    for (int i = 0; i < nmiss; ++i) FixupLabel32(miss[i], cursor);
    EmitMovRegImm32(cursor, kEdx,
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ctx->jit)));
    void* helper =
        access == TlbAccess::kReadWrite
            ? reinterpret_cast<void*>(&ArmJit::TranslateReadWriteHelper)
        : access == TlbAccess::kWrite
            ? reinterpret_cast<void*>(&ArmJit::TranslateWriteHelper)
            : reinterpret_cast<void*>(&ArmJit::TranslateReadHelper);
    EmitCall(cursor, helper);

    FixupLabel32(hit_done, cursor);
    return cursor;
}
