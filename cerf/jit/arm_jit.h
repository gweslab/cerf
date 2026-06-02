#pragma once

#include <cstdint>
#include <cstring>
#include <mutex>

#include "../core/log.h"
#include "../core/service.h"
#include "arm_cpu.h"
#include "arm_jit_types.h"
#include "block_context.h"
#include "cpu_state.h"
#include "isa_block_space.h"
#include "jit_block_index.h"
#include "jit_code_arena.h"

class ArmDecoder;
class ArmMmu;
struct ArmMmuState;
class ArmProcessorConfig;
class CoprocEmitter;
class EmulatedMemory;

class ArmJit : public Service {
public:
    using Service::Service;
    ~ArmJit() override;

    void OnReady() override;

    ArmCpuState* CpuState() { return cpu_->State(); }

    ArmCpu* Cpu() { return cpu_; }

    void* FindBlockNativeStart(uint32_t guest_pc);

    /* Compile-time same-page chain resolve: the block at folded_va, but
       only if its phys_start == phys (rejects an FCSE-PID-reuse stale
       block at the same VA, which the place_fn must not bake a JMP to). */
    JitBlock* LookupBlockByVaPhys(uint32_t folded_va, uint32_t phys);

    void Run();

    /* MUST establish ESI = ArmCpuState* and EBX = ArmMmuState*
       before CALLing ECX — every Place fn emit addresses CPU/MMU
       fields off these pinned bases and reading anything else
       reads wrong state. */
    static void __cdecl Dispatch(void*        native_pc,
                                 ArmCpuState* state,
                                 ArmMmuState* mmu_state);

    ArmMmu* Mmu() { return mmu_; }

    class PeripheralDispatcher* Peripheral() { return peripheral_; }

    ArmProcessorConfig* ProcessorConfig() { return processor_config_; }

    CoprocEmitter* Coproc() { return coproc_emitter_; }

    ArmDecoder* Decoder() { return decoder_; }

    class ArmVfp* Vfp() { return vfp_; }

    class ArmNeon* Neon() { return neon_; }

    class ArmNeonSimd3Same* Simd3Same() { return simd3_same_; }

    class ArmNeonSat* NeonSat() { return neon_sat_; }

    class ArmNeonShiftImm* NeonShiftImm() { return neon_shift_imm_; }

    class ArmNeonOneRegImm* NeonOneRegImm() { return neon_one_reg_imm_; }

    class ArmNeon3DiffLen* Neon3DiffLen() { return neon_3difflen_; }

    class ArmNeon2RegScalar* Neon2RegScalar() { return neon_2regscalar_; }
    class ArmNeon2RegScalarMul* Neon2RegScalarMul() { return neon_2reg_scalar_mul_; }

    class ArmNeon2RegReverse*    Neon2RegReverse()    { return neon_2reg_reverse_; }
    class ArmNeon2RegBitcount*   Neon2RegBitcount()   { return neon_2reg_bitcount_; }
    class ArmNeon2RegBitwiseNot* Neon2RegBitwiseNot() { return neon_2reg_bitwise_not_; }
    class ArmNeon2RegUnaryArith* Neon2RegUnaryArith() { return neon_2reg_unary_arith_; }
    class ArmNeon2RegCompareZero* Neon2RegCompareZero() { return neon_2reg_compare_zero_; }
    class ArmNeon2RegPairwiseAddLong* Neon2RegPairwiseAddLong() { return neon_2reg_pairwise_add_long_; }
    class ArmNeon2RegSatAbsNeg* Neon2RegSatAbsNeg() { return neon_2reg_sat_abs_neg_; }
    class ArmNeon2RegSwap* Neon2RegSwap() { return neon_2reg_swap_; }
    class ArmNeon2RegShuffle* Neon2RegShuffle() { return neon_2reg_shuffle_; }
    class ArmNeon2RegNarrow* Neon2RegNarrow() { return neon_2reg_narrow_; }
    class ArmNeon2RegReciprocal* Neon2RegReciprocal() { return neon_2reg_reciprocal_; }
    class ArmNeon2RegCvtIntFp* Neon2RegCvtIntFp() { return neon_2reg_cvt_int_fp_; }
    class ArmNeon2RegCvtHalfSingle* Neon2RegCvtHalfSingle() { return neon_2reg_cvt_half_single_; }
    class ArmNeon3SameFpArith* Neon3SameFpArith() { return neon_3same_fp_arith_; }
    class ArmNeon3SameFpMulAcc* Neon3SameFpMulAcc() { return neon_3same_fp_mul_acc_; }
    class ArmNeon3SameFpMinMax* Neon3SameFpMinMax() { return neon_3same_fp_min_max_; }
    class ArmNeon3SameFpFma* Neon3SameFpFma() { return neon_3same_fp_fma_; }
    class ArmNeon3SameFpPairAdd* Neon3SameFpPairAdd() { return neon_3same_fp_pair_add_; }
    class ArmNeon3SameFpPairMinMax* Neon3SameFpPairMinMax() { return neon_3same_fp_pair_min_max_; }
    class ArmNeon3SameFpCompare* Neon3SameFpCompare() { return neon_3same_fp_compare_; }
    class ArmNeon3SameFpAbsCompare* Neon3SameFpAbsCompare() { return neon_3same_fp_abs_compare_; }
    class ArmNeon3SameFpRecipStep* Neon3SameFpRecipStep() { return neon_3same_fp_recip_step_; }
    class ArmNeonVext* NeonVext() { return neon_vext_; }
    class ArmNeonVtbl* NeonVtbl() { return neon_vtbl_; }
    class ArmNeonScalarMove* NeonScalarMove() { return neon_scalar_move_; }

    uint32_t* LdrUnalignedGuestAddressPtr() {
        return &ldr_unaligned_guest_address_;
    }

    uint32_t* EndEffectiveAddressPtr()    { return &end_effective_address_; }
    uint32_t* BaseAbortValuePtr()         { return &base_abort_value_; }
    uint32_t* StartPageHostAddressEndPtr(){ return &start_page_host_address_end_; }
    uint32_t* StartIoAddressPtr()         { return &start_io_address_; }
    uint32_t* StartPageIoAddressEndPtr()  { return &start_page_io_address_end_; }
    uint32_t* NextPageHostAddressPtr()    { return &next_page_host_address_; }
    uint32_t* NextPageIoAddressPtr()      { return &next_page_io_address_; }

    /* Cleared on every JitCodeArena flush — cached host pointers
       become stale the moment the arena reuses their slabs. */
    void* NativeAddr(ExceptionVector v) const {
        return native_addrs_[static_cast<uint32_t>(v)];
    }
    void SetNativeAddr(ExceptionVector v, void* p) {
        native_addrs_[static_cast<uint32_t>(v)] = p;
    }
    void FlushNativeAddrCache() {
        for (auto& a : native_addrs_) a = nullptr;
    }

    std::mutex& InterruptLock() { return interrupt_lock_; }

    void SignalIdleWake();

    void* IdleEvent() const { return idle_event_; }

    /* Caller MUST hold InterruptLock — the body try_locks + aborts
       if not held, since concurrent peripheral threads racing the
       trampoline-byte patch produces torn (cpsr, byte) state. */
    void UpdateInterruptOnPoll();

    /* SetEvent fires unconditionally outside the lock: conditional
       wake races CPSR.I clear from JIT thread and parks the
       dispatcher with an undelivered pending IRQ. */
    void SetInterruptPending();

    void ClearInterruptPending();

    void SetResetPending();

    /* JIT-emitted MCR p15 c15 c2 op_2=2 (SA-1110 Wait-For-Interrupt)
       calls this. Blocks on idle_event_ until a peripheral asserts an
       IRQ. Advances guest_cycle_counter by wallclock-elapsed*divider so
       OEMIdle's post-WFI OSCR read sees time having passed. */
    static void __fastcall WfiHelper(ArmJit* jit);

    /* __fastcall: ECX = va, EDX = tlb_hint, stack = jit. Nullptr
       return + io_pending_address_ set ⇒ peripheral I/O dispatch;
       nullptr without io_pending set ⇒ data abort. */
    /* __fastcall: ECX = va, EDX = jit. Slow path behind the JIT-emitted
       inline TLB fast probe — only reached on an inline miss. */
    static uint8_t* __fastcall TranslateReadHelper     (uint32_t va, ArmJit* jit);
    static uint8_t* __fastcall TranslateWriteHelper    (uint32_t va, ArmJit* jit);
    static uint8_t* __fastcall TranslateReadWriteHelper(uint32_t va, ArmJit* jit);

    static uint8_t* __fastcall MapGuestPhysicalToHostRamHelper(uint32_t paddr,
                                                               ArmJit*  jit);
    static uint8_t* __fastcall MapGuestPhysicalToHostHelper(uint32_t paddr,
                                                            ArmJit*  jit);

    static void __cdecl RaiseAlignmentExceptionHelper(ArmJit* jit, uint32_t va);

    static void* __cdecl FindBlockNativeStartHelper(ArmJit*  jit,
                                                    uint32_t guest_pc);

    /* One-byte naked RET — shadow-stack slots for "not yet jitted"
       return addresses point here so the eventual BX LR / MOV PC,LR
       RETs back to the dispatcher rather than JMPing into garbage. */
    static void NotJittedHelper();

    /* Self-modifying: patches [ESI] in place to JMP rel32 to the
       resolved entrypoint's native_start, FlushInstructionCache's
       the bytes, then JMPs back to ESI. */
    static void EntrypointEndHelper();

    /* __fastcall: ECX = RegisterList, EDX = jit. */
    static void __fastcall BlockDataTransferIOLoadHelper(uint32_t register_list, ArmJit* jit);
    static void __fastcall BlockDataTransferIOStoreHelper(uint32_t register_list, ArmJit* jit);

    /* __fastcall: ECX = RegisterListAndFlags, EDX = jit, stack =
       instruction_address (only used when R15 is in the list). */
    static void __fastcall BlockDataTransferIOHelperSlow(uint32_t register_list_and_flags,
                                                          ArmJit*  jit,
                                                          uint32_t instruction_address);

    /* __fastcall: ECX = rn_value, EDX = encoded (P<<7 | U<<6 | W<<5 |
       Rn[4:0]), stack = jit. Returns the masked new_pc in EAX. Applies
       CPSR from memory via UpdateCpsrWithFlags and writes back Rn before
       the CPSR change (ddi0406c B9.3.13 pseudocode). */
    static uint32_t __fastcall RfeHelper(uint32_t rn_value,
                                          uint32_t encoded,
                                          ArmJit*  jit);

    /* __fastcall: ECX = encoded (P<<7 | U<<6 | W<<5 | target_mode[4:0]),
       EDX = jit, stack = guest_pc (for diagnostics). Writes current-mode
       LR + SPSR to the target mode's banked stack; optional writeback
       to the target mode's R13 (ddi0406c B9.3.16 pseudocode). */
    static void __fastcall SrsHelper(uint32_t encoded,
                                      ArmJit*  jit,
                                      uint32_t guest_pc);

    /* (0, 0xFFFFFFFF) = whole-cache flush. va/length are widened
       to per-SoC cache-line size before the range-overlap check. */
    void FlushTranslationCache(uint32_t va, uint32_t length);

    static void __cdecl FlushTranslationCacheStaticHelper(ArmJit*  jit,
                                                          uint32_t va,
                                                          uint32_t length);

    void* FlushTranslationCacheTrampoline() {
        return flush_translation_cache_helper_;
    }

    /* Context switch (FCSE PID / TTBR0 / CONTEXTIDR change): drop the
       VA-keyed native caches. NOT a TC flush — phys-keyed blocks survive
       and the current block keeps executing. */
    void ContextSwitchFlush();
    static void __fastcall ContextSwitchFlushHelper(ArmJit* jit);

    /* SMC: on an I-cache invalidate, drop blocks on phys pages written since
       the last invalidate (the code_page_dirty set in ArmMmuState) — targeted,
       not a whole-cache flush. */
    void InvalidateDirtyCodePages();
    static void __fastcall InvalidateDirtyCodePagesHelper(ArmJit* jit);

private:
    JitCodeArena    arena_;
    IsaBlockSpace   blocks_arm_;
    IsaBlockSpace   blocks_thumb_;
    BlockContext    block_ctx_{};

    ArmCpu*                       cpu_              = nullptr;
    ArmMmu*                       mmu_              = nullptr;
    EmulatedMemory*               memory_           = nullptr;
    class PeripheralDispatcher*   peripheral_       = nullptr;
    ArmProcessorConfig*           processor_config_ = nullptr;
    CoprocEmitter*                coproc_emitter_   = nullptr;
    ArmDecoder*                   decoder_          = nullptr;
    class ArmVfp*                 vfp_              = nullptr;
    class ArmNeon*                neon_             = nullptr;
    class ArmNeonSimd3Same*       simd3_same_       = nullptr;
    class ArmNeonSat*             neon_sat_         = nullptr;
    class ArmNeonShiftImm*        neon_shift_imm_   = nullptr;
    class ArmNeonOneRegImm*       neon_one_reg_imm_ = nullptr;
    class ArmNeon3DiffLen*        neon_3difflen_    = nullptr;
    class ArmNeon2RegScalar*      neon_2regscalar_       = nullptr;
    class ArmNeon2RegScalarMul*   neon_2reg_scalar_mul_  = nullptr;
    class ArmNeon2RegReverse*     neon_2reg_reverse_      = nullptr;
    class ArmNeon2RegBitcount*    neon_2reg_bitcount_     = nullptr;
    class ArmNeon2RegBitwiseNot*  neon_2reg_bitwise_not_  = nullptr;
    class ArmNeon2RegUnaryArith*  neon_2reg_unary_arith_  = nullptr;
    class ArmNeon2RegCompareZero* neon_2reg_compare_zero_     = nullptr;
    class ArmNeon2RegPairwiseAddLong* neon_2reg_pairwise_add_long_ = nullptr;
    class ArmNeon2RegSatAbsNeg* neon_2reg_sat_abs_neg_       = nullptr;
    class ArmNeon2RegSwap*      neon_2reg_swap_              = nullptr;
    class ArmNeon2RegShuffle*   neon_2reg_shuffle_           = nullptr;
    class ArmNeon2RegNarrow*    neon_2reg_narrow_            = nullptr;
    class ArmNeon2RegReciprocal* neon_2reg_reciprocal_       = nullptr;
    class ArmNeon2RegCvtIntFp*   neon_2reg_cvt_int_fp_        = nullptr;
    class ArmNeon2RegCvtHalfSingle* neon_2reg_cvt_half_single_ = nullptr;
    class ArmNeon3SameFpArith*  neon_3same_fp_arith_         = nullptr;
    class ArmNeon3SameFpMulAcc* neon_3same_fp_mul_acc_       = nullptr;
    class ArmNeon3SameFpMinMax* neon_3same_fp_min_max_       = nullptr;
    class ArmNeon3SameFpFma*    neon_3same_fp_fma_           = nullptr;
    class ArmNeon3SameFpPairAdd* neon_3same_fp_pair_add_     = nullptr;
    class ArmNeon3SameFpPairMinMax* neon_3same_fp_pair_min_max_ = nullptr;
    class ArmNeon3SameFpCompare* neon_3same_fp_compare_       = nullptr;
    class ArmNeon3SameFpAbsCompare* neon_3same_fp_abs_compare_ = nullptr;
    class ArmNeon3SameFpRecipStep* neon_3same_fp_recip_step_  = nullptr;
    class ArmNeonVext*          neon_vext_                   = nullptr;
    class ArmNeonVtbl*          neon_vtbl_                   = nullptr;
    class ArmNeonScalarMove*    neon_scalar_move_            = nullptr;

    uint32_t        ldr_unaligned_guest_address_ = 0;

    uint32_t        end_effective_address_         = 0;
    uint32_t        base_abort_value_              = 0;
    uint32_t        start_page_host_address_end_   = 0;
    uint32_t        start_io_address_              = 0;
    uint32_t        start_page_io_address_end_     = 0;
    uint32_t        next_page_host_address_        = 0;
    uint32_t        next_page_io_address_          = 0;

    void*           native_addrs_[static_cast<uint32_t>(ExceptionVector::kCount)] = {nullptr};

    uint8_t*        interrupt_check_                = nullptr;
    uint8_t*        r15_modified_helper_            = nullptr;
    uint8_t*        branch_helper_                  = nullptr;
    uint8_t*        cross_page_branch_helper_       = nullptr;
    uint8_t*        shadow_stack_helper_            = nullptr;
    uint8_t*        pop_shadow_stack_helper_        = nullptr;
    uint8_t*        raise_abort_data_helper_        = nullptr;
    uint8_t*        block_usermode_helper_          = nullptr;
    uint8_t*        flush_translation_cache_helper_ = nullptr;

    void*           idle_event_ = nullptr;

    std::mutex      interrupt_lock_;

    /* JIT thread reads/writes shadow_stack_ without locking;
       cross-thread access would race. */
    ShadowStackEntry shadow_stack_[256]{};
    uint8_t          shadow_stack_count_ = 0;

    void SetInterruptPendingLocked();

#if CERF_DEV_MODE
    static void __cdecl TraceDispatchPcHelper(ArmJit* jit, uint32_t pc, ArmCpuState* state);
#endif
    void InitializeInterruptCheck();
    void InitializeR15ModifiedHelper();
    void InitializeBranchHelper();
    void InitializeCrossPageBranchHelper();
    void InitializeShadowStackHelper();
    void InitializePopShadowStackHelper();
    void InitializeRaiseAbortDataHelper();
    void InitializeBlockUsermodeHelper();
    void InitializeFlushTranslationCacheHelper();

    /* Block lookup for the current ISA + ASID: probe
       per_asid[CONTEXTIDR&0xFF] first, then the shared global tree.
       Inputs are already FCSE-folded by the caller. */
    JitBlock* LookupBlockExact(uint32_t folded_va);
    JitBlock* LookupBlockContaining(uint32_t folded_va);
    uint32_t  NextBlockStart(uint32_t folded_va);

    void* JitCompile(uint32_t guest_pc);

    void JitDecode(JitBlock* containing_block, uint32_t guest_pc);

    int JitOptimizeIR();

    int LocateEntrypoints();

    void JitCreateEntrypoints(JitBlock* containing_block,
                              uint8_t*  prefix_slab);

    void OptimizeARMFlags();

    size_t JitGenerateCode(uint8_t* code_location, int entrypoint_count);

    void JitApplyFixups();

};
