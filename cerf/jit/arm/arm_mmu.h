#pragma once

#include <cstdint>
#include <vector>

#include "../../core/service.h"
#include "arm_mmu_state.h"
#include "cpu_state.h"

class ArmPageWalker;
class ArmProcessorConfig;
class EmulatedMemory;
class PhysicalAddressMapper;
class StateWriter;
class StateReader;

class ArmMmu : public Service {
public:
    using Service::Service;
    ~ArmMmu() override;

    void OnReady() override;
    bool ShouldRegister() override;

    ArmMmuState* State() { return &state_; }

    /* Table A3-1 (p. A3-108) and Table D12-1 (D12.3.1, p. D12-2506) give the
       alignment model by architecture version and SCTLR.U; D15.3.1
       (p. D15-2592) gives the v4/v5 legacy behaviour. */
    bool     UnalignedAccessesFault() const;
    uint32_t DoublewordAlignMask()    const;

    /* DDI 0211I Table 4-2 (p. 4-17) puts LDC/LDM/RFE/SRS/STC/STM in the
       Multi-word access type; Table 4-3 (pp. 4-19/4-20) gives A=0 U=0
       Word[Align32(Addr)] "unaffected by Addr[1:0]", and Alignment fault
       for unaligned Multi-word at A=0 U=1 and at A=1. */
    bool     AlignMultiWordOrFault(uint32_t& address, bool is_write);

    /* Persistent cp15 registers only. TLBs + SMC bitmaps are derived;
       RestoreState flushes the TLBs, the JIT TC flush clears the rest. */
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

    /* ARM DDI 0406C.c B1.9.1 TakeReset() -> ResetControlRegisters(); B3.15.2
       (p. B3-1450) requires a reset value for "The SCTLR, CPACR, and TTBCR"
       and for "The FCSEIDR, if the implementation includes the Fast Context
       Switch Extension", and leaves every other register UNKNOWN. */
    void ResetControlRegisters();

    void InvalidateAllTlbs();
    void SynchronizeSctlr();

    void BindWalker(ArmPageWalker* walker) { walker_ = walker; }

    static uint8_t* __fastcall TranslateReadHelper(uint32_t va, ArmMmu* mmu);
    static uint8_t* __fastcall TranslateWriteHelper(uint32_t va, ArmMmu* mmu);
    static uint8_t* __fastcall TranslateReadWriteHelper(uint32_t va, ArmMmu* mmu);

    /* LDRT/STRT-class user-forced walks (ARM DDI 0100I A4.1.25 p. A4-48 /
       A4.1.105 p. A4-206). */
    static uint8_t* __fastcall TranslateUserReadHelper(uint32_t va, ArmMmu* mmu);
    static uint8_t* __fastcall TranslateUserWriteHelper(uint32_t va, ArmMmu* mmu);

    /* Word-aligned VFP/NEON multi-byte loads may page-cross (ARM ARM DDI0406C A3.2 Table A3-1). */
    bool AccessPaged(ArmCpuState* cpu_state, uint32_t va,
                     uint8_t* host_buf, uint32_t n, bool is_load,
                     bool force_user = false, uint32_t* completed = nullptr);

    uint32_t io_pending_address() const { return io_pending_address_; }

    bool io_pending() const { return io_pending_valid_ != 0u; }

    void ClearIoPending() {
        io_pending_valid_   = 0u;
        io_pending_address_ = 0u;
    }

    uint32_t* IoPendingAddressPtr() { return &io_pending_address_; }
    uint32_t* IoPendingValidPtr()   { return &io_pending_valid_; }

    /* cp15 c0 op1=1 CRm=0 op2=0 (CCSIDR), indexed by CSSELR.
       Called from JIT only when HasCp15V7() is true.
       __fastcall: ECX = mmu pointer; return in EAX. */
    static uint32_t __fastcall CcsidrLookupHelper(ArmMmu* mmu);

    /* Set FAR + FSR.status = kAlignment for an alignment data abort;
       caller signals the abort via ArmCpu::RaiseAbortDataException. */
    void RaiseAlignmentFault(uint32_t va, bool is_write);

    static void __fastcall AlignmentFaultReadHelper(uint32_t va, ArmMmu* mmu);
    static void __fastcall AlignmentFaultWriteHelper(uint32_t va, ArmMmu* mmu);

    /* Out: zero-extended halfword (load) / 0 (store); 0xFFFFFFFF = fault,
       FAR/FSR or the io-pending slot set by the walk. */
    static uint32_t __cdecl UnalignedHalfwordLoadHelper(ArmMmu* mmu,
                                                        uint32_t va,
                                                        uint32_t force_user);
    static uint32_t __cdecl UnalignedHalfwordStoreHelper(ArmMmu* mmu,
                                                         uint32_t va,
                                                         uint32_t value,
                                                         uint32_t force_user);

    /* Out: EDX:EAX - high dword 1 (value in the low dword) / 0 = fault,
       FAR/FSR or the io-pending slot set by the walk. */
    static uint64_t __cdecl UnalignedWordLoadHelper(ArmMmu* mmu, uint32_t va,
                                                    uint32_t force_user);
    /* Out: 0 (stored) / 0xFFFFFFFF = fault. */
    static uint32_t __cdecl UnalignedWordStoreHelper(ArmMmu* mmu, uint32_t va,
                                                     uint32_t value,
                                                     uint32_t force_user);

    void RaiseAbort(uint32_t va, uint32_t fault_status, uint32_t domain,
                    ArmMmuAccess access);

    bool MapPhysicalAddress(uint64_t cpu_pa, uint32_t va, uint32_t domain,
                            ArmMmuAccess access, uint32_t& system_pa);

    void SetIoPending(uint32_t pa);

private:
    ArmMmuState         state_{};
    ArmPageWalker*      walker_           = nullptr;
    EmulatedMemory*     memory_           = nullptr;
    ArmProcessorConfig* processor_config_ = nullptr;
    PhysicalAddressMapper* address_mapper_ = nullptr;
    ArmCpuState*        cpu_state_        = nullptr;

    uint32_t io_pending_address_ = 0;
    uint32_t io_pending_valid_   = 0;

    /* Backing stores for the SMC bitmaps (code_xlat_bitmap word-marks +
       code_page_dirty page set). Sized once in OnReady, never resized, so
       the data() pointers stay stable for the JIT/MMU bitmap accesses. */
    std::vector<uint8_t> code_xlat_bitmap_storage_;
    std::vector<uint8_t> code_page_dirty_storage_;
    ArmTlbSpanTracker data_tlb_span_tracker_;
    ArmTlbSpanTracker instruction_tlb_span_tracker_;
};
