#include "arm_mmu.h"

#include <cstring>

#include "../../boards/board_context.h"
#include "../../boards/page_table_builder.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/arm_processor_config.h"
#include "../../cpu/emulated_memory.h"
#include "../../cpu/physical_address_mapper.h"
#include "arm_cpu.h"
#include "arm_page_walker.h"
#include "arm_tlb_ops.h"
#include "arm_translation_cache.h"
#include "../../state/state_stream.h"

REGISTER_SERVICE(ArmMmu);

bool ArmMmu::ShouldRegister() {
    return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
}

ArmMmu::~ArmMmu() = default;

bool ArmMmu::UnalignedAccessesFault() const {
    return processor_config_->HasCp15V7() ||
           (processor_config_->HasCp15V6() &&
            state_.effective_control_register.bits.u);
}

bool ArmMmu::AlignMultiWordOrFault(uint32_t& address, bool is_write) {
    if (!UnalignedAccessesFault() &&
        !state_.effective_control_register.bits.a) {
        address &= 0xFFFFFFFCu;
        return false;
    }
    if ((address & 3u) != 0u) {
        RaiseAlignmentFault(address, is_write);
        return true;
    }
    return false;
}

uint32_t ArmMmu::DoublewordAlignMask() const {
    return (processor_config_->HasCp15V6() && !processor_config_->HasCp15V7() &&
            !state_.effective_control_register.bits.u)
               ? 7u : 3u;
}

void ArmMmu::SaveState(StateWriter& w) {
    w.Write(state_.control_register);
    w.Write(state_.effective_control_register);
    w.Write(state_.aux_control_register);
    w.Write(state_.translation_table_base);
    w.Write(state_.domain_access_control);
    w.Write(state_.fault_status);
    w.Write(state_.fault_address);
    w.Write(state_.ifsr);
    w.Write(state_.ifar);
    w.Write(state_.process_id);
    w.Write(state_.coprocessor_access);
    w.Write(state_.cssel_register);
    w.Write(state_.ttbr1);
    w.Write(state_.ttbcr);
    w.Write(state_.prrr);
    w.Write(state_.nmrr);
    w.Write(state_.contextidr);
    w.Write(state_.tpidrurw);
    w.Write(state_.tpidruro);
    w.Write(state_.tpidrprw);
    w.Write(state_.l2_aux_control);
}

void ArmMmu::RestoreState(StateReader& r) {
    r.Read(state_.control_register);
    r.Read(state_.effective_control_register);
    r.Read(state_.aux_control_register);
    r.Read(state_.translation_table_base);
    r.Read(state_.domain_access_control);
    r.Read(state_.fault_status);
    r.Read(state_.fault_address);
    r.Read(state_.ifsr);
    r.Read(state_.ifar);
    r.Read(state_.process_id);
    r.Read(state_.coprocessor_access);
    r.Read(state_.cssel_register);
    r.Read(state_.ttbr1);
    r.Read(state_.ttbcr);
    r.Read(state_.prrr);
    r.Read(state_.nmrr);
    r.Read(state_.contextidr);
    r.Read(state_.tpidrurw);
    r.Read(state_.tpidruro);
    r.Read(state_.tpidrprw);
    r.Read(state_.l2_aux_control);
    /* Restored TTBR0/process_id/contextidr differ from the live TLBs'
       context; a stale entry would return the prior context's PA. */
    ArmTlbFlushAll(&state_.data_tlb);
    ArmTlbFlushAll(&state_.instruction_tlb);
}

void ArmMmu::ResetControlRegisters() {
    /* ARM DDI 0100I B3.4.1 (p. B3-12): "Apart from bits that read as 1
       according to this rule, all bits in CP15 register 1 are set to 0 on
       reset." VMSAv7 leaves the value IMPLEMENTATION DEFINED (ARM DDI
       0406C.c "Reset value of the SCTLR", p. B4-1713). */
    state_.control_register.word = 0;

    /* ARM DDI 0406C.c B4.1.40 (p. B4-1553): "When implemented as an RW
       field, cpn resets to zero." */
    state_.coprocessor_access = 0;

    /* ARM DDI 0406C.c B4.1.153 (p. B4-1724): TTBCR is "A 32-bit RW register
       that resets to zero". */
    state_.ttbcr = 0;

    /* ARM DDI 0100I B8.3 (p. B8-5): "the PID is initialized to 0b0000000 on
       reset, resulting in the FCSE being effectively disabled." */
    state_.process_id = 0;

    /* ARM DDI 0406C.c Glossary "Context synchronization operation": taking an
       exception is one, and B3.15.5 (p. B3-1461) puts the explicit
       synchronization at its first step, so the reset values are in effect
       for the instruction fetched at the reset entry. */
    state_.effective_control_register = state_.control_register;

    ArmTlbFlushAll(&state_.data_tlb);
    ArmTlbFlushAll(&state_.instruction_tlb);
}

void ArmMmu::InvalidateAllTlbs() {
    ArmTlbFlushAll(&state_.instruction_tlb);
    ArmTlbFlushAll(&state_.data_tlb);
}

void ArmMmu::SynchronizeSctlr() {
    if (state_.effective_control_register.word == state_.control_register.word) {
        return;
    }
    state_.effective_control_register = state_.control_register;
    InvalidateAllTlbs();
    emu_.Get<ArmTranslationCache>().InvalidateVaCachesAll();
}

uint8_t* __fastcall ArmMmu::TranslateReadHelper(uint32_t va, ArmMmu* mmu) {
    return mmu->walker_->TranslateRead(mmu->cpu_state_, va);
}

uint8_t* __fastcall ArmMmu::TranslateWriteHelper(uint32_t va, ArmMmu* mmu) {
    return mmu->walker_->TranslateWrite(mmu->cpu_state_, va);
}

uint8_t* __fastcall ArmMmu::TranslateReadWriteHelper(uint32_t va, ArmMmu* mmu) {
    return mmu->walker_->TranslateReadWrite(mmu->cpu_state_, va);
}

uint8_t* __fastcall ArmMmu::TranslateUserReadHelper(uint32_t va, ArmMmu* mmu) {
    return mmu->walker_->TranslateUserRead(mmu->cpu_state_, va);
}

uint8_t* __fastcall ArmMmu::TranslateUserWriteHelper(uint32_t va, ArmMmu* mmu) {
    return mmu->walker_->TranslateUserWrite(mmu->cpu_state_, va);
}

void ArmMmu::OnReady() {
    memory_           = &emu_.Get<EmulatedMemory>();
    processor_config_ = &emu_.Get<ArmProcessorConfig>();
    address_mapper_   = &emu_.Get<PhysicalAddressMapper>();
    cpu_state_        = emu_.Get<ArmCpu>().State();
    state_.data_tlb.span_tracker = &data_tlb_span_tracker_;
    state_.instruction_tlb.span_tracker = &instruction_tlb_span_tracker_;

    /* SMC word-bitmap spans the board's DRAM PA extent only: code is
       writable (hence self-modifiable) solely in DRAM, so a write outside
       this range can never invalidate a translation. */
    uint32_t dram_min = 0xFFFFFFFFu;
    uint32_t dram_max = 0u;
    for (const auto& r : emu_.Get<PageTableBuilder>().CachedDramRegions()) {
        if (r.pa_base < dram_min)          dram_min = r.pa_base;
        if (r.pa_base + r.size > dram_max) dram_max = r.pa_base + r.size;
    }
    state_.code_word_base         = dram_min;
    state_.code_word_top          = dram_max;
    state_.code_word_bitmap_bytes =
        (dram_max > dram_min) ? (((dram_max - dram_min) >> 2) + 7u) / 8u : 0u;

    code_xlat_bitmap_storage_.assign(state_.code_word_bitmap_bytes, 0u);
    state_.code_xlat_bitmap = code_xlat_bitmap_storage_.data();

    state_.code_page_dirty_bytes =
        (dram_max > dram_min) ? (((dram_max - dram_min) >> 12) + 7u) / 8u : 0u;
    code_page_dirty_storage_.assign(state_.code_page_dirty_bytes, 0u);
    state_.code_page_dirty = code_page_dirty_storage_.data();

    ArmTlbFlushAll(&state_.data_tlb);
    ArmTlbFlushAll(&state_.instruction_tlb);
}

uint32_t __fastcall ArmMmu::CcsidrLookupHelper(ArmMmu* mmu) {
    /* cp15 c0 op1=1 CRm=0 op2=0 (CCSIDR), indexed by CSSELR.
       Reference: QEMU helper.c:942-947, cpu.h:1131-1134. */
    return mmu->emu_.Get<ArmProcessorConfig>().Ccsidr(mmu->state_.cssel_register);
}

/* ARM DDI 0406C.c Table B3-26 (p. B3-1418): Prefetch Abort faults update
   IFSR+IFAR only, Data Abort faults DFSR+DFAR only. B4.1.52 + Table B3-27:
   DFSR.Domain is UNKNOWN on alignment and first-level faults, so 0 is
   permitted there. */
void ArmMmu::RaiseAbort(uint32_t va, uint32_t fault_status, uint32_t domain,
                        ArmMmuAccess access) {
    if (access == ArmMmuAccess::kExecute) {
        if (processor_config_->HasCp15V6()) {
            /* B4.1.96: IFSR carries FS[3:0] (FS[4] is 0 for every Table
               B3-23 code CERF raises), no Domain, no WnR. */
            state_.ifsr = fault_status;
            state_.ifar = va;
            return;
        }
        /* ARM DDI 0406C.c D15.7.6 (p. D15-2623): the single ARMv4/v5 FSR
           "is updated on Prefetch Abort exceptions and Data Abort
           exceptions"; the FAR "is only updated with the MVA on Data
           Abort exceptions". FSR = Domain[7:4] + FS[3:0]. */
        ArmDfsr fsr{};
        fsr.bits.status      = fault_status;
        fsr.bits.domain      = domain;
        state_.fault_status  = fsr;
        return;
    }
    ArmDfsr dfsr{};
    dfsr.bits.status     = fault_status;
    dfsr.bits.domain     = domain;
    /* WnR is DFSR[11] (B4.1.52); D15.7.6 makes v4/v5 FSR bits[31:11]
       UNK/SBZP, so the write is permitted there too. */
    dfsr.bits.wnr        = (access == ArmMmuAccess::kWrite ||
                            access == ArmMmuAccess::kReadWrite) ? 1u : 0u;
    state_.fault_status  = dfsr;
    state_.fault_address = va;
}

void ArmMmu::RaiseAlignmentFault(uint32_t va, bool is_write) {
    ArmDfsr dfsr{};
    dfsr.bits.status     = ArmFaultStatus::kAlignment;
    dfsr.bits.wnr        = is_write ? 1u : 0u;
    state_.fault_status  = dfsr;
    state_.fault_address = va;
    ClearIoPending();
}

void __fastcall ArmMmu::AlignmentFaultReadHelper(uint32_t va, ArmMmu* mmu) {
    mmu->RaiseAlignmentFault(va, /*is_write=*/false);
}

void __fastcall ArmMmu::AlignmentFaultWriteHelper(uint32_t va, ArmMmu* mmu) {
    mmu->RaiseAlignmentFault(va, /*is_write=*/true);
}

uint32_t __cdecl ArmMmu::UnalignedHalfwordLoadHelper(ArmMmu* mmu, uint32_t va,
                                                     uint32_t force_user) {
    ArmCpuState* cs = mmu->emu_.Get<ArmCpu>().State();
    const bool   fu = force_user != 0u;
    uint8_t b[2];
    if (!mmu->AccessPaged(cs, va,      &b[0], 1, /*is_load=*/true, fu) ||
        !mmu->AccessPaged(cs, va + 1u, &b[1], 1, /*is_load=*/true, fu)) {
        return 0xFFFFFFFFu;
    }
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8);
}

uint32_t __cdecl ArmMmu::UnalignedHalfwordStoreHelper(ArmMmu* mmu, uint32_t va,
                                                      uint32_t value,
                                                      uint32_t force_user) {
    ArmCpuState* cs = mmu->emu_.Get<ArmCpu>().State();
    const bool   fu = force_user != 0u;
    uint8_t b[2] = { static_cast<uint8_t>(value),
                     static_cast<uint8_t>(value >> 8) };
    if (!mmu->AccessPaged(cs, va,      &b[0], 1, /*is_load=*/false, fu) ||
        !mmu->AccessPaged(cs, va + 1u, &b[1], 1, /*is_load=*/false, fu)) {
        return 0xFFFFFFFFu;
    }
    return 0u;
}

uint64_t __cdecl ArmMmu::UnalignedWordLoadHelper(ArmMmu* mmu, uint32_t va,
                                                 uint32_t force_user) {
    ArmCpuState* cs = mmu->emu_.Get<ArmCpu>().State();
    const bool   fu = force_user != 0u;
    uint8_t b[4];
    for (uint32_t i = 0; i < 4u; ++i) {
        if (!mmu->AccessPaged(cs, va + i, &b[i], 1, /*is_load=*/true, fu)) {
            return 0u;
        }
    }
    const uint32_t value = static_cast<uint32_t>(b[0]) |
                           (static_cast<uint32_t>(b[1]) << 8) |
                           (static_cast<uint32_t>(b[2]) << 16) |
                           (static_cast<uint32_t>(b[3]) << 24);
    return (1ull << 32) | value;
}

uint32_t __cdecl ArmMmu::UnalignedWordStoreHelper(ArmMmu* mmu, uint32_t va,
                                                  uint32_t value,
                                                  uint32_t force_user) {
    ArmCpuState* cs = mmu->emu_.Get<ArmCpu>().State();
    const bool   fu = force_user != 0u;
    uint8_t b[4] = { static_cast<uint8_t>(value),
                     static_cast<uint8_t>(value >> 8),
                     static_cast<uint8_t>(value >> 16),
                     static_cast<uint8_t>(value >> 24) };
    for (uint32_t i = 0; i < 4u; ++i) {
        if (!mmu->AccessPaged(cs, va + i, &b[i], 1, /*is_load=*/false, fu)) {
            return 0xFFFFFFFFu;
        }
    }
    return 0u;
}

void ArmMmu::SetIoPending(uint32_t pa) {
    io_pending_address_ = pa;
    io_pending_valid_   = 1u;
}

bool ArmMmu::MapPhysicalAddress(uint64_t cpu_pa, uint32_t va,
                                uint32_t domain, ArmMmuAccess access,
                                uint32_t& system_pa) {
    if (address_mapper_->Map(cpu_pa, 1u, system_pa)) return true;
    RaiseAbort(va, ArmFaultStatus::kExternalAbort, domain, access);
    return false;
}

bool ArmMmu::AccessPaged(ArmCpuState* cpu_state, uint32_t va,
                         uint8_t* host_buf, uint32_t n, bool is_load,
                         bool force_user, uint32_t* completed) {
    for (uint32_t done = 0; done < n; ) {
        const uint32_t va_cur = va + done;
        uint8_t* host;
        if (force_user) {
            host = is_load ? walker_->TranslateUserRead (cpu_state, va_cur)
                           : walker_->TranslateUserWrite(cpu_state, va_cur);
        } else {
            host = is_load ? walker_->TranslateRead (cpu_state, va_cur)
                           : walker_->TranslateWrite(cpu_state, va_cur);
        }
        if (host == nullptr) {
            if (completed != nullptr) *completed = done;
            return false;
        }
        /* ARM DDI 0406C.c Table D15-10 (p. D15-2609): a Tiny page maps 1 KB. */
        const uint32_t page_left = 0x400u - (va_cur & 0x3FFu);
        const uint32_t chunk = (n - done < page_left) ? (n - done) : page_left;
        if (is_load) std::memcpy(host_buf + done, host, chunk);
        else         std::memcpy(host, host_buf + done, chunk);
        done += chunk;
    }
    return true;
}
