#include "arm_mmu_probe.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/arm_processor_config.h"
#include "../../cpu/emulated_memory.h"
#include "../../cpu/physical_address_mapper.h"
#include "arm_mmu.h"
#include "arm_pte.h"

REGISTER_SERVICE(ArmMmuProbe);

bool ArmMmuProbe::ShouldRegister() {
    return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
}

void ArmMmuProbe::OnReady() {
    state_p_          = emu_.Get<ArmMmu>().State();
    memory_           = &emu_.Get<EmulatedMemory>();
    processor_config_ = &emu_.Get<ArmProcessorConfig>();
    address_mapper_   = &emu_.Get<PhysicalAddressMapper>();
}

std::optional<uint32_t> ArmMmuProbe::WalkVaToPa(uint32_t va) {
    const ArmMmuState& state_ = *state_p_;
    const uint32_t p = ArmFcseFold(va, state_.process_id);

    const uint32_t l1_pa = ArmL1DescriptorAddress(
        p, state_.ttbcr, state_.translation_table_base.word, state_.ttbr1);
    uint8_t* l1_host = memory_->TryTranslateWrite(l1_pa);
    if (!l1_host) return std::nullopt;
    ArmL1Pte l1_pte;
    l1_pte.word = *reinterpret_cast<uint32_t*>(l1_host);

    switch (l1_pte.fault.type) {
    case ArmL1PteType::kSection: {
        const ArmSupersectionFormat format = ArmEffectiveSupersectionFormat(
            processor_config_->SupersectionFormat(), state_.effective_control_register.bits.xp);
        const ArmSectionTranslation translation =
            ArmTranslateSection(l1_pte.word, p, format);
        uint32_t system_pa = 0;
        if (!address_mapper_->Map(translation.physical_address, 1u, system_pa))
            return std::nullopt;
        return system_pa;
    }

    case ArmL1PteType::kCoarse: {
        const uint32_t l2_pa = (l1_pte.coarse.page_table_base << 10)
                             | (((p >> 12) & 0xFFu) << 2);
        uint8_t* l2_host = memory_->TryTranslateWrite(l2_pa);
        if (!l2_host) return std::nullopt;
        ArmL2Pte l2_pte;
        l2_pte.word = *reinterpret_cast<uint32_t*>(l2_host);

        const bool v6_ext_small = processor_config_->HasCp15V6() &&
                                  !state_.effective_control_register.bits.xp;
        uint32_t cpu_pa = 0;
        if (l2_pte.fault.type == ArmL2PteType::kSmallPage) {
            cpu_pa = (l2_pte.small_page.small_page_base << 12) | (p & 0x0FFFu);
        } else if (l2_pte.fault.type == ArmL2PteType::kExtendedSmallPage && v6_ext_small) {
            cpu_pa = ArmExtSmallPagePa(l2_pte.word, p);
        } else {
            return std::nullopt;
        }
        uint32_t system_pa = 0;
        if (!address_mapper_->Map(cpu_pa, 1u, system_pa)) return std::nullopt;
        return system_pa;
    }

    default:
        return std::nullopt;
    }
}

const ArmTlbEntry* ArmMmuProbe::MatchDataTlb(uint32_t va, uint32_t* folded) const {
    const ArmMmuState& state_ = *state_p_;
    const uint32_t p = ArmFcseFold(va, state_.process_id);
    *folded = p;
    const uint8_t current_asid = static_cast<uint8_t>(state_.contextidr & 0xFFu);
    const uint32_t base = ArmTlbSetBase(p);
    const int w = ArmTlbMatchWay(&state_.data_tlb, base, p & 0xFFFFF000u,
                                 current_asid, false);
    if (w < 0) return nullptr;
    return &state_.data_tlb.entries[base + static_cast<uint32_t>(w)];
}

std::optional<uint8_t*> ArmMmuProbe::PeekDataTlb(uint32_t va) const {
    uint32_t p = 0;
    const ArmTlbEntry* e = MatchDataTlb(va, &p);
    if (!e) return std::nullopt;
    return reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(p) + e->va_addend);
}

bool ArmMmuProbe::ExecPageGlobal(uint32_t folded_va) const {
    const ArmMmuState& state_ = *state_p_;
    const uint8_t current_asid = static_cast<uint8_t>(state_.contextidr & 0xFFu);
    const uint32_t base = ArmTlbSetBase(folded_va);
    const int w = ArmTlbMatchWay(&state_.instruction_tlb, base,
                                 folded_va & 0xFFFFF000u, current_asid,
                                 /*need_write=*/false);
    return w >= 0 &&
           state_.instruction_tlb.entries[base + static_cast<uint32_t>(w)].global != 0u;
}

uint8_t* ArmMmuProbe::PeekVaToHost(uint32_t va) {
    const ArmMmuState& state_ = *state_p_;
    if (!state_.effective_control_register.bits.m) {
        const uint32_t pa = ArmFcseFold(va, state_.process_id);
        uint8_t* ram = memory_->TryTranslateWrite(pa);
        return ram ? ram : memory_->TryTranslate(pa);
    }

    if (std::optional<uint8_t*> tlb = PeekDataTlb(va)) return *tlb;

    std::optional<uint32_t> pa = WalkVaToPa(va);
    if (!pa) return nullptr;
    uint8_t* ram = memory_->TryTranslateWrite(*pa);
    return ram ? ram : memory_->TryTranslate(*pa);
}

bool ArmMmuProbe::PeekVaToPa(uint32_t va, uint32_t* pa) {
    const ArmMmuState& state_ = *state_p_;
    if (!state_.effective_control_register.bits.m) {
        *pa = ArmFcseFold(va, state_.process_id);
        return true;
    }

    uint32_t p = 0;
    if (const ArmTlbEntry* e = MatchDataTlb(va, &p)) {
        *pa = e->pa_page | (p & 0x0FFFu);
        return true;
    }

    std::optional<uint32_t> walked = WalkVaToPa(va);
    if (!walked) return false;
    *pa = *walked;
    return true;
}
