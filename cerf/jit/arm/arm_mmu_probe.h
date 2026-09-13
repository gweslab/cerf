#pragma once

#include <cstdint>
#include <optional>

#include "../../core/service.h"
#include "arm_mmu_state.h"

class ArmProcessorConfig;
class EmulatedMemory;
class PhysicalAddressMapper;

class ArmMmuProbe : public Service {
public:
    using Service::Service;

    void OnReady() override;
    bool ShouldRegister() override;

    uint8_t* PeekVaToHost(uint32_t va);
    bool     PeekVaToPa(uint32_t va, uint32_t* pa);

    std::optional<uint8_t*> PeekDataTlb(uint32_t va) const;

    bool ExecPageGlobal(uint32_t folded_va) const;

private:
    std::optional<uint32_t> WalkVaToPa(uint32_t va);

    const ArmTlbEntry* MatchDataTlb(uint32_t va, uint32_t* folded) const;

    ArmMmuState*        state_p_          = nullptr;
    EmulatedMemory*     memory_           = nullptr;
    ArmProcessorConfig* processor_config_ = nullptr;
    PhysicalAddressMapper* address_mapper_ = nullptr;
};
