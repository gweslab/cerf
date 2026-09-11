#include "../../cpu/physical_address_mapper.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "iop13xx_atu_state.h"
#include "iop13xx_pci_config.h"

namespace {

class Iop13xxPhysicalAddressMapper final : public PhysicalAddressMapper {
public:
    using PhysicalAddressMapper::PhysicalAddressMapper;

    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetSoc() == SocFamily::IOP13xx;
    }

    bool Map(uint64_t cpu_pa, uint32_t size, uint32_t& system_pa) override {
        if ((cpu_pa >> 32) == 0u) {
            if (size == 0u ||
                static_cast<uint64_t>(size - 1u) > 0xFFFFFFFFull - cpu_pa)
                return false;
            return MapPciBarOrPassThrough(static_cast<uint32_t>(cpu_pa), size, system_pa);
        }

        /* Intel 81341/81342 Developer's Manual sections 2.13.71-2.13.78. */
        uint64_t pci_bus_address = 0;
        if (!emu_.Get<Iop13xxAtuState>().CpuPhysToPciMemBus(
                cpu_pa, size, pci_bus_address)) return false;
        if ((pci_bus_address >> 32) != 0u) {
            emu_.Get<Fatal>().Die(
                "IOP13xx ATU produced unsupported 64-bit PCI address 0x%08X%08X",
                static_cast<uint32_t>(pci_bus_address >> 32),
                static_cast<uint32_t>(pci_bus_address));
        }
        return MapPciBarOrPassThrough(static_cast<uint32_t>(pci_bus_address), size, system_pa);
    }

private:
    bool MapPciBarOrPassThrough(uint32_t address, uint32_t size, uint32_t& system_pa) {
        if (auto* config = emu_.TryGet<Iop13xxPciConfig>()) {
            switch (config->MapMemoryBar(address, size, system_pa)) {
            case Iop13xxPciMemoryMapResult::kMapped: return true;
            case Iop13xxPciMemoryMapResult::kUnmapped: return false;
            case Iop13xxPciMemoryMapResult::kNotBar: break;
            }
        }
        system_pa = address;
        return true;
    }
};

REGISTER_SERVICE_AS(Iop13xxPhysicalAddressMapper, PhysicalAddressMapper);

} // namespace
