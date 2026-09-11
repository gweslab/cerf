#include "physical_address_mapper.h"

#include "../core/cerf_emulator.h"

namespace {

class IdentityPhysicalAddressMapper final : public PhysicalAddressMapper {
public:
    using PhysicalAddressMapper::PhysicalAddressMapper;

    bool Map(uint64_t cpu_pa, uint32_t size, uint32_t& system_pa) override {
        if (size == 0u || cpu_pa > 0xFFFFFFFFull ||
            static_cast<uint64_t>(size - 1u) > 0xFFFFFFFFull - cpu_pa) return false;
        system_pa = static_cast<uint32_t>(cpu_pa);
        return true;
    }
};

REGISTER_SERVICE_AS_FALLBACK(IdentityPhysicalAddressMapper, PhysicalAddressMapper);

} // namespace
