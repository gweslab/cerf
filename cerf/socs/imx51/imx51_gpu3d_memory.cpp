#include "imx51_gpu3d_memory.h"
#include "imx51_gpu3d_regs.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"

REGISTER_SERVICE(Imx51Gpu3dMemory);

bool Imx51Gpu3dMemory::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSocId() == SocId::Imx51;
}

uint8_t* Imx51Gpu3dMemory::ReadSpan(uint64_t pa, uint64_t size, uint32_t mmu_config) {
    return MemorySpan(pa, size, false, mmu_config);
}
uint8_t* Imx51Gpu3dMemory::WriteSpan(uint64_t pa, uint64_t size, uint32_t mmu_config) {
    return MemorySpan(pa, size, true, mmu_config);
}

/* NXP linux-imx a1638da9, gsl_mmu.c:506-526; Mesa e97ad748 a2xx.xml:1042, BEH_NEVR. */
uint8_t* Imx51Gpu3dMemory::MemorySpan(uint64_t pa, uint64_t size, bool write, uint32_t config) {
    if ((config & 1u) && config != 1u)
        emu_.Get<Fatal>().Die("GPU memory rejected MMU configuration at 0x%08X (value 0x%016llX)",
                              imx51_gpu3d_regs::kBase + imx51_gpu3d_regs::kIdxMhMmuConfig * 4u,
                              static_cast<unsigned long long>(config));
    uint8_t* p = emu_.Get<EmulatedMemory>().TryTranslateRange(pa, size, write);
    if (!p) emu_.Get<Fatal>().Die("GPU memory rejected %s at 0x%08X (size 0x%016llX)",
                                 write ? "write range" : "read range", static_cast<uint32_t>(pa),
                                 static_cast<unsigned long long>(size));
    return p;
}

uint32_t Imx51Gpu3dMemory::ReadPa32(uint64_t pa, uint32_t mmu_config) {
    return cerf::le::U32(ReadSpan(pa, 4u, mmu_config));
}
void Imx51Gpu3dMemory::WritePa32(uint64_t pa, uint32_t value, uint32_t mmu_config) {
    cerf::le::Put32(WriteSpan(pa, 4u, mmu_config), value);
}
