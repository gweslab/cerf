#include "cerf_virt_dma_arena.h"

#include "cerf_virt_addr_map.h"
#include "../../boards/board_context.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/guest_engine.h"
#include "../../socs/guest_cpu_reset.h"

REGISTER_SERVICE(CerfVirtDmaArena);

bool CerfVirtDmaArena::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

uint32_t CerfVirtDmaArena::BasePa() const {
    return emu_.Get<BoardContext>().GuestAdditionsWindowBase() +
           CerfVirt::kDmaArenaOffset;
}

uint32_t CerfVirtDmaArena::SizeBytes() const { return CerfVirt::kDmaArenaSize; }

uint32_t CerfVirtDmaArena::PartitionBase(uint32_t index) const {
    return index * CerfVirt::kDmaPartitionSize;
}

void CerfVirtDmaArena::OnReady() {
    EmulatedMemory& mem = emu_.Get<EmulatedMemory>();
    mem.AddRegion(BasePa(), SizeBytes(), PAGE_READWRITE);
    base_ = mem.TryTranslate(BasePa());
    if (!base_) {
        LOG(Cerf, "[CerfVirtDmaArena] arena region at PA 0x%08X is not backed\n",
            BasePa());
        CerfFatalExit();
    }
    ZeroOwners();
    emu_.Get<GuestEngine>().SetDmaRegion(BasePa(), SizeBytes());
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) {
            if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) ZeroOwners();
        });
}

void CerfVirtDmaArena::ZeroOwners() {
    for (uint32_t i = 0; i < CerfVirt::kDmaArenaProcMax; ++i)
        cerf::le::Put32(base_ + PartitionBase(i) + CerfVirt::kDmaPartOwnerPid, 0u);
}

uint8_t* CerfVirtDmaArena::At(uint32_t offset, uint32_t bytes) {
    const uint32_t size = SizeBytes();
    if (offset > size || bytes > size - offset) return nullptr;
    return base_ + offset;
}

void CerfVirtDmaArena::Claim(uint32_t pid) {
    if (pid == 0u) {
        LOG(Cerf, "[CerfVirtDmaArena] claim with pid 0\n");
        CerfFatalExit();
    }
    uint32_t free_idx = CerfVirt::kDmaArenaProcMax;
    for (uint32_t i = 0; i < CerfVirt::kDmaArenaProcMax; ++i) {
        const uint32_t owner = cerf::le::U32(base_ + PartitionBase(i), CerfVirt::kDmaPartOwnerPid);
        if (owner == pid) return;
        if (owner == 0u && free_idx == CerfVirt::kDmaArenaProcMax) free_idx = i;
    }
    if (free_idx == CerfVirt::kDmaArenaProcMax) {
        LOG(Cerf, "[CerfVirtDmaArena] no free partition for pid 0x%X "
                  "(%u simultaneous cerf_guest loaders)\n",
            pid, CerfVirt::kDmaArenaProcMax);
        CerfFatalExit();
    }
    cerf::le::Put32(base_ + PartitionBase(free_idx) + CerfVirt::kDmaPartOwnerPid, pid);
}
