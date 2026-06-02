#pragma once

#include "../core/service.h"

#include <windows.h>

#include <cstdint>
#include <vector>

/* Board/BSP bootloader-handoff state: DRAM regions, initial SP, and the
   static cached-DRAM VA→PA map used only for ROM placement and pre-MMU
   boot — the CE kernel installs its own page tables once it runs, so
   VaToPa here is NOT the live runtime translation. */

struct DramRegion {
    uint32_t va_base;
    uint32_t pa_base;
    uint32_t size;
};

struct BackedRegion {
    uint32_t va_base;
    uint32_t pa_base;
    uint32_t size;
    DWORD    page_protect;
};

class PageTableBuilder : public Service {
public:
    using Service::Service;

    /* SP (PA) the kernel inherits from the bootloader. The kernel
       sets up its own per-mode stacks shortly after taking control. */
    virtual uint32_t InitStackTopPa() const = 0;

    /* VA→PA in the SoC's full BSP OAT view (every band — DRAM and
       peripheral). Halts on a VA outside every band. */
    virtual uint32_t VaToPa(uint32_t va) const = 0;

    virtual std::vector<DramRegion> CachedDramRegions() const = 0;

    /* Every memory-backed region in the SoC's BSP OAT — DRAM + flash
       + on-chip SRAM. EmulatedMemory iterates this on startup;
       anything not listed here is either a peripheral
       (PeripheralDispatcher) or unmapped (faults). */
    virtual std::vector<BackedRegion> BackedMemoryRegions() const = 0;

    /* True iff `va` lies inside any cached-DRAM band. Default impl
       walks CachedDramRegions(); SoC overrides not needed. */
    bool IsInCachedDram(uint32_t va) const {
        for (const auto& r : CachedDramRegions()) {
            if (va >= r.va_base && va < r.va_base + r.size) {
                return true;
            }
        }
        return false;
    }
};
