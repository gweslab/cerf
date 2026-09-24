#pragma once

#include "../core/log.h"
#include "../core/service.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <vector>

/* Board/BSP bootloader-handoff state: DRAM regions, initial SP, and the
   static cached-DRAM VA→PA map used only for ROM placement and pre-MMU
   boot - the CE kernel installs its own page tables once it runs, so
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

    uint32_t decode_span = 0;
};

class PageTableBuilder : public Service {
public:
    using Service::Service;

    /* SP (PA) the kernel inherits from the bootloader. The kernel
       sets up its own per-mode stacks shortly after taking control. */
    virtual uint32_t InitStackTopPa() const {
        LOG(Caution, "PageTableBuilder::InitStackTopPa: this board declares no "
                "bootloader-handoff SP\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    /* VA→PA in the SoC's full BSP OAT view (every band - DRAM and
       peripheral). Halts on a VA outside every band. */
    virtual uint32_t VaToPa(uint32_t va) const = 0;

    virtual std::vector<DramRegion> CachedDramRegions() const = 0;

    /* Every memory-backed region in the SoC's BSP OAT - DRAM + flash
       + on-chip SRAM. EmulatedMemory iterates this on startup;
       anything not listed here is either a peripheral
       (PeripheralDispatcher) or unmapped (faults). */
    virtual std::vector<BackedRegion> BackedMemoryRegions() const = 0;

    /* Every VA span the OAT maps - DRAM, flash AND peripheral. MUST include
       MMIO spans (unlike BackedMemoryRegions): StaticWindowHole picks a band
       VA outside these, and a band VA inside an omitted MMIO span gets shadowed
       by the real peripheral mapping so the stub bytes are never served. */
    virtual std::vector<DramRegion> MappedVaSpans() const = 0;

    virtual DramRegion EntryXipRomRegion() const;

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

    /* First 64K-aligned hole of at least `size` bytes in the kernel static
       window [0x80000000,0xA0000000) not covered by MappedVaSpans(); 0 if none.
       The band must live here, not KSEG2 (0xC0000000+) which the CE6/7 kernel
       dynamically allocates over and would shadow the overlay. */
    uint32_t StaticWindowHole(uint32_t size) const {
        constexpr uint32_t kWinBase = 0x80000000u;
        constexpr uint32_t kWinEnd  = 0xA0000000u;
        constexpr uint32_t kAlign   = 0x10000u;
        auto spans = MappedVaSpans();
        std::sort(spans.begin(), spans.end(),
                  [](const DramRegion& a, const DramRegion& b) {
                      return a.va_base < b.va_base;
                  });
        uint32_t cur = kWinBase;
        for (const auto& s : spans) {
            const uint32_t s_end = s.va_base + s.size;
            if (s_end <= kWinBase) continue;
            if (s.va_base >= kWinEnd) break;
            if (s.va_base > cur) {
                const uint32_t hole = (cur + kAlign - 1u) & ~(kAlign - 1u);
                if (s.va_base > hole && (s.va_base - hole) >= size) return hole;
            }
            if (s_end > cur) cur = s_end;
        }
        if (cur < kWinEnd) {
            const uint32_t hole = (cur + kAlign - 1u) & ~(kAlign - 1u);
            if (kWinEnd > hole && (kWinEnd - hole) >= size) return hole;
        }
        return 0u;
    }
};
