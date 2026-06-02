#include "../page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t MB(uint32_t mb) { return mb * 0x100000u; }

enum class OatKind { Dram, Flash, Mmio };

struct OatEntry {
    uint32_t va_base;
    uint32_t pa_base;
    uint32_t size;
    OatKind  kind;
};

constexpr OatEntry kOat[] = {
    /*  1 */ { 0x84000000u, 0x80000000u, MB(128), OatKind::Dram  }, /* 128 MB SDRAM bank 0 (extension RAM, see above) */
    /*  2 */ { 0x8C000000u, 0xA0000000u, MB(128), OatKind::Dram  }, /* 128 MB SDRAM bank 1 (primary, NK lives here) */
    /*  3 */ { 0x94000000u, 0x0C000000u, MB(16),  OatKind::Flash }, /* 16 MB  CS0 — OneNAND/NAND flash */
    /*  4 */ { 0x95000000u, 0x15000000u, MB(16),  OatKind::Mmio  }, /* 16 MB  CS5 — LAN9115 Ethernet */
    /*  5 */ { 0x96000000u, 0x48000000u, MB(16),  OatKind::Mmio  }, /* 16 MB  L4 Core/Wakeup registers */
    /*  6 */ { 0x97000000u, 0x49000000u, MB(1),   OatKind::Mmio  }, /*  1 MB  L4 Peripheral */
    /*  7 */ { 0x97100000u, 0x68000000u, MB(16),  OatKind::Mmio  }, /* 16 MB  L3 registers */
    /*  8 */ { 0x98100000u, 0x6C000000u, MB(16),  OatKind::Mmio  }, /* 16 MB  SMS (SDRAM Memory Scheduler) */
    /*  9 */ { 0x99100000u, 0x6D000000u, MB(16),  OatKind::Mmio  }, /* 16 MB  SDRC (SDRAM Refresh Controller) */
    /* 10 */ { 0x9A100000u, 0x6E000000u, MB(16),  OatKind::Mmio  }, /* 16 MB  GPMC (Gen Purpose Memory Controller) */
    /* 11 */ { 0x9B100000u, 0x40200000u, MB(1),   OatKind::Dram  }, /*  1 MB  62 KB on-chip SRAM (1 MB band) */
    /* 12 */ { 0x9B200000u, 0x5C000000u, MB(16),  OatKind::Mmio  }, /* 16 MB  L3 interconnect */
};

constexpr uint32_t kBank1PaBase    = 0xA0000000u;
constexpr uint32_t kBank1Size      = MB(128);
constexpr uint32_t kInitStackTopPa = kBank1PaBase + kBank1Size;

class OmapEvm3530PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OmapEvm3530;
    }

    uint32_t InitStackTopPa() const override { return kInitStackTopPa; }
    uint32_t VaToPa(uint32_t va) const override;
    std::vector<DramRegion>   CachedDramRegions()   const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;
};

uint32_t OmapEvm3530PageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : kOat) {
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    LOG(Caution, "OmapEvm3530PageTableBuilder::VaToPa: VA 0x%08X is "
            "outside every BSP OAT band (see "
            "references/WINCE700/platform/ti_evm_3530/SRC/INC/addrtab_cfg.inc)\n",
            va);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

std::vector<DramRegion> OmapEvm3530PageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Dram) {
            regions.push_back({ e.va_base, e.pa_base, e.size });
        }
    }
    return regions;
}

std::vector<BackedRegion>
OmapEvm3530PageTableBuilder::BackedMemoryRegions() const {
    std::vector<BackedRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Mmio) continue;
        const DWORD protect =
            (e.kind == OatKind::Flash) ? PAGE_READONLY : PAGE_READWRITE;
        regions.push_back({ e.va_base, e.pa_base, e.size, protect });
    }
    return regions;
}

}  /* namespace */

REGISTER_SERVICE_AS(OmapEvm3530PageTableBuilder, PageTableBuilder);
