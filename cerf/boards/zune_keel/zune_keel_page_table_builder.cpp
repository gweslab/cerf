#include "../page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"

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

/* OEMAddressTable verbatim from nk.exe at VA 0x88201A74 (immediately
   after the `start` function; format = triplets of UINT32 VA, PA,
   count_in_MB terminated by an entry whose count is zero). Full
   per-entry citation in references/imx31/zune_keel_oat_excerpts.txt. */
constexpr OatEntry kOat[] = {
    /*  1 */ { 0x88000000u, 0x80000000u, MB(64), OatKind::Dram  }, /* SDRAM CSD0 (64 MB Hynix) */
    /*  2 */ { 0x80000000u, 0xA0000000u, MB(64), OatKind::Mmio  }, /* CS0 (2 MB NOR boot flash) */
    /*  3 */ { 0x90000000u, 0xB4000000u, MB(32), OatKind::Mmio  }, /* CS4 (board-specific) */
    /*  4 */ { 0x97000000u, 0x68000000u, MB( 1), OatKind::Mmio  }, /* AVIC */
    /*  5 */ { 0x97200000u, 0xB8000000u, MB( 1), OatKind::Mmio  }, /* NANDFC */
    /*  6 */ { 0x97300000u, 0xB8002000u, MB( 1), OatKind::Mmio  }, /* WEIM */
    /*  7 */ { 0x97400000u, 0xB8003000u, MB( 1), OatKind::Mmio  }, /* M3IF */
    /*  8 */ { 0x97500000u, 0xB8001000u, MB( 1), OatKind::Mmio  }, /* ESDCTL */
    /*  9 */ { 0x97600000u, 0x30000000u, MB( 1), OatKind::Mmio  }, /* L2 cache ctrl */
    /* 10 */ { 0x97700000u, 0x1FFFC000u, MB( 1), OatKind::Dram  }, /* on-chip SRAM (MCIMX31RM §2.1.1) */
    /* 11 */ { 0x98000000u, 0x40000000u, MB(64), OatKind::Mmio  }, /* IPU + AIPS1 + ATA + USB */
    /* 12 */ { 0x9C000000u, 0x50000000u, MB(64), OatKind::Mmio  }, /* SPBA0 + AIPS2 + CCM + GPT */
};

constexpr uint32_t kDramPaBase     = 0x80000000u;
constexpr uint32_t kDramSize       = MB(64);
constexpr uint32_t kInitStackTopPa = kDramPaBase + kDramSize;

class ZuneKeelPageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    uint32_t InitStackTopPa() const override { return kInitStackTopPa; }
    uint32_t VaToPa(uint32_t va) const override;
    std::vector<DramRegion>   CachedDramRegions()   const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;
};

uint32_t ZuneKeelPageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : kOat) {
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    LOG(Caution, "ZuneKeelPageTableBuilder::VaToPa: VA 0x%08X outside "
            "every OAT band (nk.exe + 0x1A74)\n", va);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

std::vector<DramRegion> ZuneKeelPageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Dram) {
            regions.push_back({ e.va_base, e.pa_base, e.size });
        }
    }
    return regions;
}

std::vector<BackedRegion>
ZuneKeelPageTableBuilder::BackedMemoryRegions() const {
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

REGISTER_SERVICE_AS(ZuneKeelPageTableBuilder, PageTableBuilder);
