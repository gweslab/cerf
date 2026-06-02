#include "../page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t MB(uint32_t mb) { return mb * 0x100000u; }

/* MAP720.H:35-43 OEMAddressTable for Odo + ARM720T. */
enum class OatKind { Dram, Flash, Mmio };

struct OatEntry {
    uint32_t va_base;
    uint32_t pa_base;
    uint32_t size;
    OatKind  kind;
};

constexpr OatEntry kOat[] = {
    /* 1 */ { 0x8C000000u, 0x0C000000u, MB(64), OatKind::Dram  }, /* 64 MB DRAM */
    /* 2 */ { 0x80000000u, 0x00000000u, MB(64), OatKind::Flash }, /* 64 MB Flash / boot ROM */
    /* 3 */ { 0x90000000u, 0x10000000u, MB(64), OatKind::Mmio  }, /* 64 MB System ASIC (Poseidon) + chip-selects + FPGA */
    /* 4 */ { 0x84000000u, 0x04000000u, MB(64), OatKind::Mmio  }, /* 64 MB Housekeeping FPGA (LEDs, SMC ether, scratch) */
};

constexpr uint32_t kDramPaBase = 0x0C000000u;
constexpr uint32_t kDramSize   = MB(64);

constexpr uint32_t kInitStackTopPa = kDramPaBase + kDramSize;

class OdoArm720PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }

    uint32_t InitStackTopPa() const override { return kInitStackTopPa; }
    uint32_t VaToPa(uint32_t va) const override;
    std::vector<DramRegion>   CachedDramRegions()   const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;
};

uint32_t OdoArm720PageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : kOat) {
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    LOG(Caution, "OdoArm720PageTableBuilder::VaToPa: VA 0x%08X is "
            "outside every BSP OAT band (see "
            "references/WINCE300/PLATFORM/ODO/KERNEL/HAL/ARM/MAP720.H)\n",
            va);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

std::vector<DramRegion> OdoArm720PageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Dram) {
            regions.push_back({ e.va_base, e.pa_base, e.size });
        }
    }
    return regions;
}

std::vector<BackedRegion>
OdoArm720PageTableBuilder::BackedMemoryRegions() const {
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

REGISTER_SERVICE_AS(OdoArm720PageTableBuilder, PageTableBuilder);
