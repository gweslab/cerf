#include "../page_table_builder.h"
#include "../../core/fatal.h"

#include "../../peripherals/siemens_aspc2/siemens_mp377_aspc2.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"

#include <cstdint>
#include <vector>

namespace {

using siemens_mp377::kMp377Aspc2RamPa;
using siemens_mp377::kMp377Aspc2RamSize;
using siemens_mp377::kMp377Aspc2RamVa;

constexpr uint32_t MB(uint32_t mb) {
    return mb * 0x100000u;
}

enum class OatKind { CachedDram, Mmio };

struct OatEntry {
    uint32_t va_base;
    uint32_t pa_base;
    uint32_t size;
    OatKind kind;
};

/* siemens_mp377_v1040 nk.exe OEMAddressTable, VA 0x80409F00. */
constexpr OatEntry kOat[] = {
    {0x80000000u, 0x00000000u, MB(256), OatKind::CachedDram}, {0x90000000u, 0xF0000000u, MB(16), OatKind::Mmio},
    {0x91000000u, 0xF2000000u, MB(32), OatKind::Mmio},        {0x93000000u, 0xFF000000u, MB(16), OatKind::Mmio},
    {0x94000000u, 0xC0000000u, MB(128), OatKind::Mmio},       {0x9C000000u, 0xD0000000u, MB(64), OatKind::Mmio},
};

constexpr uint32_t kBackedDramSize = 0x0F400000u;

/* siemens_mp377_v1040 nk.exe sub_804420B8, OALPAtoVA(pa, cached). */
constexpr uint32_t kOalUncachedAliasBit = 0x20000000u;

/* siemens_mp377_v1040 eddertec400.dll EDD_Init: VA 0xAF800000,
   PA 0x0F800000, size 0x00200000. */
constexpr uint32_t kErtecDmaVa = 0x8F800000u;
constexpr uint32_t kErtecDmaPa = 0x0F800000u;
constexpr uint32_t kErtecDmaSize = 0x00200000u;

class SiemensMp377PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SiemensMP377;
    }

    uint32_t InitStackTopPa() const override { return kBackedDramSize; }
    uint32_t VaToPa(uint32_t va) const override;
    std::vector<DramRegion> CachedDramRegions() const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;
    std::vector<DramRegion> MappedVaSpans() const override;
};

uint32_t SiemensMp377PageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : kOat) {
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }

    for (const auto& e : kOat) {
        const uint32_t alias_va = e.va_base | kOalUncachedAliasBit;
        if (va >= alias_va && va < alias_va + e.size) {
            return e.pa_base + (va - alias_va);
        }
    }

    emu_.Get<Fatal>().Die("SiemensMp377PageTableBuilder::VaToPa: VA 0x%08X outside "
                          "MP377 OEMAddressTable/OALPAtoVA aliases (nk.exe 0x80409F00, sub_804420B8)",
                          va);
}

std::vector<DramRegion> SiemensMp377PageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::CachedDram) {
            regions.push_back({e.va_base, e.pa_base, kBackedDramSize});
        }
    }
    return regions;
}

std::vector<BackedRegion> SiemensMp377PageTableBuilder::BackedMemoryRegions() const {
    std::vector<BackedRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::CachedDram) {
            regions.push_back({e.va_base, e.pa_base, kBackedDramSize, PAGE_READWRITE});
        }
    }
    regions.push_back({kErtecDmaVa, kErtecDmaPa, kErtecDmaSize, PAGE_READWRITE});
    /* siemens_mp377_v1040 S7pbhmix.dll sub_2A530D0/sub_2A52DB8;
       Siemens ASPC2 Hardware User Description V2.4, sections 1.4/4.1.2. */
    regions.push_back({kMp377Aspc2RamVa, kMp377Aspc2RamPa, kMp377Aspc2RamSize, PAGE_READWRITE});
    return regions;
}

std::vector<DramRegion> SiemensMp377PageTableBuilder::MappedVaSpans() const {
    std::vector<DramRegion> regions;
    for (const auto& e : kOat) {
        regions.push_back({e.va_base, e.pa_base, e.size});
    }
    for (const auto& e : kOat) {
        regions.push_back({e.va_base | kOalUncachedAliasBit, e.pa_base, e.size});
    }
    return regions;
}

} /* namespace */

REGISTER_SERVICE_AS(SiemensMp377PageTableBuilder, PageTableBuilder);
