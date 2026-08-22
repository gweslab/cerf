#include "../page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t MB(uint32_t mb) { return mb * 0x100000u; }

enum class OatKind { Dram, Flash, Sram, Mmio };

struct OatEntry {
    uint32_t va_base;
    uint32_t pa_base;
    uint32_t size;
    OatKind  kind;
};

/* dump.bin OEMAddressTable at ROM offsets 0x00001E80 and 0x0018131C - identical
   13 entries, (VA, PA, size-MB) triples, zero-VA terminated. */
constexpr OatEntry kOat[] = {
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-3: SDRAM Partition 0/1 at 0xA000_0000. */
    { 0x8C000000u, 0xA0000000u, MB(128), OatKind::Dram },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-3: 0xE000_0000 is reserved (64 Mbyte);
       Section 28.1 - accessing reserved portions results in a data-abort exception. */
    { 0x86000000u, 0xE0000000u, MB(1),   OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Table 4-2: 0x5C00_0000 Memory Bank 0-3, 64-Kbyte SRAM each. */
    { 0x85D00000u, 0x5C000000u, MB(1),   OatKind::Sram },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x5800_0000 internal memory control. */
    { 0x85E00000u, 0x58000000u, MB(1),   OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x4C00_0000 USB host memory-mapped registers. */
    { 0x85F00000u, 0x4C000000u, MB(1),   OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x4800_0000 memory controller memory-mapped registers. */
    { 0x86100000u, 0x48000000u, MB(1),   OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x4400_0000 LCD memory-mapped registers. */
    { 0x87F00000u, 0x44000000u, MB(1),   OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x4000_0000 peripherals memory-mapped registers. */
    { 0x86200000u, 0x40000000u, MB(29),  OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x0000_0000 Static Chip Select 0 (64 Mbyte). */
    { 0x98300000u, 0x00000000u, MB(64),  OatKind::Flash },
    { 0x80000000u, 0x00000000u, MB(64),  OatKind::Flash },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x0800_0000 Static Chip Select 2 (64 Mbyte). */
    { 0x9C300000u, 0x08000000u, MB(1),   OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x1000_0000 Static Chip Select 4 (64 Mbyte). */
    { 0x96700000u, 0x10000000u, MB(1),   OatKind::Mmio },
    /* Intel PXA27x Developer's Manual 280000-001 Figure 28-2: 0x1400_0000 Static Chip Select 5 (64 Mbyte). */
    { 0x9FF00000u, 0x14000000u, MB(1),   OatKind::Mmio },
};

constexpr uint32_t DramTopPa() {
    uint32_t top = 0;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Dram && e.pa_base + e.size > top) {
            top = e.pa_base + e.size;
        }
    }
    return top;
}

std::vector<BackedRegion>
MergeBackedPaOverlaps(std::vector<BackedRegion> regions) {
    std::sort(regions.begin(), regions.end(),
              [](const BackedRegion& a, const BackedRegion& b) {
                  return a.pa_base < b.pa_base;
              });
    std::vector<BackedRegion> merged;
    for (const auto& r : regions) {
        if (!merged.empty()) {
            BackedRegion& m = merged.back();
            const uint32_t m_end = m.pa_base + m.size;
            if (r.page_protect == m.page_protect &&
                r.decode_span == m.decode_span && r.pa_base <= m_end) {
                const uint32_t r_end = r.pa_base + r.size;
                if (r_end > m_end) m.size = r_end - m.pa_base;
                continue;
            }
        }
        merged.push_back(r);
    }
    return merged;
}

class SymbolMk500PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SymbolMk500;
    }

    uint32_t VaToPa(uint32_t va) const override;
    uint32_t InitStackTopPa() const override { return DramTopPa(); }
    std::vector<DramRegion>   CachedDramRegions()   const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;
    std::vector<DramRegion>   MappedVaSpans()       const override;
};

uint32_t SymbolMk500PageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : kOat) {
        if (va >= e.va_base && va - e.va_base < e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    LOG(Caution, "MK500: VA %08X is outside the OEMAddressTable\n", va);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

std::vector<DramRegion> SymbolMk500PageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind != OatKind::Dram) continue;
        regions.push_back({ e.va_base, e.pa_base, e.size });
    }
    return regions;
}

std::vector<BackedRegion> SymbolMk500PageTableBuilder::BackedMemoryRegions() const {
    std::vector<BackedRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Mmio) continue;
        const DWORD protect =
            (e.kind == OatKind::Flash) ? PAGE_READONLY : PAGE_READWRITE;
        regions.push_back({ e.va_base, e.pa_base, e.size, protect });
    }
    return MergeBackedPaOverlaps(std::move(regions));
}

std::vector<DramRegion> SymbolMk500PageTableBuilder::MappedVaSpans() const {
    std::vector<DramRegion> spans;
    for (const auto& e : kOat) {
        spans.push_back({ e.va_base, e.pa_base, e.size });
    }
    return spans;
}

}  /* namespace */

REGISTER_SERVICE_AS(SymbolMk500PageTableBuilder, PageTableBuilder);
