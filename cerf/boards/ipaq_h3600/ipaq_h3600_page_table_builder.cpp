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

/* OEMAddressTable, decoded from PPC2002 nk.exe at IDA 0x800413F4. */
constexpr OatEntry kOat[] = {
    { 0x80000000u, 0x00000000u, MB(32), OatKind::Flash }, /* static bank 0 — boot Flash (kernel image at PA 0x40000) */
    { 0x82000000u, 0x08000000u, MB(32), OatKind::Mmio  }, /* static bank 1 */
    { 0x84000000u, 0x18000000u, MB(16), OatKind::Mmio  }, /* static bank 3 */
    { 0x86000000u, 0x40000000u, MB(32), OatKind::Mmio  }, /* static bank 4 */
    { 0x8C000000u, 0xC0000000u, MB(64), OatKind::Dram  }, /* SDRAM bank 0 (kernel ulRAMStart=0x8C0A0000) */
    { 0x92000000u, 0x10000000u, MB(32), OatKind::Mmio  }, /* static bank 2 */
    { 0x8BA00000u, 0x20000000u, MB( 2), OatKind::Mmio  }, /* PCMCIA socket 0 attribute/IO window */
    { 0x8BC00000u, 0x30000000u, MB( 2), OatKind::Mmio  }, /* PCMCIA socket 1 attribute/IO window */
    { 0x90000000u, 0x28000000u, MB( 8), OatKind::Mmio  }, /* PCMCIA socket 0 mid window */
    { 0x94400000u, 0x38000000u, MB( 8), OatKind::Mmio  }, /* PCMCIA socket 1 mid window */
    { 0x94C00000u, 0x2C000000u, MB(64), OatKind::Mmio  }, /* PCMCIA socket 0 common-memory window */
    { 0x98C00000u, 0x3C000000u, MB(64), OatKind::Mmio  }, /* PCMCIA socket 1 common-memory window */
    { 0x88000000u, 0x80000000u, MB( 4), OatKind::Mmio  }, /* SA-1110 system control regs (PPC, UART, GPIO, OST) */
    { 0x89000000u, 0x90000000u, MB( 4), OatKind::Mmio  }, /* SA-1110 power manager / RTC / reset */
    { 0x8A000000u, 0xA0000000u, MB( 4), OatKind::Mmio  }, /* SA-1110 memory controller regs */
    { 0x8B000000u, 0xB0000000u, MB( 4), OatKind::Mmio  }, /* SA-1110 LCD / DMA controller regs */
    { 0x88C00000u, 0xE0000000u, MB( 4), OatKind::Mmio  }, /* SA-1110 zeros bank / cache-flush stripe */
    { 0x88700000u, 0x49000000u, MB( 1), OatKind::Mmio  }, /* static bank 5 (variable-latency) */
    { 0x88800000u, 0x4A000000u, MB( 1), OatKind::Mmio  }, /* static bank 5 alt window */
    { 0x88500000u, 0x19000000u, MB( 1), OatKind::Mmio  }, /* static bank 3 1MB alias */
    { 0x88600000u, 0x1A000000u, MB( 1), OatKind::Mmio  }, /* static bank 3 1MB alt alias */
};

constexpr uint32_t kDramPaBase     = 0xC0000000u;
constexpr uint32_t kDramSize       = MB(64);
constexpr uint32_t kInitStackTopPa = kDramPaBase + kDramSize;

class Ipaq3650PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Ipaq3650;
    }

    uint32_t InitStackTopPa() const override { return kInitStackTopPa; }
    uint32_t VaToPa(uint32_t va) const override;
    std::vector<DramRegion>   CachedDramRegions()   const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;
};

uint32_t Ipaq3650PageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : kOat) {
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    LOG(Caution, "Ipaq3650PageTableBuilder::VaToPa: VA 0x%08X outside "
            "every OAT band (nk.exe + 0x13F4)\n", va);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

std::vector<DramRegion> Ipaq3650PageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Dram) {
            regions.push_back({ e.va_base, e.pa_base, e.size });
        }
    }
    return regions;
}

std::vector<BackedRegion>
Ipaq3650PageTableBuilder::BackedMemoryRegions() const {
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

REGISTER_SERVICE_AS(Ipaq3650PageTableBuilder, PageTableBuilder);
