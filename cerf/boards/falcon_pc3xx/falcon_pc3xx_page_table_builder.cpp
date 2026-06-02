#include "../page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t MB(uint32_t mb) { return mb * 0x100000u; }

enum class OatKind { Dram, Mmio };

struct OatEntry {
    uint32_t va_base;
    uint32_t pa_base;
    uint32_t size;
    OatKind  kind;
};

/* OEMAddressTable, decoded from Falcon nk.exe at IDA 0x800BA4E0
   ({0,0,0}-terminated). Cached VA -> PA, size in MB. PXA255 memory map
   per manual 278693-002 Figures 2-2/2-3. */
constexpr OatEntry kOat[] = {
    { 0x80000000u, 0xA0000000u, MB(64), OatKind::Dram }, /* SDRAM bank 0 — kernel/ROM image */
    { 0x84000000u, 0xA8000000u, MB(64), OatKind::Dram }, /* SDRAM bank 2 */
    { 0x9A300000u, 0xE0000000u, MB( 1), OatKind::Mmio }, /* XScale cache-flush region */
    { 0x9A400000u, 0x48000000u, MB( 1), OatKind::Mmio }, /* Memory Controller regs */
    { 0x9A500000u, 0x40000000u, MB(32), OatKind::Mmio }, /* Peripherals (DMA/UART/INTC/GPIO/OST/clocks) */
    { 0x88200000u, 0x20000000u, MB(32), OatKind::Mmio }, /* PCMCIA/CF slot 0 */
    { 0x8A200000u, 0x28000000u, MB(32), OatKind::Mmio }, /* PCMCIA/CF slot 0 */
    { 0x8C200000u, 0x2C000000u, MB(64), OatKind::Mmio }, /* PCMCIA/CF slot 0 common memory */
    { 0x90200000u, 0x30000000u, MB(32), OatKind::Mmio }, /* PCMCIA/CF slot 1 */
    { 0x92200000u, 0x38000000u, MB(32), OatKind::Mmio }, /* PCMCIA/CF slot 1 */
    { 0x94200000u, 0x3C000000u, MB(64), OatKind::Mmio }, /* PCMCIA/CF slot 1 common memory */
    { 0x98300000u, 0x00000000u, MB( 1), OatKind::Mmio }, /* Static CS0 (boot NOR flash window) */
    { 0x9E300000u, 0x08000000u, MB( 1), OatKind::Mmio }, /* Static CS2 (flash/board device window) */
};

/* Bootloader-handoff SP: top of SDRAM bank 0. The kernel sets up its own
   per-mode stacks shortly after taking control. */
constexpr uint32_t kInitStackTopPa = 0xA0000000u + MB(64);

class FalconPc3xxPageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::FalconPC3xx;
    }

    uint32_t InitStackTopPa() const override { return kInitStackTopPa; }
    uint32_t VaToPa(uint32_t va) const override;
    std::vector<DramRegion>   CachedDramRegions()   const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;
};

uint32_t FalconPc3xxPageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : kOat) {
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    LOG(Caution, "FalconPc3xxPageTableBuilder::VaToPa: VA 0x%08X outside "
            "every OAT band (nk.exe 0x800BA4E0)\n", va);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

/* Carve the board CPLD page (PA 0xA3CC3000) out of RAM backing so its reset
   register (+0x380C) routes to FalconBoardCpld, not RAM — else WarmCheck's
   IOCTL_HAL_REBOOT write lands in RAM and the OAL spins forever waiting for the
   reset. The 1 MB section is then non-uniform (arm_mmu_walker handles it). */
constexpr uint32_t kCpldPa   = 0xA3CC3000u;
constexpr uint32_t kCpldSize = 0x1000u;

struct DramTriple { uint32_t va, pa, size; };

std::vector<DramTriple> CarvedDramTriples() {
    std::vector<DramTriple> out;
    for (const auto& e : kOat) {
        if (e.kind != OatKind::Dram) continue;
        if (kCpldPa >= e.pa_base && kCpldPa + kCpldSize <= e.pa_base + e.size) {
            out.push_back({ e.va_base, e.pa_base, kCpldPa - e.pa_base });
            const uint32_t apa = kCpldPa + kCpldSize;
            out.push_back({ e.va_base + (apa - e.pa_base), apa,
                            e.pa_base + e.size - apa });
        } else {
            out.push_back({ e.va_base, e.pa_base, e.size });
        }
    }
    return out;
}

std::vector<DramRegion> FalconPc3xxPageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& t : CarvedDramTriples()) regions.push_back({ t.va, t.pa, t.size });
    return regions;
}

std::vector<BackedRegion>
FalconPc3xxPageTableBuilder::BackedMemoryRegions() const {
    std::vector<BackedRegion> regions;
    for (const auto& t : CarvedDramTriples())
        regions.push_back({ t.va, t.pa, t.size, PAGE_READWRITE });
    return regions;
}

}  /* namespace */

REGISTER_SERVICE_AS(FalconPc3xxPageTableBuilder, PageTableBuilder);
