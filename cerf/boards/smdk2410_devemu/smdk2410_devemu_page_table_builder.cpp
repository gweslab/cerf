#include "../page_table_builder.h"

#include "../../boot/rom_parser_service.h"
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
    uint32_t size;     /* bytes */
    OatKind  kind;
};

constexpr OatEntry kOat[] = {
    /*  1 */ { 0x80000000u, 0x30000000u,  MB(64),  OatKind::Dram  }, /* 64 MB DRAM BANK 6 (primary) */
    /*  2 */ { 0x84000000u, 0x10000000u,  MB(32),  OatKind::Mmio  }, /* nGCS2: PCMCIA/PCCARD */
    /*  3 */ { 0x86000000u, 0x18000000u,  MB(32),  OatKind::Mmio  }, /* SROM (CS8900 netcard) */
    /*  4 */ { 0x88000000u, 0x00000000u,  MB(96),  OatKind::Flash }, /* NOR flash */
    /*  5 */ { 0x90800000u, 0x48000000u,  MB(1),   OatKind::Mmio  }, /* Memory control register */
    /*  6 */ { 0x90900000u, 0x49000000u,  MB(1),   OatKind::Mmio  }, /* USB Host register */
    /*  7 */ { 0x90A00000u, 0x4A000000u,  MB(1),   OatKind::Mmio  }, /* Interrupt Control */
    /*  8 */ { 0x90B00000u, 0x4B000000u,  MB(1),   OatKind::Mmio  }, /* DMA control */
    /*  9 */ { 0x90C00000u, 0x4C000000u,  MB(1),   OatKind::Mmio  }, /* Clock & Power */
    /* 10 */ { 0x90D00000u, 0x4D000000u,  MB(1),   OatKind::Mmio  }, /* LCD control */
    /* 11 */ { 0x90E00000u, 0x4E000000u,  MB(1),   OatKind::Mmio  }, /* NAND flash control */
    /* 12 */ { 0x91000000u, 0x50000000u,  MB(1),   OatKind::Mmio  }, /* UART control */
    /* 13 */ { 0x91100000u, 0x51000000u,  MB(1),   OatKind::Mmio  }, /* PWM timer */
    /* 14 */ { 0x91200000u, 0x52000000u,  MB(1),   OatKind::Mmio  }, /* USB device */
    /* 15 */ { 0x91300000u, 0x53000000u,  MB(1),   OatKind::Mmio  }, /* Watchdog Timer */
    /* 16 */ { 0x91400000u, 0x54000000u,  MB(1),   OatKind::Mmio  }, /* IIC control */
    /* 17 */ { 0x91500000u, 0x55000000u,  MB(1),   OatKind::Mmio  }, /* IIS control */
    /* 18 */ { 0x91600000u, 0x56000000u,  MB(1),   OatKind::Mmio  }, /* I/O Port */
    /* 19 */ { 0x91700000u, 0x57000000u,  MB(1),   OatKind::Mmio  }, /* RTC control */
    /* 20 */ { 0x91800000u, 0x58000000u,  MB(1),   OatKind::Mmio  }, /* A/D convert */
    /* 21 */ { 0x91900000u, 0x59000000u,  MB(1),   OatKind::Mmio  }, /* SPI */
    /* 22 */ { 0x91A00000u, 0x5A000000u,  MB(1),   OatKind::Mmio  }, /* SD Interface */
    /* 23 */ { 0x94000000u, 0x34000000u,  MB(192), OatKind::Dram  }, /* 192 MB DRAM BANK 6&7 (extended) */
};

constexpr uint32_t kDramPaBase = 0x30000000u;
constexpr uint32_t kDramSize   = 0x10000000u;  /* 256 MB */

/* Top-of-DRAM SP, matching S3C2410 eboot handoff. */
constexpr uint32_t kInitStackTopPa = kDramPaBase + kDramSize;

class Smdk2410DevEmuPageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }

    void OnReady() override;

    uint32_t InitStackTopPa() const override { return kInitStackTopPa; }
    uint32_t VaToPa(uint32_t va) const override;
    std::vector<DramRegion>   CachedDramRegions()   const override;
    std::vector<BackedRegion> BackedMemoryRegions() const override;

private:
    /* Per-OS kernel VA→PA placement, selected from ROMHDR.ulRAMStart in
       OnReady. VaToPa serves these before kOat; the kOat DRAM entries
       drive PA backing only. */
    std::vector<OatEntry> dram_bands_;
};

/* Kernel VA→PA placement, keyed on the primary kernel ROMHDR.ulRAMStart,
   per the DeviceEmulator BSP's BoardMapVAToPA. The DRAM chip is physically
   at 0x30000000 in every case; ulRAMStart only selects the kernel offset. */
void Smdk2410DevEmuPageTableBuilder::OnReady() {
    uint32_t ram_start = 0;
    auto& rom = emu_.Get<RomParserService>();
    if (rom.Ok() && !rom.Loaded().empty()) {
        const ParsedRom& prim = rom.Primary();
        for (const auto& xip : prim.xips) {
            const ParsedROMHDR& h = xip.toc.romhdr;
            if (prim.entry_va >= h.physfirst && prim.entry_va < h.physlast) {
                ram_start = h.ulRAMStart;
                break;
            }
        }
        if (ram_start == 0 && !prim.xips.empty()) {
            ram_start = prim.xips.front().toc.romhdr.ulRAMStart;
        }
    }

    const char* name;
    if (ram_start >= 0x92000000u) {
        /* CE5 NOR-flash UI image: VA 0x92000000 → PA 0x00000000 (flash). */
        name = "CE5 NOR-flash";
        dram_bands_ = { { 0x92000000u, 0x00000000u, MB(32), OatKind::Flash } };
    } else if (ram_start >= 0x8c000000u) {
        /* CE4.2 SMDK2410: kernel VA 0x80000000 → PA 0x32000000;
           RAM VA 0x8c000000 → PA 0x30000000 (32 MB banks). */
        name = "CE4.2";
        dram_bands_ = { { 0x80000000u, 0x32000000u, MB(32), OatKind::Dram },
                        { 0x8c000000u, 0x30000000u, MB(32), OatKind::Dram } };
    } else {
        /* Bowmore DeviceEmulator BSP (CE5 standalone, CE6/CE7):
           VA 0x80000000 → PA 0x30000000, 64 MB. */
        name = "Bowmore";
        dram_bands_ = { { 0x80000000u, 0x30000000u, MB(64),  OatKind::Dram },
                        { 0x94000000u, 0x34000000u, MB(192), OatKind::Dram } };
    }
    LOG(Boot, "Smdk2410DevEmuPageTableBuilder: ulRAMStart=0x%08X -> %s "
              "kernel placement\n",
        ram_start, name);
}

uint32_t Smdk2410DevEmuPageTableBuilder::VaToPa(uint32_t va) const {
    for (const auto& e : dram_bands_) {
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    for (const auto& e : kOat) {
        if (e.kind == OatKind::Dram) continue;  /* served by dram_bands_ */
        if (va >= e.va_base && va < e.va_base + e.size) {
            return e.pa_base + (va - e.va_base);
        }
    }
    LOG(Caution, "Smdk2410DevEmuPageTableBuilder::VaToPa: VA 0x%08X is "
            "outside every BSP OAT band (see "
            "references/WINCE600/PLATFORM/DEVICEEMULATOR/SRC/INC/"
            "oemaddrtab_cfg.inc)\n",
            va);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

std::vector<DramRegion> Smdk2410DevEmuPageTableBuilder::CachedDramRegions() const {
    std::vector<DramRegion> regions;
    for (const auto& e : dram_bands_) {
        if (e.kind == OatKind::Dram) {
            regions.push_back({ e.va_base, e.pa_base, e.size });
        }
    }
    return regions;
}

std::vector<BackedRegion> Smdk2410DevEmuPageTableBuilder::BackedMemoryRegions() const {
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

REGISTER_SERVICE_AS(Smdk2410DevEmuPageTableBuilder, PageTableBuilder);
