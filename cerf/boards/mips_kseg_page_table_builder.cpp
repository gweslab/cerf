#include "mips_kseg_page_table_builder.h"

#include "../boot/rom_parser_service.h"
#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../jit/mips/mips_mmu.h"

#include <typeinfo>

uint32_t MipsKsegPageTableBuilder::VaToPa(uint32_t va) const {
    if (MipsSeg::IsUnmapped(va)) {
        return MipsSeg::UnmappedPa(va);
    }
    emu_.Get<Fatal>().Die("%s::VaToPa: VA 0x%08X is outside the kseg0/kseg1 "
                          "unmapped windows", typeid(*this).name(), va);
}

const ParsedRom& MipsKsegPageTableBuilder::PrimaryRom() const {
    auto& rom = emu_.Get<RomParserService>();
    if (!rom.Ok() || rom.Loaded().empty() || rom.Primary().xips.empty()) {
        emu_.Get<Fatal>().Die("%s: ROM not parsed", typeid(*this).name());
    }
    return rom.Primary();
}

DramRegion MipsKsegPageTableBuilder::Kseg0RomSpan(uint32_t va_first,
                                                  uint32_t va_end) const {
    if (va_first < MipsSeg::kKusegEnd || va_end <= va_first ||
        va_end > MipsSeg::kKseg1Base) {
        emu_.Get<Fatal>().Die("%s: ROM outside kseg0: va 0x%08X..0x%08X",
                              typeid(*this).name(), va_first, va_end);
    }
    return { va_first, MipsSeg::UnmappedPa(va_first), va_end - va_first };
}

void MipsKsegPageTableBuilder::RequireRamEndWithin(const ParsedROMHDR& hdr,
                                                   uint32_t dram_va,
                                                   uint32_t dram_size) const {
    if (hdr.ulRAMEnd <= dram_va || hdr.ulRAMEnd - dram_va > dram_size) {
        emu_.Get<Fatal>().Die("%s: ROMHDR ulRAMEnd 0x%08X does not fit the DRAM "
                              "at 0x%08X (0x%X bytes)", typeid(*this).name(),
                              hdr.ulRAMEnd, dram_va, dram_size);
    }
}

const ParsedROMHDR& MipsKsegPageTableBuilder::EntryXipHeader() const {
    const ParsedRom&    prim = PrimaryRom();
    const ParsedROMHDR* hdr  = prim.XipHeaderContaining(prim.entry_va);
    return hdr ? *hdr : prim.xips.front().toc.romhdr;
}

DramRegion MipsKsegPageTableBuilder::EntryXipRomRegion() const {
    const ParsedROMHDR& hdr = EntryXipHeader();
    return Kseg0RomSpan(hdr.physfirst, hdr.physlast);
}

DramRegion MipsKsegPageTableBuilder::PlaceEntryXipRom(uint32_t dram_va,
                                                      uint32_t dram_size) const {
    const ParsedROMHDR& hdr = EntryXipHeader();
    const DramRegion    rom = EntryXipRomRegion();
    RequireRamEndWithin(hdr, dram_va, dram_size);

    LOG(Boot, "%s: ROM kva=0x%08X pa=0x%08X size=0x%X, DRAM kva=0x%08X size=0x%X "
              "(ulRAMEnd=0x%08X)\n", typeid(*this).name(), rom.va_base, rom.pa_base,
        rom.size, dram_va, dram_size, hdr.ulRAMEnd);
    return rom;
}
