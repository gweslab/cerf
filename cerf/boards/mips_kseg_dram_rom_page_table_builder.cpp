#include "mips_kseg_dram_rom_page_table_builder.h"

void MipsKsegDramRomPageTableBuilder::OnReady() {
    if (rom_from_entry_xip_) {
        rom_ = PlaceEntryXipRom(dram_.region.va_base, dram_.region.size);
    }
}

std::vector<DramRegion> MipsKsegDramRomPageTableBuilder::CachedDramRegions() const {
    return { dram_.region };
}

std::vector<BackedRegion> MipsKsegDramRomPageTableBuilder::BackedMemoryRegions() const {
    return {
        { dram_.region.va_base, dram_.region.pa_base, dram_.region.size, PAGE_READWRITE,
          dram_.decode_span },
        { rom_.va_base, rom_.pa_base, rom_.size, PAGE_EXECUTE_READ },
    };
}

std::vector<DramRegion> MipsKsegDramRomPageTableBuilder::MappedVaSpans() const {
    return {
        { dram_.region.va_base, dram_.region.pa_base, dram_.mapped_span },
        rom_,
    };
}
