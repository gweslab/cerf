#pragma once

#include "mips_kseg_page_table_builder.h"

#include <cstdint>
#include <vector>

struct MipsKsegDram {
    DramRegion region;
    uint32_t   decode_span;
    uint32_t   mapped_span;
};

class MipsKsegDramRomPageTableBuilder : public MipsKsegPageTableBuilder {
public:
    MipsKsegDramRomPageTableBuilder(CerfEmulator& emu, const MipsKsegDram& dram,
                                    const DramRegion& rom)
        : MipsKsegPageTableBuilder(emu), dram_(dram), rom_(rom),
          rom_from_entry_xip_(false) {}

    MipsKsegDramRomPageTableBuilder(CerfEmulator& emu, const MipsKsegDram& dram)
        : MipsKsegPageTableBuilder(emu), dram_(dram), rom_{},
          rom_from_entry_xip_(true) {}

    void OnReady() override;

    std::vector<DramRegion>   CachedDramRegions()   const final;
    std::vector<BackedRegion> BackedMemoryRegions() const final;
    std::vector<DramRegion>   MappedVaSpans()       const final;

private:
    const MipsKsegDram dram_;
    DramRegion         rom_;
    const bool         rom_from_entry_xip_;
};
