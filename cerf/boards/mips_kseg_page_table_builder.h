#pragma once

#include "page_table_builder.h"

#include <cstdint>

struct ParsedRom;
struct ParsedROMHDR;

class MipsKsegPageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    uint32_t VaToPa(uint32_t va) const final;

    DramRegion EntryXipRomRegion() const final;

protected:
    const ParsedRom& PrimaryRom() const;

    DramRegion Kseg0RomSpan(uint32_t va_first, uint32_t va_end) const;

    void RequireRamEndWithin(const ParsedROMHDR& hdr, uint32_t dram_va,
                             uint32_t dram_size) const;

    DramRegion PlaceEntryXipRom(uint32_t dram_va, uint32_t dram_size) const;

private:
    const ParsedROMHDR& EntryXipHeader() const;
};
