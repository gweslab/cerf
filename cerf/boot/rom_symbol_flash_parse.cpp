#include "rom_symbol_flash_parse.h"

#include "../core/byte_order.h"

#include <cstddef>
#include <string_view>

namespace cerf::rom_image_parse {

namespace {

using cerf::le::U32;

constexpr std::string_view kSymbolOsPartName = "Windows CE";

constexpr size_t kSymbolPartStartOff = kSymbolPartNameBytes;
constexpr size_t kSymbolPartSizeOff  = kSymbolPartNameBytes + 4;

bool NameEqualsNoCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = char(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = char(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

bool SlotName(std::span<const uint8_t> raw, size_t off, std::string_view& out) {
    size_t n = 0;
    while (n < kSymbolPartNameBytes && raw[off + n] != 0) {
        const uint8_t c = raw[off + n];
        if (c < 0x20 || c > 0x7E) return false;
        ++n;
    }
    if (n == 0 || n == kSymbolPartNameBytes) return false;
    out = std::string_view(reinterpret_cast<const char*>(raw.data() + off), n);
    return true;
}

struct SymbolPartExtent {
    uint32_t block  = 0;
    uint32_t blocks = 0;
};

bool SlotExtent(std::span<const uint8_t> raw, size_t off, SymbolPartExtent& out) {
    const uint32_t start  = U32(raw.data(), off + kSymbolPartStartOff);
    const uint32_t blocks = U32(raw.data(), off + kSymbolPartSizeOff);
    if ((start >> 16) != 0 || (start & 0x8000u) == 0) return false;
    if (blocks == 0) return false;

    out.block  = start & 0x7FFFu;
    out.blocks = blocks;
    const uint64_t end =
        (uint64_t(out.block) + out.blocks) * kSymbolFlashBlockBytes;
    return end <= raw.size();
}

bool ResolveOsPartition(std::span<const uint8_t> raw,
                        const SymbolPartExtent&  part,
                        SymbolFlashOsXip&        out) {
    const size_t   data_off = size_t(part.block) * kSymbolFlashBlockBytes;
    const uint64_t part_end =
        uint64_t(data_off) + uint64_t(part.blocks) * kSymbolFlashBlockBytes;

    EcecRecord ecec;
    if (!ReadEcec(raw, data_off + kRomSignatureOffset, ecec)) return false;
    const uint32_t ptoc = ecec.ptoc;
    if (ptoc <= uint32_t(data_off)) return false;

    ParsedROMHDR h;
    uint32_t     pf = 0;
    if (!FindSelfLocatingRomhdr(
            raw.subspan(data_off, size_t(part_end - data_off)), ptoc, 0x100000u,
            uint32_t(data_off),
            [&](const ParsedROMHDR& c) {
                return c.physfirst >= uint32_t(data_off) && c.physlast > c.physfirst
                    && uint64_t(data_off) + (c.physlast - c.physfirst) <= part_end;
            },
            h, pf)) {
        return false;
    }
    out.data_off    = data_off;
    out.flat_size   = h.physlast - h.physfirst;
    out.base_va     = pf;
    out.flash_va    = pf - uint32_t(data_off);
    out.part_blocks = part.blocks;
    return true;
}

}  /* namespace */

bool SymbolFlashLocateOsXip(std::span<const uint8_t> raw,
                            SymbolFlashOsXip&        out) {
    const size_t entries = kSymbolPartTableOff + kSymbolPartEntrySize;
    if (raw.size() < entries + kSymbolPartEntrySize * kSymbolPartSlots)
        return false;

    unsigned         named    = 0;
    bool             have_os  = false;
    SymbolPartExtent os_part;

    for (size_t i = 0; i < kSymbolPartSlots; ++i) {
        const size_t     off = entries + i * kSymbolPartEntrySize;
        std::string_view name;
        SymbolPartExtent part;
        if (!SlotName(raw, off, name))     continue;
        if (!SlotExtent(raw, off, part))   continue;
        ++named;
        if (!have_os && NameEqualsNoCase(name, kSymbolOsPartName)) {
            os_part = part;
            have_os = true;
        }
    }

    if (named < 3 || !have_os) return false;
    if (!ResolveOsPartition(raw, os_part, out)) return false;

    out.table_off = kSymbolPartTableOff;
    return true;
}

}  /* namespace cerf::rom_image_parse */
