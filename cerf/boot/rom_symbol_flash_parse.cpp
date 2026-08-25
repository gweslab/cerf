#include "rom_symbol_flash_parse.h"

#include <cstddef>
#include <string_view>

namespace cerf::rom_image_parse {

namespace {

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

    if (data_off + kRomSignatureOffset + 8 > raw.size()) return false;
    if (U32(raw.data(), data_off + kRomSignatureOffset) != kRomSignature)
        return false;

    const uint32_t ptoc = U32(raw.data(), data_off + kRomSignatureOffset + 4);
    if (ptoc <= uint32_t(data_off)) return false;

    const uint32_t va_top = ptoc & ~0xFFFFFu;
    const uint32_t va_min =
        (ptoc > uint32_t(part_end)) ? ptoc - uint32_t(part_end) : 0u;

    for (uint32_t flash_va = va_top; flash_va >= va_min;
         flash_va -= 0x100000u) {
        const uint32_t romhdr_off = ptoc - flash_va;
        if (romhdr_off >= data_off && romhdr_off + kRomHdrSize <= part_end) {
            ParsedROMHDR h;
            if (ParseRomHdr(raw, romhdr_off, h) &&
                h.physfirst == flash_va + uint32_t(data_off) &&
                h.physlast > h.physfirst) {
                const uint32_t span = h.physlast - h.physfirst;
                if (uint64_t(data_off) + span <= part_end) {
                    out.data_off    = data_off;
                    out.flat_size   = span;
                    out.base_va     = h.physfirst;
                    out.flash_va    = flash_va;
                    out.part_blocks = part.blocks;
                    return true;
                }
            }
        }
        if (flash_va < va_min + 0x100000u) break;
    }
    return false;
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
