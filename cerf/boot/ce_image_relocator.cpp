#include "ce_image_relocator.h"

#include "pe_image.h"

#include <cstring>

namespace cerf::ce_image_relocator {

namespace {

uint32_t RvaToFileOff(const PeImage& pe, uint32_t rva) {
    for (const auto& s : pe.Sections()) {
        const uint32_t span = (s.vsize > s.psize) ? s.vsize : s.psize;
        if (rva >= s.rva && rva < s.rva + span) {
            return s.pe_file_off + (rva - s.rva);
        }
    }
    return 0;
}

}

void ApplyRelocations(std::vector<uint8_t>& bytes,
                      const PeImage& pe, int32_t delta,
                      uint32_t& out_patched, uint32_t& out_unhandled) {
    out_patched   = 0;
    out_unhandled = 0;
    constexpr int kFixDirIdx = 5;   /* IMAGE_DIRECTORY_ENTRY_BASERELOC */
    const uint32_t reloc_rva  = pe.DirRva(kFixDirIdx);
    const uint32_t reloc_size = pe.DirSize(kFixDirIdx);
    if (!reloc_size) return;
    const uint32_t reloc_off = RvaToFileOff(pe, reloc_rva);
    if (!reloc_off) return;

    uint32_t cursor = reloc_off;
    const uint32_t end = reloc_off + reloc_size;
    while (cursor + 8 <= end && cursor + 8 <= bytes.size()) {
        uint32_t page_va, block_size;
        std::memcpy(&page_va,    bytes.data() + cursor,     4);
        std::memcpy(&block_size, bytes.data() + cursor + 4, 4);
        if (block_size < 8 || cursor + block_size > end) break;

        const uint32_t entry_count = (block_size - 8) / 2;
        for (uint32_t i = 0; i < entry_count; i++) {
            uint16_t entry;
            std::memcpy(&entry, bytes.data() + cursor + 8 + i*2, 2);
            const uint32_t type   = (entry >> 12) & 0xF;
            const uint32_t offset = entry & 0xFFF;
            if (type == 0) continue;            /* IMAGE_REL_BASED_ABSOLUTE — padding */
            if (type == 3) {                    /* IMAGE_REL_BASED_HIGHLOW */
                const uint32_t tgt_rva = page_va + offset;
                const uint32_t tgt_off = RvaToFileOff(pe, tgt_rva);
                if (tgt_off && tgt_off + 4 <= bytes.size()) {
                    uint32_t v;
                    std::memcpy(&v, bytes.data() + tgt_off, 4);
                    v = uint32_t(int64_t(v) + delta);
                    std::memcpy(bytes.data() + tgt_off, &v, 4);
                    ++out_patched;
                }
                continue;
            }
            ++out_unhandled;
        }
        cursor += block_size;
    }
}

}
