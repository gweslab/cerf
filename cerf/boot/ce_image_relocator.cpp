#include "ce_image_relocator.h"

#include "pe_image.h"

#include "../core/byte_order.h"

namespace cerf::ce_image_relocator {

namespace {

using cerf::le::Put16;
using cerf::le::Put32;
using cerf::le::U16;
using cerf::le::U32;

constexpr uint32_t kNoFileOff = PeImage::kNoFileOff;

constexpr uint32_t kBlockOffPageRva   = 0;
constexpr uint32_t kBlockOffBlockSize = 4;
constexpr uint32_t kBlockHeaderSize   = 8;
constexpr uint32_t kEntrySize         = 2;

constexpr uint32_t kRelAbsolute    = 0;
constexpr uint32_t kRelHigh        = 1;
constexpr uint32_t kRelLow         = 2;
constexpr uint32_t kRelHighLow     = 3;
constexpr uint32_t kRelHighAdj     = 4;
constexpr uint32_t kRelMipsJmpAddr = 5;

bool IsMipsMachine(uint16_t m) {
    return m == PeImage::kMachineR3000 || m == PeImage::kMachineR4000 ||
           m == PeImage::kMachineR10000 || m == PeImage::kMachineWceMipsV2 ||
           m == PeImage::kMachineMips16 || m == PeImage::kMachineMipsFpu ||
           m == PeImage::kMachineMipsFpu16;
}

}

void ApplyRelocations(std::vector<uint8_t>& bytes,
                      const PeImage& pe,
                      const std::vector<uint32_t>& section_realaddr,
                      int32_t code_delta,
                      uint32_t& out_patched, uint32_t& out_unhandled) {
    out_patched   = 0;
    out_unhandled = 0;
    const uint32_t reloc_rva  = pe.DirRva(PeImage::kDirBaseReloc);
    const uint32_t reloc_size = pe.DirSize(PeImage::kDirBaseReloc);
    if (!reloc_size) return;
    const uint32_t reloc_off = pe.RvaToFileOff(reloc_rva);
    if (reloc_off == kNoFileOff || reloc_off == 0) return;

    const bool is_mips = IsMipsMachine(pe.Machine());
    uint32_t hi_off  = kNoFileOff;

    uint8_t* const b = bytes.data();
    const auto fits = [&](uint32_t off, uint32_t len) {
        return off != kNoFileOff && off != 0 && size_t(off) + len <= bytes.size();
    };

    uint32_t cursor = reloc_off;
    const uint32_t end = reloc_off + reloc_size;
    while (cursor + kBlockHeaderSize <= end && fits(cursor, kBlockHeaderSize)) {
        const uint32_t page_va    = U32(b, cursor + kBlockOffPageRva);
        const uint32_t block_size = U32(b, cursor + kBlockOffBlockSize);
        if (block_size < kBlockHeaderSize || cursor + block_size > end) break;

        const uint32_t entries     = cursor + kBlockHeaderSize;
        const uint32_t entry_count = (block_size - kBlockHeaderSize) / kEntrySize;
        for (uint32_t i = 0; i < entry_count; i++) {
            const uint16_t entry  = U16(b, entries + i * kEntrySize);
            const uint32_t type   = (entry >> 12) & 0xF;
            const uint32_t offset = entry & 0xFFF;
            if (type == kRelAbsolute) continue;

            const uint32_t tgt_off = pe.RvaToFileOff(page_va + offset);

            if (type == kRelHighLow) {
                if (fits(tgt_off, 4)) {
                    uint32_t v = U32(b, tgt_off);
                    const uint32_t pointed_rva = v - pe.ImageBase();
                    const int sec = pe.SectionIndexForRva(pointed_rva);
                    if (sec >= 0 && size_t(sec) < section_realaddr.size()) {
                        v = section_realaddr[size_t(sec)]
                          + (pointed_rva - pe.Sections()[size_t(sec)].rva);
                    } else {
                        v = uint32_t(int64_t(v) + code_delta);
                    }
                    Put32(b + tgt_off, v);
                    ++out_patched;
                }
                continue;
            }

            if (is_mips) {
                if (type == kRelHigh) {
                    hi_off = tgt_off;
                    ++out_patched;
                    continue;
                }
                if (type == kRelLow) {
                    if (fits(tgt_off, 2)) {
                        const uint16_t lo = U16(b, tgt_off);
                        if (fits(hi_off, 2)) {
                            const uint16_t hi = U16(b, hi_off);
                            const uint32_t fv =
                                (uint32_t(hi) << 16) + lo + uint32_t(code_delta);
                            Put16(b + hi_off, uint16_t((fv + 0x8000u) >> 16));
                            Put16(b + tgt_off, uint16_t(fv & 0xFFFFu));
                        } else {
                            const uint32_t fv =
                                uint32_t(int32_t(int16_t(lo)) + code_delta);
                            Put16(b + tgt_off, uint16_t(fv & 0xFFFFu));
                        }
                        ++out_patched;
                    }
                    hi_off = kNoFileOff;
                    continue;
                }
                if (type == kRelHighAdj) {
                    uint16_t low_raw = 0;
                    if (i + 1 < entry_count && fits(entries + (i + 1) * kEntrySize, 2))
                        low_raw = U16(b, entries + (i + 1) * kEntrySize);
                    if (fits(tgt_off, 2)) {
                        uint16_t hi = U16(b, tgt_off);
                        hi = uint16_t(hi + uint16_t(
                            (int32_t(int16_t(low_raw)) + code_delta + 0x8000) >> 16));
                        Put16(b + tgt_off, hi);
                        ++out_patched;
                    }
                    ++i;
                    continue;
                }
                if (type == kRelMipsJmpAddr) {
                    if (fits(tgt_off, 4)) {
                        const uint32_t instr = U32(b, tgt_off);
                        const uint32_t fv =
                            (instr & 0x03FFFFFFu) + uint32_t(code_delta >> 2);
                        Put32(b + tgt_off, (instr & 0xFC000000u) | (fv & 0x03FFFFFFu));
                        ++out_patched;
                    }
                    continue;
                }
            }
            ++out_unhandled;
        }
        cursor += block_size;
    }
}

}
