#pragma once

#include "ce_imgfs_walker.h"
#include "rom_record_layout.h"

#include <algorithm>
#include <cstdint>
#include <vector>

class PeImage;

namespace cerf::ce_imgfs_patcher {

struct PackedSlot {
    uint32_t             vsize;
    uint32_t             rva;
    uint32_t             psize;
    uint32_t             flags;
    std::vector<uint8_t> bytes;
};

/* Pack pe's sections into at most `target_slot_count` slots. When
   pe.Sections().size() <= target_slot_count, returns 1:1. When more,
   greedy packs trailing sections into the final slot, zero-filling
   inter-section RVA gaps. Each slot ends with psize == vsize. */
std::vector<PackedSlot> PackPeSections(const PeImage&            pe,
                                        const std::vector<uint8_t>& pe_bytes,
                                        size_t                    target_slot_count);

/* One 16-byte IMGFS index block: a single record covering
   [data_logical_addr, data_logical_addr + data_size) uncompressed,
   followed by an all-zero terminator. Used to overwrite an existing
   index block in place. */
std::vector<uint8_t> BuildIndexBlock(uint32_t data_size,
                                      uint32_t data_logical_addr);

/* Multi-record index block: one record per (data_size, logical_addr)
   pair, terminated by an all-zero record. Each record advertises
   stored uncompressed (comp_sz == full_sz). */
struct IndexRec {
    uint32_t data_size;
    uint32_t data_logical_addr;
};
std::vector<uint8_t> BuildIndexBlock(const std::vector<IndexRec>& records);

template <typename WritePage>
std::vector<IndexRec> WritePagedData(const std::vector<uint8_t>& bytes, WritePage write_page) {
    using cerf::ce_imgfs_walker::kImgfsPageSize;
    const uint32_t pages = cerf::ce_imgfs_walker::PagesFor(bytes.size());
    std::vector<IndexRec> recs;
    recs.reserve(pages);
    for (uint32_t p = 0; p < pages; ++p) {
        const uint32_t off   = p * kImgfsPageSize;
        const uint32_t chunk = std::min<uint32_t>(kImgfsPageSize, uint32_t(bytes.size()) - off);
        recs.push_back({kImgfsPageSize, write_page(p, bytes.data() + off, chunk)});
    }
    return recs;
}

std::vector<uint8_t> BuildModuleHeader(const PeImage&             pe,
                                        uint32_t                   target_vbase,
                                        uint16_t                   subsys_major,
                                        uint16_t                   subsys_minor,
                                        const std::vector<uint32_t>& slot_realaddr,
                                        const std::vector<PackedSlot>& slots);

}
