#pragma once

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

struct E32Layout {
    uint32_t size;
    uint32_t off_objcnt;
    uint32_t off_imageflags;
    uint32_t off_entryrva;
    uint32_t off_vbase;
    uint32_t off_subsysmajor;
    uint32_t off_subsysminor;
    uint32_t off_stackmax;
    uint32_t off_vsize;
    uint32_t off_sect14rva;
    uint32_t off_sect14size;
    int32_t  off_timestamp;
    uint32_t off_unit;
    uint32_t off_subsys;
};

std::vector<uint8_t> BuildModuleHeader(const E32Layout&            L,
                                        const PeImage&             pe,
                                        uint32_t                   target_vbase,
                                        const std::vector<PackedSlot>& slots);

}
