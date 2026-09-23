#pragma once

#include "../core/byte_order.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace cerf::ce_imgfs_walker {

constexpr uint32_t kMagicModule  = 0xFFFFFEFEu;
constexpr uint32_t kMagicFile    = 0xFFFFF6FEu;
constexpr uint32_t kMagicName    = 0xFFFFFEFBu;
constexpr uint32_t kMagicSection = 0xFFFFF6FDu;
constexpr uint32_t kMagicModuleSection = 0xFFFFFEFDu;
constexpr uint32_t kDirMagic     = 0x2F5314CEu;

constexpr uint32_t kImgfsPageSize          = 0x1000;
constexpr uint32_t kImgfsEraseBlock        = 0x10000;
constexpr uint32_t kImgfsDataPagesPerBlock = 15;
constexpr uint32_t kImgfsMapEntrySize      = 8;
constexpr uint32_t kImgfsMapOffSector      = 0;
constexpr uint32_t kImgfsMapOffFlags       = 4;
constexpr uint32_t kFtlErasedSector        = 0xFFFFFFFFu;

constexpr uint32_t kModuleIndexPtrOff   = 0x2C;
constexpr uint32_t kModuleIndexSizeOff  = 0x30;
constexpr uint32_t kSectionIndexPtrOff  = 0x1C;
constexpr uint32_t kSectionIndexSizeOff = 0x20;
constexpr uint32_t kDirentFileSizeOff   = 0x18;
constexpr uint32_t kDirentNameInfoOff   = 0x0C;

constexpr uint32_t kIndexRecSize        = 8;
constexpr uint32_t kIndexRecOffCompSize = 0;
constexpr uint32_t kIndexRecOffFullSize = 2;
constexpr uint32_t kIndexRecOffPtr      = 4;

struct IndexRecord {
    uint16_t comp_size;
    uint16_t full_size;
    uint32_t ptr;
    bool IsTerminator() const { return comp_size == 0 && full_size == 0 && ptr == 0; }
};

IndexRecord ReadIndexRecord(const uint8_t* rec);

inline size_t FtlMapEntryOffset(size_t imgfs_base, size_t block, uint32_t entry) {
    return imgfs_base + block * kImgfsEraseBlock + kImgfsDataPagesPerBlock * kImgfsPageSize
         + size_t(entry) * kImgfsMapEntrySize;
}

inline uint32_t FtlPhysPage(size_t block, uint32_t entry) {
    return uint32_t(block) * (kImgfsDataPagesPerBlock + 1) + entry;
}

inline uint32_t PagesFor(size_t bytes) {
    return uint32_t((bytes + kImgfsPageSize - 1) / kImgfsPageSize);
}

template <typename Visit>
void ForEachFtlMapEntry(std::span<const uint8_t> raw, size_t imgfs_base, size_t num_blocks,
                        Visit&& visit) {
    for (size_t blk = 0; blk < num_blocks; ++blk) {
        for (uint32_t e = 0; e < kImgfsDataPagesPerBlock; ++e) {
            const size_t eo = FtlMapEntryOffset(imgfs_base, blk, e);
            if (eo + kImgfsMapEntrySize > raw.size()) break;
            visit(blk, e, cerf::le::U32(raw.data() + eo + kImgfsMapOffSector),
                  cerf::le::U32(raw.data() + eo + kImgfsMapOffFlags));
        }
    }
}

class Translator {
public:
    static Translator Detect(std::span<const uint8_t> raw,
                              size_t                   imgfs_base);

    size_t Translate(uint32_t logical_addr) const;

    std::vector<uint8_t> Read(std::span<const uint8_t> raw,
                              uint32_t                 logical_addr,
                              uint32_t                 size) const;

    bool     IsFtl()      const { return is_ftl_; }
    size_t   ImgfsBase()  const { return imgfs_base_; }
    size_t   RawSize()    const { return raw_size_; }
    uint32_t BaseSector() const { return base_sector_; }
    uint32_t MaxLs()      const { return sector_to_phys_.empty()
                                       ? 0
                                       : uint32_t(sector_to_phys_.size() - 1); }

private:
    Translator() = default;
    size_t              imgfs_base_ = 0;
    size_t              raw_size_   = 0;
    bool                is_ftl_     = false;
    std::vector<uint32_t> sector_to_phys_;
    uint32_t              base_sector_  = 0;
};

std::vector<uint8_t> ReadIndexData(std::span<const uint8_t> raw,
                                    const Translator&        tr,
                                    uint32_t                 indexptr,
                                    uint32_t                 indexsize,
                                    uint32_t                 expected_size);

struct DirentRef {
    size_t   abs_file_off;
    uint32_t magic;
};

std::vector<DirentRef> EnumerateAll(std::span<const uint8_t> raw,
                                     const Translator&        tr,
                                     uint32_t                 bytes_per_block,
                                     uint32_t                 dirent_size);

std::string ResolveName(std::span<const uint8_t> raw,
                        const Translator&        tr,
                        const uint8_t*           nameinfo_12);

struct ImgfsModule {
    std::string              name;
    size_t                   dirent_off;
    uint32_t                 file_size;
    uint32_t                 mod_indexptr;
    uint32_t                 mod_indexsize;
    struct Section {
        std::string  name;
        size_t       dirent_off;
        uint32_t     file_size;
        uint32_t     sec_indexptr;
        uint32_t     sec_indexsize;
    };
    std::vector<Section>     sections;
};

std::vector<ImgfsModule> CollectModules(std::span<const uint8_t> raw,
                                         const Translator&        tr,
                                         uint32_t                 bytes_per_block);

}
