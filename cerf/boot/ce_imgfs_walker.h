#pragma once

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
constexpr uint32_t kDirMagic     = 0x2F5314CEu;
constexpr uint32_t kDirentSize   = 52;

constexpr uint32_t kModuleIndexPtrOff   = 0x2C;
constexpr uint32_t kModuleIndexSizeOff  = 0x30;
constexpr uint32_t kSectionIndexPtrOff  = 0x1C;
constexpr uint32_t kSectionIndexSizeOff = 0x20;
constexpr uint32_t kDirentFileSizeOff   = 0x18;
constexpr uint32_t kDirentNameInfoOff   = 0x0C;

constexpr uint32_t kIndexRecSize = 8;

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
