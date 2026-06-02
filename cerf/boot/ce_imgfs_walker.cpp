#include "ce_imgfs_walker.h"

#include "ce_imgfs_xpress.h"

#include <algorithm>
#include <cstring>

namespace cerf::ce_imgfs_walker {

namespace {

constexpr uint32_t kPageSize    = 0x1000;
constexpr uint32_t kEraseBlock  = 0x10000;
constexpr uint32_t kDataPagesPerBlock = 15;
constexpr uint32_t kMappingEntrySize  = 8;
constexpr uint32_t kFtlValidFlagsMask = 0xFFF00000u;
constexpr uint32_t kFtlValidFlagsBits = 0xFFF00000u;

inline uint32_t Rd32(const uint8_t* p) {
    return uint32_t(p[0])
         | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16)
         | (uint32_t(p[3]) << 24);
}
inline uint16_t Rd16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}

std::string Utf16LeToAscii(const uint8_t* utf16, size_t bytes) {
    std::string out;
    out.reserve(bytes / 2);
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        uint16_t w = uint16_t(utf16[i]) | (uint16_t(utf16[i + 1]) << 8);
        if (w == 0) break;
        out.push_back((w < 128) ? char(w) : '?');
    }
    return out;
}

}  /* namespace */

Translator Translator::Detect(std::span<const uint8_t> raw,
                               size_t                   imgfs_base) {
    Translator t;
    t.imgfs_base_ = imgfs_base;
    t.raw_size_   = raw.size();
    if (imgfs_base >= raw.size()) {
        t.is_ftl_ = false;
        return t;
    }
    const size_t imgfs_size = raw.size() - imgfs_base;
    const size_t num_blocks = imgfs_size / kEraseBlock;

    size_t valid = 0;
    size_t total = 0;
    const size_t sample_blocks = std::min<size_t>(8, num_blocks);
    for (size_t blk = 0; blk < sample_blocks; ++blk) {
        const size_t map_off = imgfs_base + blk * kEraseBlock
                             + kDataPagesPerBlock * kPageSize;
        for (uint32_t e = 0; e < kDataPagesPerBlock; ++e) {
            const size_t eo = map_off + e * kMappingEntrySize;
            if (eo + kMappingEntrySize > raw.size()) break;
            const uint32_t ls = Rd32(raw.data() + eo);
            const uint32_t fl = Rd32(raw.data() + eo + 4);
            ++total;
            if (ls != 0xFFFFFFFFu
                && (fl & kFtlValidFlagsMask) == kFtlValidFlagsBits) {
                ++valid;
            }
        }
    }
    if (total > 0 && valid * 10 >= total * 4) {
        t.is_ftl_ = true;
        uint32_t max_ls = 0;
        std::vector<std::pair<uint32_t, uint32_t>> raw_pairs;
        raw_pairs.reserve(num_blocks * kDataPagesPerBlock);
        for (size_t blk = 0; blk < num_blocks; ++blk) {
            const size_t map_off = imgfs_base + blk * kEraseBlock
                                 + kDataPagesPerBlock * kPageSize;
            for (uint32_t e = 0; e < kDataPagesPerBlock; ++e) {
                const size_t eo = map_off + e * kMappingEntrySize;
                if (eo + kMappingEntrySize > raw.size()) break;
                const uint32_t ls = Rd32(raw.data() + eo);
                const uint32_t fl = Rd32(raw.data() + eo + 4);
                if (ls == 0xFFFFFFFFu) continue;
                if ((fl & kFtlValidFlagsMask) != kFtlValidFlagsBits) continue;
                const uint32_t phys_page = uint32_t(blk) * (kDataPagesPerBlock + 1) + e;
                raw_pairs.push_back({ls, phys_page});
                if (ls > max_ls) max_ls = ls;
            }
        }
        t.sector_to_phys_.assign(size_t(max_ls) + 1, 0xFFFFFFFFu);
        for (auto [ls, phys] : raw_pairs) {
            t.sector_to_phys_[ls] = phys;
        }
        t.base_sector_ = 0;
        for (size_t i = 0; i < t.sector_to_phys_.size(); ++i) {
            if (t.sector_to_phys_[i] == 0) {
                t.base_sector_ = uint32_t(i);
                break;
            }
        }
    } else {
        t.is_ftl_ = false;
    }
    return t;
}

size_t Translator::Translate(uint32_t la) const {
    if (la == 0) return SIZE_MAX;
    if (!is_ftl_) {
        const size_t a = imgfs_base_ + la;
        return (a < raw_size_) ? a : SIZE_MAX;
    }
    const uint32_t page = la / kPageSize;
    const uint32_t sector = page + base_sector_;
    if (sector >= sector_to_phys_.size()) return SIZE_MAX;
    const uint32_t phys = sector_to_phys_[sector];
    if (phys == 0xFFFFFFFFu) return SIZE_MAX;
    const size_t a = imgfs_base_
                   + size_t(phys) * kPageSize
                   + (la & (kPageSize - 1));
    return (a < raw_size_) ? a : SIZE_MAX;
}

std::vector<uint8_t> Translator::Read(std::span<const uint8_t> raw,
                                       uint32_t                 la,
                                       uint32_t                 size) const {
    std::vector<uint8_t> out(size, 0);
    uint32_t remaining = size;
    uint32_t cursor = la;
    size_t   di = 0;
    while (remaining > 0) {
        const size_t abs_off = Translate(cursor);
        if (abs_off == SIZE_MAX) {
            break;
        }
        const uint32_t page_off = cursor & (kPageSize - 1);
        const uint32_t in_page = kPageSize - page_off;
        const uint32_t to_read = std::min(remaining, in_page);
        if (abs_off + to_read > raw.size()) break;
        std::memcpy(out.data() + di, raw.data() + abs_off, to_read);
        di       += to_read;
        cursor   += to_read;
        remaining -= to_read;
    }
    return out;
}

std::vector<uint8_t> ReadIndexData(std::span<const uint8_t> raw,
                                    const Translator&        tr,
                                    uint32_t                 indexptr,
                                    uint32_t                 indexsize,
                                    uint32_t                 expected_size) {
    if (indexptr == 0 || indexsize == 0) return {};
    const std::vector<uint8_t> idx = tr.Read(raw, indexptr, indexsize);
    if (idx.size() < indexsize) return {};

    std::vector<uint8_t> out;
    out.reserve(expected_size);
    const uint32_t n_records = indexsize / kIndexRecSize;
    for (uint32_t i = 0; i < n_records; ++i) {
        const uint8_t* r = idx.data() + i * kIndexRecSize;
        const uint16_t comp_sz = Rd16(r);
        const uint16_t full_sz = Rd16(r + 2);
        const uint32_t ptr     = Rd32(r + 4);
        if (comp_sz == 0 && full_sz == 0 && ptr == 0) break;
        if (ptr == 0) {
            out.insert(out.end(), full_sz, uint8_t(0));
            continue;
        }
        std::vector<uint8_t> chunk = tr.Read(raw, ptr, comp_sz);
        if (comp_sz == full_sz) {
            out.insert(out.end(), chunk.begin(), chunk.end());
        } else {
            std::vector<uint8_t> dec =
                ce_imgfs_xpress::Decompress(chunk.data(), chunk.size(),
                                             full_sz);
            if (dec.size() == full_sz) {
                out.insert(out.end(), dec.begin(), dec.end());
            } else {
                out.insert(out.end(), dec.begin(), dec.end());
                out.insert(out.end(), full_sz - dec.size(), uint8_t(0));
            }
        }
    }
    if (expected_size > 0 && out.size() > expected_size) {
        out.resize(expected_size);
    }
    return out;
}

std::vector<DirentRef> EnumerateAll(std::span<const uint8_t> raw,
                                     const Translator&        tr,
                                     uint32_t                 bytes_per_block,
                                     uint32_t                 dirent_size) {
    std::vector<DirentRef> out;
    if (bytes_per_block == 0 || dirent_size == 0) return out;
    const uint32_t ents_per_blk = (bytes_per_block - 8) / dirent_size;
    const size_t   imgfs_base   = tr.ImgfsBase();
    if (imgfs_base + 8 > raw.size()) return out;

    for (size_t off = imgfs_base; off + 8 <= raw.size(); off += bytes_per_block) {
        if (Rd32(raw.data() + off) != kDirMagic) continue;
        for (uint32_t i = 0; i < ents_per_blk; ++i) {
            const size_t eo = off + 8 + i * dirent_size;
            if (eo + dirent_size > raw.size()) break;
            const uint32_t magic = Rd32(raw.data() + eo);
            out.push_back({eo, magic});
        }
    }
    return out;
}

std::string ResolveName(std::span<const uint8_t> raw,
                        const Translator&        tr,
                        const uint8_t*           ni) {
    const uint16_t length = Rd16(ni);
    const uint16_t flags  = Rd16(ni + 2);
    if (length == 0) return {};

    if (length <= 4) {
        return Utf16LeToAscii(ni + 4, size_t(length) * 2);
    }

    const uint32_t ptr = Rd32(ni + 8);
    if (flags & 0x02) {
        const size_t off = tr.Translate(ptr);
        if (off != SIZE_MAX && off + kDirentSize <= raw.size()) {
            if (Rd32(raw.data() + off) == kMagicName) {
                return Utf16LeToAscii(raw.data() + off + 4, kDirentSize - 4);
            }
        }
        return {};
    }
    const size_t off = tr.Translate(ptr);
    if (off == SIZE_MAX) return {};
    const size_t bytes = size_t(length) * 2;
    if (off + bytes > raw.size()) return {};
    return Utf16LeToAscii(raw.data() + off, bytes);
}

std::vector<ImgfsModule> CollectModules(std::span<const uint8_t> raw,
                                         const Translator&        tr,
                                         uint32_t                 bytes_per_block) {
    std::vector<ImgfsModule> mods;
    const auto refs = EnumerateAll(raw, tr, bytes_per_block, kDirentSize);
    size_t i = 0;
    while (i < refs.size()) {
        if (refs[i].magic != kMagicModule) { ++i; continue; }
        const size_t eo = refs[i].abs_file_off;
        const uint8_t* d = raw.data() + eo;
        ImgfsModule m;
        m.dirent_off    = eo;
        m.file_size     = Rd32(d + kDirentFileSizeOff);
        m.mod_indexptr  = Rd32(d + kModuleIndexPtrOff);
        m.mod_indexsize = Rd32(d + kModuleIndexSizeOff);
        m.name          = ResolveName(raw, tr, d + kDirentNameInfoOff);

        size_t j = i + 1;
        while (j < refs.size()) {
            const uint32_t mj = refs[j].magic;
            if (mj == kMagicName) { ++j; continue; }
            if (mj != kMagicSection) break;
            const size_t seo = refs[j].abs_file_off;
            const uint8_t* sd = raw.data() + seo;
            ImgfsModule::Section s;
            s.dirent_off    = seo;
            s.file_size     = Rd32(sd + kDirentFileSizeOff);
            s.sec_indexptr  = Rd32(sd + kSectionIndexPtrOff);
            s.sec_indexsize = Rd32(sd + kSectionIndexSizeOff);
            s.name          = ResolveName(raw, tr, sd + kDirentNameInfoOff);
            m.sections.push_back(std::move(s));
            ++j;
        }
        mods.push_back(std::move(m));
        i = j;
    }
    return mods;
}

}
