#include "compactflash_fat16.h"

#include "compactflash_fat_common.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../storage/fat_volume_layout.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

REGISTER_SERVICE(CompactFlashFat16Builder);

namespace {

constexpr uint32_t kBytesPerSec = 512;
constexpr uint32_t kSecPerClus  = 2;
constexpr uint32_t kReserved    = 1;
constexpr uint32_t kNumFats     = 1;
constexpr uint32_t kRootEntries = 512;
constexpr uint32_t kPartStart   = 63;
constexpr uint32_t kSecPerTrack = 63;
constexpr uint32_t kHeads       = 16;
constexpr uint8_t  kMedia       = 0xF8;
constexpr uint8_t  kPartType    = 0x06;     /* MBR type: FAT16B */
constexpr uint16_t kEoc16       = 0xFFFFu;
constexpr uint32_t kMinClusters = 4096;     /* >= 4085 -> FAT16, not FAT12 */
constexpr uint32_t kMaxClusters = 65524;    /* <= 65524 -> FAT16, not FAT32 */

/* MBR CHS byte-pack: [head][sector | cyl[9:8]][cyl[7:0]], cyl clamped to 10 bits. */
void PackChs(uint32_t lba, uint8_t out[3]) {
    uint32_t c = lba / (kSecPerTrack * kHeads);
    const uint32_t rem = lba % (kSecPerTrack * kHeads);
    uint32_t h = rem / kSecPerTrack;
    uint32_t s = rem % kSecPerTrack + 1;
    if (c > 1023) { c = 1023; h = kHeads - 1; s = kSecPerTrack; }
    out[0] = static_cast<uint8_t>(h);
    out[1] = static_cast<uint8_t>((s & 0x3F) | ((c >> 8) << 6));
    out[2] = static_cast<uint8_t>(c & 0xFF);
}

}  /* namespace */

bool CompactFlashFat16Builder::Build(const std::wstring& out_path,
                                     const std::vector<std::wstring>& files,
                                     uint32_t data_mb) {
    struct Entry {
        std::wstring         name;
        std::vector<uint8_t> data;
        uint8_t              sfn[11];
        uint8_t              ntres = 0;
        uint32_t             lfn_count = 0;
        uint32_t             first_clus = 0;
        uint32_t             clusters = 0;
    };

    const uint32_t clus_bytes = kBytesPerSec * kSecPerClus;
    std::vector<Entry> entries;
    std::vector<std::array<uint8_t, 11>> used_sfns;
    auto sfn_taken = [&](const uint8_t* s) {
        for (const auto& u : used_sfns)
            if (std::memcmp(u.data(), s, 11) == 0) return true;
        return false;
    };
    uint32_t root_entries_used = 0;
    uint32_t payload_clusters = 0;
    int sfn_index = 1;
    for (const auto& path : files) {
        Entry e;
        e.name = cf_fat::BaseName(path);
        e.data = cf_fat::ReadHostFile(path);
        cf_fat::ShortName sn = cf_fat::MakeShortName(e.name, sfn_index);
        if (sfn_taken(sn.sfn)) {
            cf_fat::MakeMangledSfn(e.name, sfn_index, sn.sfn);
            sn.ntres = 0;
            sn.needs_lfn = true;
        }
        ++sfn_index;
        std::memcpy(e.sfn, sn.sfn, 11);
        e.ntres = sn.ntres;
        e.lfn_count = sn.needs_lfn ? cf_fat::LfnSlotCount(e.name) : 0;
        std::array<uint8_t, 11> a{};
        std::memcpy(a.data(), sn.sfn, 11);
        used_sfns.push_back(a);
        e.clusters = static_cast<uint32_t>((e.data.size() + clus_bytes - 1) / clus_bytes);
        root_entries_used += e.lfn_count + 1;
        payload_clusters += e.clusters;
        entries.push_back(std::move(e));
    }

    if (root_entries_used > kRootEntries) {
        LOG(Caution, "[CF] FAT16 build: %u root dir entries needed > %u max\n",
            root_entries_used, kRootEntries);
        return false;
    }
    if (payload_clusters > kMaxClusters) {
        LOG(Caution, "[CF] FAT16 build: payload needs %u clusters > FAT16 max %u "
            "(files too large for a 1 KB-cluster card)\n", payload_clusters, kMaxClusters);
        return false;
    }

    const uint32_t req_clusters = static_cast<uint32_t>(
        (static_cast<uint64_t>(data_mb) * 1024u * 1024u) / clus_bytes);
    uint32_t data_clusters =
        std::max(std::max(req_clusters, payload_clusters), kMinClusters);
    if (data_clusters > kMaxClusters) data_clusters = kMaxClusters;

    const uint32_t fat_entries  = data_clusters + 2;
    const uint32_t fat_sectors  = (fat_entries * 2 + kBytesPerSec - 1) / kBytesPerSec;
    const uint32_t root_sectors = (kRootEntries * 32 + kBytesPerSec - 1) / kBytesPerSec;
    const uint32_t part_sectors = kReserved + kNumFats * fat_sectors + root_sectors
                                  + data_clusters * kSecPerClus;
    /* Whole-cylinder card size: else CE's fatfs derives fewer clusters from the
       disk's (smaller) CHS size and reads the 16-bit FAT as FAT12. */
    const uint32_t kCylSectors = kSecPerTrack * kHeads;
    const uint32_t total_sectors =
        ((kPartStart + part_sectors + kCylSectors - 1) / kCylSectors) * kCylSectors;

    std::vector<uint8_t> img(static_cast<std::size_t>(total_sectors) * 512, 0);

    fat_volume_layout::MbrPartition part;
    part.status = 0x80;
    PackChs(kPartStart, part.chs_first);
    part.type = kPartType;
    PackChs(kPartStart + part_sectors - 1, part.chs_last);
    part.start_lba = kPartStart;
    part.sectors = part_sectors;
    fat_volume_layout::WriteMbrPartition(img.data(), 0, part);
    fat_volume_layout::WriteBootSignature(img.data());

    uint8_t* bs = img.data() + static_cast<std::size_t>(kPartStart) * 512;
    fat_volume_layout::Bpb bpb;
    bpb.jump[0] = 0xEB; bpb.jump[1] = 0xFE; bpb.jump[2] = 0x00;
    bpb.bytes_per_sector = kBytesPerSec;
    bpb.sectors_per_cluster = kSecPerClus;
    bpb.reserved_sectors = kReserved;
    bpb.num_fats = kNumFats;
    bpb.root_entries = kRootEntries;
    if (part_sectors <= 0xFFFFu) bpb.total_sectors16 = static_cast<uint16_t>(part_sectors);
    else                         bpb.total_sectors32 = part_sectors;
    bpb.media = kMedia;
    bpb.fat_size16 = static_cast<uint16_t>(fat_sectors);
    bpb.sectors_per_track = kSecPerTrack;
    bpb.num_heads = kHeads;
    bpb.hidden_sectors = kPartStart;
    fat_volume_layout::WriteBpb(bs, bpb);
    bs[fat_volume_layout::kBs16DrvNum] = 0x80;
    fat_volume_layout::WriteBootSignature(bs);

    uint32_t next = 2;
    for (auto& e : entries) { e.first_clus = e.clusters ? next : 0; next += e.clusters; }

    const std::size_t fat0 = (static_cast<std::size_t>(kPartStart) + kReserved) * 512;
    auto set_fat = [&](uint32_t clus, uint16_t val) { cerf::le::Put16(img.data() + fat0 + clus * 2, val); };
    set_fat(0, static_cast<uint16_t>(0xFF00u | kMedia));
    set_fat(1, kEoc16);
    for (const auto& e : entries)
        for (uint32_t c = 0; c < e.clusters; ++c)
            set_fat(e.first_clus + c,
                    c + 1 < e.clusters ? static_cast<uint16_t>(e.first_clus + c + 1) : kEoc16);

    const std::size_t root_off =
        (static_cast<std::size_t>(kPartStart) + kReserved + kNumFats * fat_sectors) * 512;
    uint8_t* dir = img.data() + root_off;
    for (const auto& e : entries)
        dir = cf_fat::EmitFileDir(dir, e.name, e.sfn, e.lfn_count, e.ntres, e.first_clus,
                                  static_cast<uint32_t>(e.data.size()));

    const std::size_t data_start =
        (static_cast<std::size_t>(kPartStart) + kReserved + kNumFats * fat_sectors
         + root_sectors) * 512;
    for (const auto& e : entries) {
        if (e.data.empty()) continue;
        std::memcpy(img.data() + data_start +
                        static_cast<std::size_t>(e.first_clus - 2) * clus_bytes,
                    e.data.data(), e.data.size());
    }

    std::FILE* out = nullptr;
    if (_wfopen_s(&out, out_path.c_str(), L"wb") != 0 || !out) {
        LOG(Caution, "[CF] FAT16 build: cannot open output image for write\n");
        return false;
    }
    const bool ok = std::fwrite(img.data(), 1, img.size(), out) == img.size();
    std::fclose(out);
    if (!ok) LOG(Caution, "[CF] FAT16 build: short write to image\n");
    else LOG(Cerf, "[CF] FAT16 image built: %u sectors, %u data clusters, %zu file(s)\n",
             total_sectors, data_clusters, entries.size());
    return ok;
}
