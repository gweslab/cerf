#include "../board_ata_service.h"

#include "../board_context.h"
#include "zune_30_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/host_file_bytes.h"
#include "../../core/log.h"
#include "../../core/cerf_paths.h"
#include "../../core/string_utils.h"
#include "../../storage/disk_image.h"
#include "../../storage/fat_volume_layout.h"

#include <cstdint>
#include <cstring>
#include <string>

namespace {

constexpr uint64_t kCapacityBytes   = 30005821440ull;        /* real Zune 30 HDD */
constexpr uint32_t kSectorSize      = 512u;
constexpr uint64_t kCapacitySectors = kCapacityBytes / kSectorSize;  /* 58,605,120 */
constexpr uint16_t kReservedSectors = 32u;

/* Geometry + BPB field values byte-verified against the real Zune 30 dump
   (hdd_someones_dump.img): MBR @ LBA0, two type-0x0B FAT32 partitions. */
struct ZunePart {
    uint32_t start_lba;
    uint32_t total_sectors;
    uint8_t  sec_per_clus;
    uint32_t fat_size_sectors;
    uint16_t sec_per_track;
    uint16_t num_heads;
    uint32_t vol_id;
};
constexpr ZunePart kP1{ 64u,     307200u,   4u,  600u,  63u, 16u, 0x20202000u };
constexpr ZunePart kP2{ 307264u, 58297856u, 64u, 7117u, 1u,  1u,  0x07F10014u };
static_assert(kP2.start_lba + kP2.total_sectors == kCapacitySectors,
              "P2 must span exactly to disk end");

/* MBR partition-table entries verbatim from the dump @ 0x1BE / 0x1CE
   (boot flag, CHS, type 0x0B, start LBA, sector count). */
constexpr uint8_t kMbrP1[16] = {0x01,0x01,0x02,0x00, 0x0B,0x0D,0x4D,0x30,
                                0x40,0x00,0x00,0x00, 0x00,0xB0,0x04,0x00};
constexpr uint8_t kMbrP2[16] = {0x00,0x0D,0x4E,0x30, 0x0B,0x0F,0xFF,0x1B,
                                0x40,0xB0,0x04,0x00, 0x00,0x8E,0x79,0x03};

using cerf::le::Put32;

class ZuneBoardAtaService : public BoardAtaService {
public:
    using BoardAtaService::BoardAtaService;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Zune30;
    }

    std::string GetImagePath() override {
        const DeviceConfig& cfg = emu_.Get<DeviceConfig>();
        return ResolveDeviceFile(cfg.device_name, cfg.storage_hdd);
    }
    uint64_t GetCapacityBytes() const override { return kCapacityBytes; }

    void EnsureExists() override {
        const std::string path = GetImagePath();
        if (HostFileNonEmpty(path)) return;
        LOG(Boot, "[ZUNE-HDD] no disk image; synthesizing blank Zune 30 HDD "
                  "(MBR + 2 empty FAT32 partitions) at '%s'\n", path.c_str());
        DiskImage img;
        if (!img.Open(path, kCapacityBytes)) {
            LOG(Caution, "[ZUNE-HDD] FATAL: cannot create disk image '%s'\n",
                path.c_str());
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        WriteMbr(img);
        FormatFat32(img, kP1);
        FormatFat32(img, kP2);
        LOG(Boot, "[ZUNE-HDD] synth complete\n");
    }

private:
    static void WriteMbr(DiskImage& img) {
        uint8_t sec[kSectorSize] = {};
        std::memcpy(fat_volume_layout::MbrPartitionEntry(sec, 0), kMbrP1, 16);
        std::memcpy(fat_volume_layout::MbrPartitionEntry(sec, 1), kMbrP2, 16);
        fat_volume_layout::WriteBootSignature(sec);
        img.WriteSectors(0, 1, sec);
    }

    static void FormatFat32(DiskImage& img, const ZunePart& p) {
        uint8_t vbr[kSectorSize] = {};
        fat_volume_layout::Bpb bpb;
        bpb.jump[0] = 0xEB; bpb.jump[1] = 0xFE; bpb.jump[2] = 0x90;
        bpb.oem_name = "MSWIN4.1";
        bpb.sectors_per_cluster = p.sec_per_clus;
        bpb.reserved_sectors = kReservedSectors;
        bpb.num_fats = 2;
        bpb.media = 0xF8;
        bpb.sectors_per_track = p.sec_per_track;
        bpb.num_heads = p.num_heads;
        bpb.total_sectors32 = p.total_sectors;
        fat_volume_layout::WriteBpb(vbr, bpb);
        fat_volume_layout::Fat32Extension ext;
        ext.fat_size32 = p.fat_size_sectors;
        ext.root_cluster = 2;
        ext.fsinfo_sector = 1;
        ext.drive_number = 0x80;
        ext.boot_signature = 0x29;
        ext.volume_id = p.vol_id;
        ext.volume_label = "           ";
        ext.fs_type = "FAT32   ";
        fat_volume_layout::WriteFat32Extension(vbr, ext);
        fat_volume_layout::WriteBootSignature(vbr);
        img.WriteSectors(p.start_lba, 1, vbr);

        uint8_t fsi[kSectorSize] = {};
        fat_volume_layout::WriteFsInfo(fsi, 0xFFFFFFFFu, 0xFFFFFFFFu);
        img.WriteSectors(p.start_lba + 1u, 1, fsi);

        /* Both FAT copies, first sector: entry0=media+EOC, entry1=EOC, entry2=
           root EOC; all other clusters free(0). Rest of each FAT stays
           sparse-zero (free); root cluster stays sparse-zero (empty dir). */
        uint8_t fat0[kSectorSize] = {};
        Put32(fat0 + 0, 0xFFFFFFF8u);
        Put32(fat0 + 4, 0xFFFFFFFFu);
        Put32(fat0 + 8, 0x0FFFFFFFu);
        img.WriteSectors(p.start_lba + kReservedSectors, 1, fat0);
        img.WriteSectors(p.start_lba + kReservedSectors + p.fat_size_sectors, 1, fat0);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(ZuneBoardAtaService, BoardAtaService);
