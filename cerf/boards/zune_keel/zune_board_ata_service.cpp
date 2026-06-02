#include "../board_ata_service.h"

#include "../board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/string_utils.h"
#include "../../storage/disk_image.h"

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

inline void Put16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); }
inline void Put32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v); p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24);
}

class ZuneBoardAtaService : public BoardAtaService {
public:
    using BoardAtaService::BoardAtaService;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    std::string GetImagePath() override {
        return GetCerfDir() + "devices/" +
               emu_.Get<DeviceConfig>().device_name + "/hdd.img";
    }
    uint64_t GetCapacityBytes() const override { return kCapacityBytes; }

    void EnsureExists() override {
        const std::string path = GetImagePath();
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad)) {
            const uint64_t sz =
                (uint64_t(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
            if (sz > 0) return;  /* user's disk — never touch */
        }
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
        std::memcpy(sec + 0x1BE, kMbrP1, 16);
        std::memcpy(sec + 0x1CE, kMbrP2, 16);
        sec[0x1FE] = 0x55; sec[0x1FF] = 0xAA;
        img.WriteSectors(0, 1, sec);
    }

    static void FormatFat32(DiskImage& img, const ZunePart& p) {
        uint8_t vbr[kSectorSize] = {};
        vbr[0] = 0xEB; vbr[1] = 0xFE; vbr[2] = 0x90;   /* halt; never runs on ARM */
        std::memcpy(vbr + 3, "MSWIN4.1", 8);
        Put16(vbr + 11, 512);
        vbr[13] = p.sec_per_clus;
        Put16(vbr + 14, kReservedSectors);
        vbr[16] = 2;                                   /* num FATs */
        vbr[21] = 0xF8;                                /* media */
        Put16(vbr + 24, p.sec_per_track);
        Put16(vbr + 26, p.num_heads);
        Put32(vbr + 32, p.total_sectors);
        Put32(vbr + 36, p.fat_size_sectors);
        Put32(vbr + 44, 2);                            /* root cluster */
        Put16(vbr + 48, 1);                            /* FSInfo sector */
        vbr[64] = 0x80;                                /* drive number */
        vbr[66] = 0x29;                                /* extended boot signature */
        Put32(vbr + 67, p.vol_id);
        std::memset(vbr + 71, ' ', 11);                /* volume label (blank) */
        std::memcpy(vbr + 82, "FAT32   ", 8);
        vbr[510] = 0x55; vbr[511] = 0xAA;
        img.WriteSectors(p.start_lba, 1, vbr);

        uint8_t fsi[kSectorSize] = {};
        Put32(fsi + 0,   0x41615252u);                 /* lead sig */
        Put32(fsi + 484, 0x61417272u);                 /* struc sig */
        Put32(fsi + 488, 0xFFFFFFFFu);                 /* free count: unknown */
        Put32(fsi + 492, 0xFFFFFFFFu);                 /* next free: unknown */
        Put32(fsi + 508, 0xAA550000u);                 /* trail sig */
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
