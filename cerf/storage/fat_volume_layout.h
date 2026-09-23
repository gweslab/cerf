#pragma once

#include <cstdint>

namespace fat_volume_layout {

/* QEMU block/vvfat.c: bootsector_t, partition_t, mbr_t. */
inline constexpr uint32_t kBsJump         = 0;
inline constexpr uint32_t kBsOemName      = 3;
inline constexpr uint32_t kBpbBytsPerSec  = 11;
inline constexpr uint32_t kBpbSecPerClus  = 13;
inline constexpr uint32_t kBpbRsvdSecCnt  = 14;
inline constexpr uint32_t kBpbNumFats     = 16;
inline constexpr uint32_t kBpbRootEntCnt  = 17;
inline constexpr uint32_t kBpbTotSec16    = 19;
inline constexpr uint32_t kBpbMedia       = 21;
inline constexpr uint32_t kBpbFatSz16     = 22;
inline constexpr uint32_t kBpbSecPerTrk   = 24;
inline constexpr uint32_t kBpbNumHeads    = 26;
inline constexpr uint32_t kBpbHiddSec     = 28;
inline constexpr uint32_t kBpbTotSec32    = 32;
inline constexpr uint32_t kBs16DrvNum     = 36;
inline constexpr uint32_t kBpb32FatSz32   = 36;
inline constexpr uint32_t kBpb32ExtFlags  = 40;
inline constexpr uint32_t kBpb32FsVer     = 42;
inline constexpr uint32_t kBpb32RootClus  = 44;
inline constexpr uint32_t kBpb32FsInfo    = 48;
inline constexpr uint32_t kBpb32BkBootSec = 50;
inline constexpr uint32_t kBs32DrvNum     = 64;
inline constexpr uint32_t kBs32BootSig    = 66;
inline constexpr uint32_t kBs32VolId      = 67;
inline constexpr uint32_t kBs32VolLab     = 71;
inline constexpr uint32_t kBs32FilSysType = 82;
inline constexpr uint32_t kBootSignature  = 510;

inline constexpr uint32_t kMbrPartTable      = 446;
inline constexpr uint32_t kMbrPartEntryBytes = 16;
inline constexpr uint32_t kPartStatus        = 0;
inline constexpr uint32_t kPartChsFirst      = 1;
inline constexpr uint32_t kPartType          = 4;
inline constexpr uint32_t kPartChsLast       = 5;
inline constexpr uint32_t kPartStartLba      = 8;
inline constexpr uint32_t kPartSectors       = 12;

/* Linux include/uapi/linux/msdos_fs.h: struct fat_boot_fsinfo, FAT_FSINFO_SIG1/2. */
inline constexpr uint32_t kFsiLeadSig      = 0;
inline constexpr uint32_t kFsiStrucSig     = 484;
inline constexpr uint32_t kFsiFreeCount    = 488;
inline constexpr uint32_t kFsiNxtFree      = 492;
inline constexpr uint32_t kFsiLeadSigValue  = 0x41615252u;
inline constexpr uint32_t kFsiStrucSigValue = 0x61417272u;

struct MbrPartition {
    uint8_t  status = 0;
    uint8_t  chs_first[3] = {};
    uint8_t  type = 0;
    uint8_t  chs_last[3] = {};
    uint32_t start_lba = 0;
    uint32_t sectors = 0;
};

struct Bpb {
    uint8_t     jump[3] = {};
    const char* oem_name = nullptr;
    uint16_t    bytes_per_sector = 512;
    uint8_t     sectors_per_cluster = 0;
    uint16_t    reserved_sectors = 0;
    uint8_t     num_fats = 0;
    uint16_t    root_entries = 0;
    uint16_t    total_sectors16 = 0;
    uint8_t     media = 0;
    uint16_t    fat_size16 = 0;
    uint16_t    sectors_per_track = 0;
    uint16_t    num_heads = 0;
    uint32_t    hidden_sectors = 0;
    uint32_t    total_sectors32 = 0;
};

struct Fat32Extension {
    uint32_t    fat_size32 = 0;
    uint32_t    root_cluster = 0;
    uint16_t    fsinfo_sector = 0;
    uint16_t    backup_boot_sector = 0;
    uint8_t     drive_number = 0;
    uint8_t     boot_signature = 0;
    uint32_t    volume_id = 0;
    const char* volume_label = nullptr;
    const char* fs_type = nullptr;
};

uint8_t* MbrPartitionEntry(uint8_t* mbr, unsigned index);
void WriteMbrPartition(uint8_t* mbr, unsigned index, const MbrPartition& p);
void WriteBootSignature(uint8_t* sector);
void WriteBpb(uint8_t* bs, const Bpb& b);
void WriteFat32Extension(uint8_t* bs, const Fat32Extension& e);
void WriteFsInfo(uint8_t* fsi, uint32_t free_count, uint32_t next_free);

}
