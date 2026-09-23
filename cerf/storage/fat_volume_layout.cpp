#include "fat_volume_layout.h"

#include "../core/byte_order.h"

#include <cstring>

namespace fat_volume_layout {

uint8_t* MbrPartitionEntry(uint8_t* mbr, unsigned index) {
    return mbr + kMbrPartTable + index * kMbrPartEntryBytes;
}

void WriteMbrPartition(uint8_t* mbr, unsigned index, const MbrPartition& p) {
    uint8_t* e = MbrPartitionEntry(mbr, index);
    e[kPartStatus] = p.status;
    std::memcpy(e + kPartChsFirst, p.chs_first, sizeof(p.chs_first));
    e[kPartType] = p.type;
    std::memcpy(e + kPartChsLast, p.chs_last, sizeof(p.chs_last));
    cerf::le::Put32(e + kPartStartLba, p.start_lba);
    cerf::le::Put32(e + kPartSectors, p.sectors);
}

/* dosfstools src/mkfs.fat.c: BOOT_SIGN 0xAA55 at 0x1FE, also on the FSInfo sector. */
void WriteBootSignature(uint8_t* sector) {
    cerf::le::Put16(sector + kBootSignature, 0xAA55u);
}

void WriteBpb(uint8_t* bs, const Bpb& b) {
    std::memcpy(bs + kBsJump, b.jump, sizeof(b.jump));
    if (b.oem_name) std::memcpy(bs + kBsOemName, b.oem_name, 8);
    cerf::le::Put16(bs + kBpbBytsPerSec, b.bytes_per_sector);
    bs[kBpbSecPerClus] = b.sectors_per_cluster;
    cerf::le::Put16(bs + kBpbRsvdSecCnt, b.reserved_sectors);
    bs[kBpbNumFats] = b.num_fats;
    cerf::le::Put16(bs + kBpbRootEntCnt, b.root_entries);
    cerf::le::Put16(bs + kBpbTotSec16, b.total_sectors16);
    bs[kBpbMedia] = b.media;
    cerf::le::Put16(bs + kBpbFatSz16, b.fat_size16);
    cerf::le::Put16(bs + kBpbSecPerTrk, b.sectors_per_track);
    cerf::le::Put16(bs + kBpbNumHeads, b.num_heads);
    cerf::le::Put32(bs + kBpbHiddSec, b.hidden_sectors);
    cerf::le::Put32(bs + kBpbTotSec32, b.total_sectors32);
}

void WriteFat32Extension(uint8_t* bs, const Fat32Extension& e) {
    cerf::le::Put32(bs + kBpb32FatSz32, e.fat_size32);
    cerf::le::Put16(bs + kBpb32ExtFlags, 0);
    cerf::le::Put16(bs + kBpb32FsVer, 0);
    cerf::le::Put32(bs + kBpb32RootClus, e.root_cluster);
    cerf::le::Put16(bs + kBpb32FsInfo, e.fsinfo_sector);
    cerf::le::Put16(bs + kBpb32BkBootSec, e.backup_boot_sector);
    bs[kBs32DrvNum] = e.drive_number;
    bs[kBs32BootSig] = e.boot_signature;
    cerf::le::Put32(bs + kBs32VolId, e.volume_id);
    if (e.volume_label) std::memcpy(bs + kBs32VolLab, e.volume_label, 11);
    if (e.fs_type) std::memcpy(bs + kBs32FilSysType, e.fs_type, 8);
}

void WriteFsInfo(uint8_t* fsi, uint32_t free_count, uint32_t next_free) {
    cerf::le::Put32(fsi + kFsiLeadSig, kFsiLeadSigValue);
    cerf::le::Put32(fsi + kFsiStrucSig, kFsiStrucSigValue);
    cerf::le::Put32(fsi + kFsiFreeCount, free_count);
    cerf::le::Put32(fsi + kFsiNxtFree, next_free);
    WriteBootSignature(fsi);
}

}
