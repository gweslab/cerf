#pragma once

#include <cstdint>

constexpr uint32_t kRomSignature       = 0x43454345u;
constexpr uint32_t kRomSignatureOffset = 0x40u;
constexpr uint32_t kEcecOffPtoc        = 0x04;
constexpr uint32_t kEcecOffRomhdr      = 0x08;
constexpr uint32_t kEcecRecordSize     = 12;

constexpr uint8_t  kImgfsUuid[16] = {
    0xF8, 0xAC, 0x2C, 0x9D, 0xE3, 0xD4, 0x2B, 0x4D,
    0xBD, 0x30, 0x91, 0x6E, 0xD8, 0x4F, 0x31, 0xDC,
};
constexpr uint32_t kImgfsSbOffDirentSize    = 0x1C;
constexpr uint32_t kImgfsSbOffBytesPerBlock = 0x24;
constexpr uint32_t kImgfsSbSize             = 0x28;
constexpr uint32_t kImgfsDirentSize         = 0x34;

constexpr uint32_t kE32OffObjcnt      = 0x00;
constexpr uint32_t kE32OffImageflags  = 0x02;
constexpr uint32_t kE32OffEntryRva    = 0x04;
constexpr uint32_t kE32OffVbase       = 0x08;
constexpr uint32_t kE32OffSubsysMajor = 0x0C;
constexpr uint32_t kE32OffSubsysMinor = 0x0E;

struct E32RomLayout {
    uint32_t size;
    uint32_t off_objcnt;
    uint32_t off_imageflags;
    uint32_t off_entryrva;
    uint32_t off_vbase;
    uint32_t off_subsysmajor;
    uint32_t off_subsysminor;
    int32_t  off_stackmax;      /* absent on CE2.0 → negative (added in CE2.11) */
    int32_t  off_vsize;
    int32_t  off_sect14rva;     /* absent on CE2 → negative (added in CE3) */
    int32_t  off_sect14size;    /* absent on CE2 → negative (added in CE3) */
    int32_t  off_timestamp;     /* absent on CE3 → negative */
    uint32_t off_unit;
    uint32_t off_subsys;
};

constexpr E32RomLayout kE32RomCE211 = {
    100,
    kE32OffObjcnt, kE32OffImageflags, kE32OffEntryRva, kE32OffVbase,
    kE32OffSubsysMajor, kE32OffSubsysMinor, 0x10, 0x14,
    -1, -1,
    -1,
    0x1C, 0x18,
};

/* CE 2.0 e32_rom (no e32_stackmax): e32_vsize@0x10, e32_subsys@0x14, DD array@0x18. */
constexpr E32RomLayout kE32RomCE20 = {
    96,
    kE32OffObjcnt, kE32OffImageflags, kE32OffEntryRva, kE32OffVbase,
    kE32OffSubsysMajor, kE32OffSubsysMinor, -1, 0x10,
    -1, -1,
    -1,
    0x18, 0x14,
};

constexpr E32RomLayout kE32RomCE3 = {
    106,
    kE32OffObjcnt, kE32OffImageflags, kE32OffEntryRva, kE32OffVbase,
    kE32OffSubsysMajor, kE32OffSubsysMinor, 0x10, 0x14,
    0x18, 0x1C,
    -1,
    0x20, 0x68,
};

constexpr E32RomLayout kE32RomCE5plus = {
    110,
    kE32OffObjcnt, kE32OffImageflags, kE32OffEntryRva, kE32OffVbase,
    kE32OffSubsysMajor, kE32OffSubsysMinor, 0x10, 0x14,
    0x18, 0x1C,
    0x20,
    0x24, 0x6C,
};

constexpr int kE32UnitCount = 9;

constexpr uint32_t kE32RomCE5plusO32Base = 0x70;

constexpr uint32_t kRomHdrSize    = 84;
constexpr uint32_t kTocEntrySize  = 32;

constexpr uint32_t kO32RomSize    = 24;
constexpr uint32_t kO32OffVsize    = 0;
constexpr uint32_t kO32OffRva      = 4;
constexpr uint32_t kO32OffPsize    = 8;
constexpr uint32_t kO32OffDataptr  = 12;
constexpr uint32_t kO32OffRealaddr = 16;
constexpr uint32_t kO32OffFlags    = 20;

/* ROMHDR field offsets. */
constexpr uint32_t kHdrDllFirstOff       = 0x00;
constexpr uint32_t kHdrDllLastOff        = 0x04;
constexpr uint32_t kHdrPhysFirstOff      = 0x08;
constexpr uint32_t kHdrPhysLastOff       = 0x0C;
constexpr uint32_t kHdrNumModsOff        = 0x10;
constexpr uint32_t kHdrRAMStartOff       = 0x14;
constexpr uint32_t kHdrRAMFreeOff        = 0x18;
constexpr uint32_t kHdrRAMEndOff         = 0x1C;
constexpr uint32_t kHdrCopyEntriesOff    = 0x20;
constexpr uint32_t kHdrCopyOffsetOff     = 0x24;
constexpr uint32_t kHdrProfileLenOff     = 0x28;
constexpr uint32_t kHdrProfileOffsetOff  = 0x2C;
constexpr uint32_t kHdrNumFilesOff       = 0x30;
constexpr uint32_t kHdrKernelFlagsOff    = 0x34;
constexpr uint32_t kHdrFSRamPercentOff   = 0x38;
constexpr uint32_t kHdrDrivglobStartOff  = 0x3C;
constexpr uint32_t kHdrDrivglobLenOff    = 0x40;
constexpr uint32_t kHdrCPUTypeOff        = 0x44;
constexpr uint32_t kHdrMiscFlagsOff      = 0x46;
constexpr uint32_t kHdrExtensionsOff     = 0x48;
constexpr uint32_t kHdrTrackingStartOff  = 0x4C;
constexpr uint32_t kHdrTrackingLenOff    = 0x50;

/* TOCentry field offsets. */
constexpr uint32_t kTocOffAttributes = 0x00;
constexpr uint32_t kTocOffTimeLow    = 0x04;
constexpr uint32_t kTocOffTimeHigh   = 0x08;
constexpr uint32_t kTocOffNFileSize  = 0x0C;
constexpr uint32_t kTocOffFileName   = 0x10;
constexpr uint32_t kTocOffE32Offset  = 0x14;
constexpr uint32_t kTocOffO32Offset  = 0x18;
constexpr uint32_t kTocOffLoadOffset = 0x1C;

constexpr uint32_t kFileEntrySize     = 28;
constexpr uint32_t kFileOffAttributes = 0x00;
constexpr uint32_t kFileOffTimeLow    = 0x04;
constexpr uint32_t kFileOffTimeHigh   = 0x08;
constexpr uint32_t kFileOffRealSize   = 0x0C;
constexpr uint32_t kFileOffCompSize   = 0x10;
constexpr uint32_t kFileOffFileName   = 0x14;
constexpr uint32_t kFileOffLoadOffset = 0x18;

constexpr uint32_t kRomPageMask = 0xFFFu;
constexpr uint32_t AlignRomPage(uint32_t v) { return (v + kRomPageMask) & ~kRomPageMask; }
