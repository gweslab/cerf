#include "ata_drive.h"

#include <cstring>

#include "../core/log.h"

uint32_t AtaDrive::CurrentLba28() const {
    return (static_cast<uint32_t>(device_ & 0x0Fu) << 24) |
           (static_cast<uint32_t>(lba_high_) << 16) |
           (static_cast<uint32_t>(lba_mid_)  << 8)  |
            static_cast<uint32_t>(lba_low_);
}

uint8_t AtaDrive::ReadTaskFile(uint8_t idx) {
    switch (idx) {
        case kRegStatus:    irq_ = false; return status_;  /* read clears INTRQ */
        case kRegAltStatus: return status_;                /* no INTRQ clear */
        case kRegError:     return error_;
        case kRegSectorCnt: return sector_cnt_;
        case kRegLbaLow:    return lba_low_;
        case kRegLbaMid:    return lba_mid_;
        case kRegLbaHigh:   return lba_high_;
        case kRegDevice:    return device_;
    }
    return 0xFFu;
}

void AtaDrive::WriteTaskFile(uint8_t idx, uint8_t value) {
    switch (idx) {
        case kRegFeatures:   features_   = value; return;
        case kRegSectorCnt:  sector_cnt_ = value; return;
        case kRegLbaLow:     lba_low_    = value; return;
        case kRegLbaMid:     lba_mid_    = value; return;
        case kRegLbaHigh:    lba_high_   = value; return;
        case kRegDevice:     device_     = value; return;
        case kRegCommand:    ExecCommand(value);  return;
        case kRegControl:
            nien_ = (value & kCtlNien) != 0;
            if (value & kCtlSrst) Reset();
            return;
    }
}

uint16_t AtaDrive::ReadData() {
    if (buf_out_ || buf_len_ == 0 || buf_pos_ >= buf_len_) return 0xFFFFu;

    const uint16_t v = buf_[buf_pos_++];
    if (buf_pos_ >= buf_len_) {  /* current DRQ block drained */
        status_ &= ~kStDrq;
        buf_len_ = 0;
        if (xfer_remaining_ > 0) {
            LoadNextReadBlock();  /* refills next block, re-sets DRQ + one INTRQ */
        }
    }
    return v;
}

void AtaDrive::WriteData(uint16_t value) {
    if (!buf_out_ || buf_pos_ >= buf_len_) return;

    buf_[buf_pos_++] = value;
    if (buf_pos_ < buf_len_) return;

    /* Whole DRQ block received — flush it to the disk in one go. */
    const uint32_t n = buf_len_ / kWordsPerSector;
    if (!disk_ || !disk_->WriteSectors(xfer_lba_, n, buf_)) {
        AbortCommand(cur_block_ > 1u ? 0xC5u : 0x30u);
        return;
    }
    xfer_lba_       += n;
    xfer_remaining_ -= n;
    if (xfer_remaining_ > 0) {
        const uint32_t m = cur_block_ < xfer_remaining_ ? cur_block_ : xfer_remaining_;
        buf_pos_ = 0;                  /* next block (full or partial) */
        buf_len_ = m * kWordsPerSector;
        status_  = kStRdy | kStDrq;
    } else {
        buf_len_ = buf_pos_ = 0;
        buf_out_ = false;
        status_  = kStRdy;             /* transfer complete */
    }
    irq_ = true;                       /* one INTRQ per DRQ block (§8.60.8) */
}

/* Read the next DRQ block: min(cur_block_, remaining) sectors. cur_block_ is 1
   for READ SECTORS (one sector / one INTRQ) and multiple_block_ for READ
   MULTIPLE (a block / one INTRQ). ATA/ATAPI-6 §8.30. */
bool AtaDrive::LoadNextReadBlock() {
    const uint32_t n = cur_block_ < xfer_remaining_ ? cur_block_ : xfer_remaining_;
    if (!disk_ || !disk_->ReadSectors(xfer_lba_, n, buf_)) {
        AbortCommand(cur_block_ > 1u ? 0xC4u : 0x20u);
        return false;
    }
    xfer_lba_       += n;
    xfer_remaining_ -= n;
    buf_pos_ = 0;
    buf_len_ = n * kWordsPerSector;
    buf_out_ = false;
    status_  = kStRdy | kStDrq;
    irq_     = true;                   /* INTRQ at the start of each block (§8.30) */
    return true;
}

void AtaDrive::CompleteNonData() {
    status_ = kStRdy;
    error_  = 0;
    irq_    = true;
}

void AtaDrive::AbortCommand(uint8_t cmd) {
    LOG(Caution, "[ATA] command 0x%02X aborted (lba=%u remaining=%u)\n",
        cmd, CurrentLba28(), xfer_remaining_);
    error_   = kErrAbrt;
    status_  = kStRdy | kStErr;
    buf_len_ = buf_pos_ = 0;
    buf_out_ = false;
    xfer_remaining_ = 0;
    irq_ = true;
}

void AtaDrive::Reset() {
    /* Post-reset ATA hard-disk signature (QEMU v8.2.0 ide_reset +
       ide_set_signature + cmd_exec_dev_diagnostic). The host reads ERROR +
       count/LBA to detect a present non-packet device; without 0x01/1/1/0/0 it
       treats the bay as empty and never issues IDENTIFY. */
    status_     = kStRdy | kStDsc;
    error_      = 0x01u;
    sector_cnt_ = 0x01u;
    lba_low_    = 0x01u;
    lba_mid_    = 0x00u;
    lba_high_   = 0x00u;
    device_     = 0;
    buf_len_ = buf_pos_ = 0;
    buf_out_ = false;
    xfer_remaining_ = 0;
    irq_ = false;
}

void AtaDrive::ExecCommand(uint8_t cmd) {
    if (!disk_ || !disk_->IsOpen()) { AbortCommand(cmd); return; }

    switch (cmd) {
        case 0xECu:  /* IDENTIFY DEVICE */
            if (!logged_id_) {
                logged_id_ = true;
                LOG(Boot, "[ATA] IDENTIFY DEVICE (advertising %llu sectors)\n",
                    static_cast<unsigned long long>(disk_->SectorCount()));
            }
            BuildIdentify();
            buf_pos_ = 0;
            buf_len_ = kWordsPerSector;
            buf_out_ = false;
            xfer_remaining_ = 0;
            error_  = 0;
            status_ = kStRdy | kStDrq;
            irq_    = true;
            return;

        case 0x20u:    /* READ SECTORS  (PIO, LBA28, 1 sector / INTRQ) */
        case 0xC4u: {  /* READ MULTIPLE (PIO, LBA28, block / INTRQ, §8.30) */
            if (cmd == 0xC4u && multiple_block_ == 0u) { AbortCommand(cmd); return; }
            const uint32_t n = sector_cnt_ ? sector_cnt_ : 256u;
            xfer_lba_       = CurrentLba28();
            xfer_remaining_ = n;
            cur_block_      = cmd == 0xC4u ? multiple_block_ : 1u;
            error_          = 0;
            if (!logged_rd_) {
                logged_rd_ = true;
                LOG(Boot, "[ATA] first READ cmd=0x%02X lba=%u count=%u block=%u\n",
                    cmd, xfer_lba_, n, cur_block_);
            }
            LoadNextReadBlock();
            return;
        }

        case 0x30u:    /* WRITE SECTORS  (PIO, LBA28, 1 sector / INTRQ) */
        case 0xC5u: {  /* WRITE MULTIPLE (PIO, LBA28, block / INTRQ, §8.60.8) */
            if (cmd == 0xC5u && multiple_block_ == 0u) { AbortCommand(cmd); return; }
            const uint32_t n = sector_cnt_ ? sector_cnt_ : 256u;
            xfer_lba_       = CurrentLba28();
            xfer_remaining_ = n;
            cur_block_      = cmd == 0xC5u ? multiple_block_ : 1u;
            error_          = 0;
            if (!logged_wr_) {
                logged_wr_ = true;
                LOG(Boot, "[ATA] first WRITE cmd=0x%02X lba=%u count=%u block=%u\n",
                    cmd, xfer_lba_, n, cur_block_);
            }
            const uint32_t m = cur_block_ < n ? cur_block_ : n;
            buf_pos_ = 0;
            buf_len_ = m * kWordsPerSector;
            buf_out_ = true;
            status_  = kStRdy | kStDrq;  /* host writes the first block */
            return;
        }

        case 0xC6u:  /* SET MULTIPLE MODE — Sector Count = sectors/block (§8.39) */
            /* The host requests a block size in the Sector Count register; we
               support up to kMaxMultiple (what IDENTIFY word 47 advertises). A
               count of 0 disables multiple mode. */
            if (sector_cnt_ > kMaxMultiple) { AbortCommand(cmd); return; }
            multiple_block_ = sector_cnt_;
            CompleteNonData();
            return;

        case 0xEFu:  /* SET FEATURES */
            /* Subcommand 0x03 = set transfer mode; sector_cnt_ holds the mode.
               Modes 0x00..0x0F are PIO (accept); 0x20+/0x40+ are MWDMA/UDMA
               which this drive does not implement, so abort honestly. */
            if (features_ == 0x03u && sector_cnt_ >= 0x20u) { AbortCommand(cmd); return; }
            CompleteNonData();
            return;

        case 0xE7u:  /* FLUSH CACHE — writes are synchronous, nothing to flush */
        case 0x91u:  /* INITIALIZE DEVICE PARAMETERS — legacy CHS, LBA in use */
        case 0xE0u:  /* STANDBY IMMEDIATE (ATA_CMD_STANDBYNOW1) */
        case 0xE1u:  /* IDLE IMMEDIATE (ATA_CMD_IDLEIMMEDIATE) */
        case 0xE2u:  /* STANDBY (ATA_CMD_STANDBY) */
        case 0xE3u:  /* IDLE (ATA_CMD_IDLE) */
        case 0xE6u:  /* SLEEP (ATA_CMD_SLEEP) */
            CompleteNonData();
            return;

        case 0x90u:  /* EXECUTE DEVICE DIAGNOSTIC — device 0 passed */
            error_ = 0x01u;
            status_ = kStRdy;
            irq_ = true;
            return;

        case 0xE5u:  /* CHECK POWER MODE — report active/idle */
            sector_cnt_ = 0xFFu;
            CompleteNonData();
            return;

        default:
            AbortCommand(cmd);
            return;
    }
}

void AtaDrive::BuildIdentify() {
    std::memset(buf_, 0, sizeof(buf_));

    auto put_str = [&](uint32_t w0, const char* s, uint32_t chars) {
        for (uint32_t k = 0; k < chars / 2u; ++k) {
            const char c0 = s[2u * k]     ? s[2u * k]     : ' ';
            const char c1 = c0 && s[2u * k + 1] ? s[2u * k + 1] : ' ';
            buf_[w0 + k] = static_cast<uint16_t>(
                (static_cast<uint8_t>(c0) << 8) | static_cast<uint8_t>(c1));
        }
    };

    /* Capacity from the backing DiskImage, clamped to the LBA28 limit. */
    uint64_t total = disk_ ? disk_->SectorCount() : 0;
    if (total > 0x0FFFFFFFull) total = 0x0FFFFFFFull;
    const uint32_t total28 = static_cast<uint32_t>(total);

    /* Legacy CHS translation (ATA-6 word 1 clamps cylinders to 16383). */
    const uint32_t heads = 16u, spt = 63u;
    uint32_t cyl = total28 / (heads * spt);
    if (cyl > 16383u) cyl = 16383u;
    const uint32_t chs_cap = cyl * heads * spt;

    /* Constant words: QEMU v8.2.0 hw/ide/core.c ide_identify(), with the
       DMA/UDMA/LBA48/SMART capability bits cleared (those data paths are not
       implemented — see the class comment). */
    buf_[0]  = 0x0040u;                 /* general config: fixed ATA device */
    buf_[1]  = static_cast<uint16_t>(cyl);
    buf_[3]  = static_cast<uint16_t>(heads);
    buf_[6]  = static_cast<uint16_t>(spt);
    put_str(10, "CERF-ZUNE-HDD-0001", 20);   /* serial number */
    buf_[20] = 3u;
    buf_[21] = 512u;
    buf_[22] = 4u;
    put_str(23, "CERF1.00", 8);              /* firmware revision */
    put_str(27, "CERF Virtual ATA Disk", 40); /* model number */
    /* Word 47 bits(7:0) = max sectors/MULTIPLE-block, word 59 bit8+bits(7:0) =
       current block size (§8.15.22/8.15.28). If 0, pmc_atapi sub_30549E0 leaves
       its PIO chunk a1[1872]=0 and READ MULTIPLE transfers nothing (read hangs). */
    buf_[47] = static_cast<uint16_t>(0x8000u | kMaxMultiple);
    buf_[59] = multiple_block_ ? static_cast<uint16_t>(0x0100u | multiple_block_) : 0u;
    buf_[48] = 1u;
    buf_[49] = (1u << 11) | (1u << 9);  /* IORDY + LBA (no DMA bit 8) */
    buf_[51] = 0x200u;
    buf_[52] = 0x200u;
    buf_[53] = (1u << 0) | (1u << 1);   /* words 54-58 + 64-70 valid (no 88) */
    buf_[54] = static_cast<uint16_t>(cyl);
    buf_[55] = static_cast<uint16_t>(heads);
    buf_[56] = static_cast<uint16_t>(spt);
    buf_[57] = static_cast<uint16_t>(chs_cap);
    buf_[58] = static_cast<uint16_t>(chs_cap >> 16);
    buf_[60] = static_cast<uint16_t>(total28);          /* LBA28 sector count */
    buf_[61] = static_cast<uint16_t>(total28 >> 16);
    buf_[64] = 0x03u;                   /* PIO modes 3 and 4 supported */
    buf_[67] = 120u;                    /* min PIO cycle, no IORDY (ns) */
    buf_[68] = 120u;                    /* min PIO cycle, IORDY (ns) */
    buf_[80] = 0xF0u;                   /* major version ATA-4..7 */
    buf_[81] = 0x16u;                   /* minor version */
    buf_[82] = (1u << 14) | (1u << 5);  /* NOP + write cache (no SMART) */
    buf_[83] = (1u << 14) | (1u << 12); /* FLUSH CACHE (no LBA48 / no EXT) */
    buf_[84] = (1u << 14);
    buf_[85] = (1u << 14) | (1u << 5);  /* write cache enabled (no SMART) */
    buf_[86] = (1u << 12);              /* FLUSH CACHE enabled */
    buf_[87] = (1u << 14);
    buf_[93] = 1u | (1u << 14) | 0x2000u;  /* hw reset / single device */
}
