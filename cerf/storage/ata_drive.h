#pragma once

#include <cstdint>

#include "disk_image.h"

/* A single ATA-6 PIO hard drive, parameterized by a DiskImage*, reusable by any
   ATA host controller. IDENTIFY advertises PIO + LBA28 only — do NOT add DMA or
   LBA48 capability bits without first implementing the FIFO/SDMA bulk-data path,
   or the host issues READ DMA / READ SECTORS EXT and reaches nonexistent code. */
class AtaDrive {
public:
    explicit AtaDrive(DiskImage* disk) : disk_(disk) {}

    /* Task-file register indices; read vs write disambiguates shared offsets. */
    enum Reg : uint8_t {
        kRegError      = 1,  /* read  */
        kRegFeatures   = 1,  /* write */
        kRegSectorCnt  = 2,
        kRegLbaLow     = 3,
        kRegLbaMid     = 4,
        kRegLbaHigh    = 5,
        kRegDevice     = 6,
        kRegStatus     = 7,  /* read  — reading clears INTRQ */
        kRegCommand    = 7,  /* write — triggers command execution */
        kRegAltStatus  = 8,  /* read  — does NOT clear INTRQ */
        kRegControl    = 8,  /* write — device control (nIEN, SRST) */
    };

    uint8_t  ReadTaskFile (uint8_t idx);
    void     WriteTaskFile(uint8_t idx, uint8_t value);
    uint16_t ReadData ();
    void     WriteData(uint16_t value);

    /* INTRQ line as seen by the host controller (already masked by nIEN). */
    bool IrqAsserted() const { return irq_ && !nien_; }

    /* True while a PIO data block is staged (DRQ phase) — i.e. the ATA bus is
       active. The controller maps the inverse onto its controller_idle bit. */
    bool DataTransferActive() const { return buf_len_ != 0; }

private:
    /* ATA STATUS register bits (Linux include/linux/ata.h v6.6). */
    static constexpr uint8_t kStBusy = 0x80u;  /* ATA_BUSY = (1<<7) */
    static constexpr uint8_t kStRdy  = 0x40u;  /* ATA_DRDY = (1<<6) */
    static constexpr uint8_t kStDf   = 0x20u;  /* ATA_DF   = (1<<5) */
    static constexpr uint8_t kStDsc  = 0x10u;  /* DSC/SEEK_STAT (1<<4) */
    static constexpr uint8_t kStDrq  = 0x08u;  /* ATA_DRQ  = (1<<3) */
    static constexpr uint8_t kStErr  = 0x01u;  /* ATA_ERR  = (1<<0) */

    /* ATA ERROR / DEVICE / CONTROL bits (Linux include/linux/ata.h v6.6). */
    static constexpr uint8_t kErrAbrt = 0x04u;  /* ATA_ABORTED = (1<<2) */
    static constexpr uint8_t kDevLba  = 0x40u;  /* ATA_LBA     = (1<<6) */
    static constexpr uint8_t kCtlNien = 0x02u;  /* ATA_NIEN    = (1<<1) */
    static constexpr uint8_t kCtlSrst = 0x04u;  /* ATA_SRST    = (1<<2) */

    static constexpr uint32_t kWordsPerSector = 256u;  /* 512 bytes / 2 */

    /* Max sectors per READ/WRITE MULTIPLE block we advertise (IDENTIFY word 47,
       ATA/ATAPI-6 §8.15.22). The PIO buffer holds one whole DRQ block, so it is
       sized for this many sectors. The pmc_atapi driver (sub_30549E0) issues SET
       MULTIPLE MODE with this value and then drives READ MULTIPLE (0xC4). */
    static constexpr uint32_t kMaxMultiple = 16u;

    void Reset();  /* present the post-reset ATA device signature */
    void ExecCommand(uint8_t cmd);
    void BuildIdentify();
    bool LoadNextReadBlock();
    void CompleteNonData();
    void AbortCommand(uint8_t cmd);
    uint32_t CurrentLba28() const;

    DiskImage* disk_;

    /* Power-on state IS the post-reset ATA signature (see Reset()). */
    uint8_t features_   = 0;
    uint8_t error_      = 0x01u;  /* device 0 passed diagnostic */
    uint8_t sector_cnt_ = 0x01u;
    uint8_t lba_low_    = 0x01u;
    uint8_t lba_mid_    = 0x00u;
    uint8_t lba_high_   = 0x00u;
    uint8_t device_     = 0;
    uint8_t status_     = kStRdy | kStDsc;

    bool nien_ = false;
    bool irq_  = false;

    uint16_t buf_[kMaxMultiple * kWordsPerSector] = {};
    uint32_t buf_pos_ = 0;  /* next word index */
    uint32_t buf_len_ = 0;  /* valid words (0 = no transfer active) */
    bool     buf_out_ = false;  /* true: host writing (WRITE SECTORS) */

    uint32_t xfer_lba_       = 0;
    uint32_t xfer_remaining_ = 0;

    /* READ/WRITE MULTIPLE block size in sectors (IDENTIFY word 59, set by SET
       MULTIPLE MODE 0xC6). 0 = multiple mode disabled. cur_block_ is the block
       size of the in-flight transfer: 1 for READ/WRITE SECTORS, multiple_block_
       for READ/WRITE MULTIPLE — one INTRQ per DRQ block (ATA/ATAPI-6 §8.30/8.60.8). */
    uint32_t multiple_block_ = 0;
    uint32_t cur_block_      = 1;

    /* One-shot boot-milestone logging (IDENTIFY / first READ / first WRITE). */
    bool logged_id_ = false, logged_rd_ = false, logged_wr_ = false;
};
