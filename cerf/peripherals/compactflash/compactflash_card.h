#pragma once

#include "../pcmcia/pcmcia_card.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

/* CompactFlash card in PC Card ATA mode (PCMCIA FUNCID 4 = fixed disk):
   ATA task-file in I/O space, backed by a host image file in 512-byte
   LBA sectors (read+write). Register/command codes: ATAPI.H. */
class CompactFlashCard : public PcmciaCard {
public:
    CompactFlashCard(CerfEmulator& emu, std::wstring image_path);
    ~CompactFlashCard() override;

    std::wstring DisplayName() const override;
    std::wstring MenuLabel() const override;
    std::wstring TooltipDetail() const override;
    const wchar_t* IconResource() const override { return L"ICON_PCMCIA_CF"; }

    void PowerOn () override;
    void PowerOff() override;

    uint8_t  ReadAttribute8 (uint32_t offset)                override;
    void     WriteAttribute8(uint32_t offset, uint8_t value) override;

    uint8_t  ReadCommon8  (uint32_t offset)                  override;
    uint16_t ReadCommon16 (uint32_t offset)                  override;
    void     WriteCommon8 (uint32_t offset, uint8_t  value)  override;
    void     WriteCommon16(uint32_t offset, uint16_t value)  override;

    uint8_t  ReadIo8  (uint32_t offset)                      override;
    uint16_t ReadIo16 (uint32_t offset)                      override;
    void     WriteIo8 (uint32_t offset, uint8_t  value)      override;
    void     WriteIo16(uint32_t offset, uint16_t value)      override;

    const char* SaveId() const override { return "cf"; }
    std::wstring SaveBinding() const override { return image_path_; }
    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    /* A failed-open card still inserts and reports ATA not-ready (status
       without READY), so the OS sees a failed disk, not an empty socket. */
    bool ImageOk() const { return file_ != nullptr; }

private:
    std::wstring ImageName() const;
    /* ATAPI.H register offsets within the I/O window. kRegDevCtl is the
       device-control / alternate-status register. */
    enum : uint32_t {
        kRegData = 0, kRegFeature = 1, kRegError = 1, kRegSectCnt = 2,
        kRegSectNum = 3, kRegCylLow = 4, kRegCylHigh = 5, kRegDrvHead = 6,
        kRegCommand = 7, kRegStatus = 7, kRegDevCtl = 0x0E,
    };

    /* Card I/O address -> task-file register for the active COR config:
       config 2/3 decode 10 address lines at the legacy ATA bases
       (0x1F0/0x3F6, 0x170/0x376); config 0/1 decode 4 lines (16-byte
       alias). -1 = address not decoded by this config. */
    int DecodeIoLocked(uint32_t offset) const;

    /* Common-memory address -> task-file register in memory-mapped mode
       (config 0, the power-up default): task file at 0x0-0xF. */
    int DecodeCommonLocked(uint32_t offset) const;

    /* Task-file register engine shared by the I/O and common-memory
       decodes. reg < 0 reads float (0xFF) / writes drop. */
    uint8_t  ReadRegLocked (int reg);
    void     WriteRegLocked(int reg, uint8_t value);
    uint16_t ReadData16Locked();
    void     WriteData16Locked(uint16_t value);
    void     WriteData8Locked(uint8_t value);

    void IrqAssertLocked();
    void IrqClearLocked();

    void StartReadLocked();
    void StartWriteLocked();
    void CompleteWriteSectorLocked();
    void BuildIdentifyLocked();
    uint64_t CurrentLbaLocked() const;
    void AdvanceSectorLocked();
    bool ReadSectorLocked (uint64_t lba, uint8_t* out);
    bool WriteSectorLocked(uint64_t lba, const uint8_t* in);

    const std::wstring image_path_;
    std::FILE*         file_ = nullptr;
    uint64_t           total_sectors_ = 0;

    mutable std::mutex mtx_;

    /* ATA task-file registers. */
    uint8_t  feature_  = 0;
    uint8_t  error_    = 0;
    uint8_t  sect_cnt_ = 1;
    uint8_t  sect_num_ = 1;
    uint8_t  cyl_low_  = 0;
    uint8_t  cyl_high_ = 0;
    uint8_t  drv_head_ = 0xA0;   /* ATA_HEAD_MUST_BE_ON */
    uint8_t  status_   = 0;      /* set in PowerOn */
    uint8_t  dev_ctrl_ = 0;

    /* Geometry for CHS translation (used when DRV_HEAD LBA bit clear). */
    uint32_t chs_heads_   = 0;
    uint32_t chs_sectors_ = 0;

    /* 512-byte PIO data buffer + cursor; drained/filled through the data
       port one 16-bit word at a time. */
    std::array<uint8_t, 512> buf_{};
    uint32_t buf_pos_ = 0;     /* byte cursor into buf_ */
    uint32_t sectors_left_ = 0;
    bool     writing_ = false;

    uint8_t cor_ = 0;          /* config-option register (attribute 0x200) */
    bool    irq_line_ = false; /* INTRQ pin state */
};
