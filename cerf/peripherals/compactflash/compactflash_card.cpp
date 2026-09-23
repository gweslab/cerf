#include "compactflash_card.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../pcmcia/pcmcia_slot.h"
#include "../../state/state_stream.h"

#include <cstring>

namespace {

/* ATA status bits (ATAPI.H). */
constexpr uint8_t kStBusy  = 0x80;
constexpr uint8_t kStReady = 0x40;
constexpr uint8_t kStSeek  = 0x10;   /* DSC */
constexpr uint8_t kStDrq   = 0x08;
constexpr uint8_t kStError = 0x01;

/* ATA commands (ATAPI.H). */
constexpr uint8_t kCmdRead     = 0x20;
constexpr uint8_t kCmdWrite    = 0x30;
constexpr uint8_t kCmdIdentify = 0xEC;
constexpr uint8_t kCmdRecalib  = 0x10;   /* 0x10..0x1F */
constexpr uint8_t kCmdSeek     = 0x70;
constexpr uint8_t kCmdSetParm  = 0x91;
constexpr uint8_t kCmdIdle     = 0x97;

constexpr uint8_t kHeadLbaBit  = 0x40;   /* ATA_HEAD_LBA_MODE without MUST_BE_ON */

/* Config-option register lives at the CISTPL_CONFIG base below. */
constexpr uint32_t kCorAttrOffset = 0x200u;

/* 16-bit PC Card ATA CIS (FUNCID 4 = fixed disk): COR at attribute 0x200,
   two CFTABLE entries (5.0V / 3.3V), each declaring an I/O interface with
   4 address lines (16-byte task-file window, 8+16-bit). atadisk binds on
   FUNCID 4, picks an entry, and requests that I/O window. */
const uint8_t kCisData[] = {
    0x01, 0x03, 0xDB, 0x00, 0xFF,             /* CISTPL_DEVICE: 250ns, term */
    0x17, 0x03, 0xDB, 0x00, 0xFF,             /* CISTPL_DEVICE_A (attr) */
    /* CISTPL_MANFID 0x0045/0x0401 = "SanDisk CFA" in Linux ide-cs.c's
       id_table. Linux binds its disk driver pre-userspace ONLY on these
       explicit ids (the FUNCID fallback needs a userspace sysfs write,
       ds.c allow_func_id_match) - other ids = unmountable root on CF. */
    0x20, 0x04, 0x45, 0x00, 0x01, 0x04,
    0x21, 0x02, 0x04, 0x00,                   /* CISTPL_FUNCID: fixed disk */
    /* CISTPL_FUNCE type 1 (disk), data 1 (ATA): atadisk's DetectATADisk
       binds the card only when a type-1 FUNCE reports data==1 (ATA). */
    0x22, 0x02, 0x01, 0x01,
    0x1A, 0x05, 0x01, 0x03, 0x00, 0x02, 0x01, /* CISTPL_CONFIG: COR @ 0x200,
                                                  last config index 3 */
    /* CFTABLE 0 memory, 1 generic I/O, 2 primary 0x1F0, 3 secondary 0x170.
       Dropping a shape unbinds a CE line: CE5 atadisk binds entry 1; CE3
       binds I/O only at 0x1F0/0x170, falls back to entry 0 on one-I/O-window
       sockets (iPAQ); a missing Vcc descriptor (0x01,0x55) parses as 0V. */
    0x1B, 0x05, 0x80, 0x40, 0x01, 0x01, 0x55,
    0x1B, 0x0B, 0xC1, 0x41, 0x09, 0x01, 0x55,
                0xE4, 0x51, 0x00, 0x07, 0x0E, 0x01,
    0x1B, 0x0D, 0x82, 0x41, 0x09, 0x01, 0x55,
                0xEA, 0x61, 0xF0, 0x01, 0x07, 0xF6, 0x03, 0x01,
    0x1B, 0x0D, 0x83, 0x41, 0x09, 0x01, 0x55,
                0xEA, 0x61, 0x70, 0x01, 0x07, 0x76, 0x03, 0x01,
    0x14, 0x00,                               /* CISTPL_NO_LINK */
    0xFF, 0x00,                               /* CISTPL_END */
};
constexpr std::size_t kCisSize = sizeof(kCisData);

uint64_t FileSizeBytes(std::FILE* f) {
    if (!f) return 0;
    std::fseek(f, 0, SEEK_END);
    const long end = std::ftell(f);
    return end > 0 ? static_cast<uint64_t>(end) : 0;
}

void PutAtaString(uint8_t* dst, const char* s, std::size_t bytes) {
    /* ATA strings are space-padded, byte-swapped within each 16-bit word. */
    for (std::size_t i = 0; i < bytes; ++i) {
        const char c = s[i] ? s[i] : ' ';
        dst[i ^ 1] = static_cast<uint8_t>(c ? c : ' ');
        if (!s[i]) { for (std::size_t j = i; j < bytes; ++j) dst[j ^ 1] = ' '; break; }
    }
}

}  /* namespace */

CompactFlashCard::CompactFlashCard(CerfEmulator& emu, std::wstring image_path)
    : PcmciaCard(emu), image_path_(std::move(image_path)) {
    if (_wfopen_s(&file_, image_path_.c_str(), L"r+b") != 0) file_ = nullptr;
    const uint64_t bytes = FileSizeBytes(file_);
    total_sectors_ = bytes / 512u;
    /* Standard fixed CHS translation; LBA is the primary access path. */
    chs_sectors_ = 63u;
    chs_heads_   = 16u;
}

CompactFlashCard::~CompactFlashCard() {
    if (file_) std::fclose(file_);
}

std::wstring CompactFlashCard::DisplayName() const {
    const std::size_t slash = image_path_.find_last_of(L"\\/");
    const std::wstring name = slash == std::wstring::npos
        ? image_path_ : image_path_.substr(slash + 1);
    return L"CompactFlash (" + name + L")";
}

std::wstring CompactFlashCard::TooltipDetail() const {
    if (!file_) return DisplayName() + L" - image not found";
    return DisplayName() + L" - " +
           std::to_wstring(total_sectors_ / 2048u) + L" MB";
}

void CompactFlashCard::PowerOn() {
    std::lock_guard<std::mutex> lk(mtx_);
    sectors_left_ = 0;
    buf_pos_      = 0;
    writing_      = false;
    drv_head_     = 0xA0;
    error_        = 0x01;                 /* diagnostic passed */
    status_       = file_ ? (kStReady | kStSeek) : 0;
    irq_line_     = false;
}

void CompactFlashCard::PowerOff() {
    std::lock_guard<std::mutex> lk(mtx_);
    IrqClearLocked();
    status_ = 0;
    sectors_left_ = 0;
    writing_ = false;
}

uint8_t CompactFlashCard::ReadAttribute8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (offset == kCorAttrOffset) return cor_;
    /* CIS is 8-bit but the card is read 16-bit: each ROM byte images on two
       consecutive even attribute addresses (offset/2), as for RTL8019. */
    if (offset < kCisSize * 2u) return kCisData[offset / 2u];
    return 0u;
}

void CompactFlashCard::WriteAttribute8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (offset == kCorAttrOffset) cor_ = value;
}

int CompactFlashCard::DecodeCommonLocked(uint32_t offset) const {
    if ((cor_ & 0x3Fu) != 0u || (offset > 7u && offset != kRegDevCtl)) {
        return -1;
    }
    return static_cast<int>(offset);
}

uint8_t CompactFlashCard::ReadCommon8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadRegLocked(DecodeCommonLocked(offset));
}

uint16_t CompactFlashCard::ReadCommon16(uint32_t offset) {
    std::lock_guard<std::mutex> lk(mtx_);
    const int reg = DecodeCommonLocked(offset);
    if (reg == kRegData) return ReadData16Locked();
    return static_cast<uint16_t>(ReadRegLocked(reg));
}

void CompactFlashCard::WriteCommon8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    WriteRegLocked(DecodeCommonLocked(offset), value);
}

void CompactFlashCard::WriteCommon16(uint32_t offset, uint16_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    const int reg = DecodeCommonLocked(offset);
    if (reg == kRegData) WriteData16Locked(value);
    else WriteRegLocked(reg, static_cast<uint8_t>(value & 0xFFu));
}

/* INTRQ per QEMU hw/ide/core.c v8.2.0: raise on each read/IDENTIFY DRQ
   block (789-790, 1747-48), each COMPLETED write sector - never the first
   write DRQ (1024) - and non-data/abort completion (1212-23). nIEN
   (DevCtl bit1) gates (2800-05); only Status read (2287) or Command
   write (1343) drop the line, alternate status does not. */
void CompactFlashCard::IrqAssertLocked() {
    if (dev_ctrl_ & 0x02u) return;
    if (!irq_line_ && slot_) {
        irq_line_ = true;
        slot_->RaiseIrq();
    }
}

void CompactFlashCard::IrqClearLocked() {
    if (irq_line_ && slot_) {
        irq_line_ = false;
        slot_->ClearIrq();
    }
}

uint64_t CompactFlashCard::CurrentLbaLocked() const {
    if (drv_head_ & kHeadLbaBit) {
        return (static_cast<uint64_t>(drv_head_ & 0x0Fu) << 24) |
               (static_cast<uint64_t>(cyl_high_) << 16) |
               (static_cast<uint64_t>(cyl_low_)  << 8)  |
                static_cast<uint64_t>(sect_num_);
    }
    const uint32_t cyl  = (static_cast<uint32_t>(cyl_high_) << 8) | cyl_low_;
    const uint32_t head = drv_head_ & 0x0Fu;
    const uint32_t sec  = sect_num_;
    return (static_cast<uint64_t>(cyl) * chs_heads_ + head) * chs_sectors_ +
           (sec ? sec - 1u : 0u);
}

void CompactFlashCard::AdvanceSectorLocked() {
    /* Reflect the next LBA into the task-file registers, as a real drive
       does, so the OS reads back a consistent address after a transfer. */
    uint64_t lba = CurrentLbaLocked() + 1u;
    if (drv_head_ & kHeadLbaBit) {
        sect_num_ = static_cast<uint8_t>(lba & 0xFFu);
        cyl_low_  = static_cast<uint8_t>((lba >> 8) & 0xFFu);
        cyl_high_ = static_cast<uint8_t>((lba >> 16) & 0xFFu);
        drv_head_ = static_cast<uint8_t>((drv_head_ & 0xF0u) |
                                         ((lba >> 24) & 0x0Fu));
    } else {
        const uint32_t spt = chs_sectors_ ? chs_sectors_ : 63u;
        const uint32_t hpc = chs_heads_ ? chs_heads_ : 16u;
        uint32_t sec  = static_cast<uint32_t>(lba % spt) + 1u;
        uint32_t rest = static_cast<uint32_t>(lba / spt);
        uint32_t head = rest % hpc;
        uint32_t cyl  = rest / hpc;
        sect_num_ = static_cast<uint8_t>(sec);
        cyl_low_  = static_cast<uint8_t>(cyl & 0xFFu);
        cyl_high_ = static_cast<uint8_t>((cyl >> 8) & 0xFFu);
        drv_head_ = static_cast<uint8_t>((drv_head_ & 0xF0u) | (head & 0x0Fu));
    }
}

bool CompactFlashCard::ReadSectorLocked(uint64_t lba, uint8_t* out) {
    if (!file_ || lba >= total_sectors_) return false;
    if (std::fseek(file_, static_cast<long>(lba * 512u), SEEK_SET) != 0) return false;
    return std::fread(out, 1u, 512u, file_) == 512u;
}

bool CompactFlashCard::WriteSectorLocked(uint64_t lba, const uint8_t* in) {
    if (!file_ || lba >= total_sectors_) return false;
    if (std::fseek(file_, static_cast<long>(lba * 512u), SEEK_SET) != 0) return false;
    const bool ok = std::fwrite(in, 1u, 512u, file_) == 512u;
    std::fflush(file_);
    return ok;
}

void CompactFlashCard::BuildIdentifyLocked() {
    buf_.fill(0);
    uint16_t* w = reinterpret_cast<uint16_t*>(buf_.data());
    const uint32_t cyls = (chs_heads_ && chs_sectors_)
        ? static_cast<uint32_t>(total_sectors_ / (chs_heads_ * chs_sectors_)) : 0;
    w[0]  = 0x848A;                              /* fixed device, removable */
    w[1]  = static_cast<uint16_t>(cyls > 0xFFFFu ? 0xFFFFu : cyls);
    w[3]  = static_cast<uint16_t>(chs_heads_);
    w[6]  = static_cast<uint16_t>(chs_sectors_);
    PutAtaString(reinterpret_cast<uint8_t*>(&w[10]), "CERF00000001", 20); /* serial */
    PutAtaString(reinterpret_cast<uint8_t*>(&w[23]), "1.0", 8);           /* firmware */
    PutAtaString(reinterpret_cast<uint8_t*>(&w[27]), "CERF CompactFlash", 40);
    w[47] = 0x8001;                              /* max sectors/interrupt = 1 */
    w[49] = 0x0200;                              /* LBA supported (bit 9) */
    w[51] = 0x0200;                              /* PIO timing */
    w[53] = 0x0001;                              /* words 54-58 valid */
    w[54] = w[1]; w[55] = w[3]; w[56] = w[6];    /* current CHS */
    const uint32_t cur_cap = (chs_heads_ * chs_sectors_) *
                             (w[1] ? w[1] : 0u);
    w[57] = static_cast<uint16_t>(cur_cap & 0xFFFFu);
    w[58] = static_cast<uint16_t>(cur_cap >> 16);
    const uint32_t lba28 = total_sectors_ > 0x0FFFFFFFu
        ? 0x0FFFFFFFu : static_cast<uint32_t>(total_sectors_);
    w[60] = static_cast<uint16_t>(lba28 & 0xFFFFu);   /* total LBA sectors */
    w[61] = static_cast<uint16_t>(lba28 >> 16);
}

void CompactFlashCard::StartReadLocked() {
    sectors_left_ = sect_cnt_ ? sect_cnt_ : 256u;
    writing_ = false;
    if (ReadSectorLocked(CurrentLbaLocked(), buf_.data())) {
        buf_pos_ = 0;
        status_ = kStReady | kStSeek | kStDrq;
    } else {
        error_ = 0x10;                           /* ID not found */
        status_ = kStReady | kStError;
        sectors_left_ = 0;
    }
    IrqAssertLocked();
}

void CompactFlashCard::StartWriteLocked() {
    sectors_left_ = sect_cnt_ ? sect_cnt_ : 256u;
    writing_ = true;
    buf_pos_ = 0;
    status_ = kStReady | kStSeek | kStDrq;        /* awaiting first data word */
}

void CompactFlashCard::CompleteWriteSectorLocked() {
    if (!WriteSectorLocked(CurrentLbaLocked(), buf_.data())) {
        error_ = 0x10;
        status_ = kStReady | kStError;
        sectors_left_ = 0;
        writing_ = false;
        IrqAssertLocked();
        return;
    }
    if (--sectors_left_ == 0) {
        status_ = kStReady | kStSeek;             /* done, DRQ cleared */
        writing_ = false;
    } else {
        AdvanceSectorLocked();
        buf_pos_ = 0;
        status_ = kStReady | kStSeek | kStDrq;
    }
    IrqAssertLocked();
}

int CompactFlashCard::DecodeIoLocked(uint32_t offset) const {
    const uint8_t idx = cor_ & 0x3Fu;
    if (idx == 2u || idx == 3u) {
        const uint32_t off = offset & 0x3FFu;
        const uint32_t cmd = idx == 2u ? 0x1F0u : 0x170u;
        const uint32_t ctl = idx == 2u ? 0x3F6u : 0x376u;
        if (off >= cmd && off <= cmd + 7u) return static_cast<int>(off - cmd);
        if (off == ctl) return kRegDevCtl;
    } else {
        const uint32_t off = offset & 0x0Fu;
        if (off <= 7u || off == kRegDevCtl) return static_cast<int>(off);
    }
    return -1;
}

uint8_t CompactFlashCard::ReadRegLocked(int reg) {
    switch (reg) {
        case kRegError:    return error_;
        case kRegSectCnt:  return sect_cnt_;
        case kRegSectNum:  return sect_num_;
        case kRegCylLow:   return cyl_low_;
        case kRegCylHigh:  return cyl_high_;
        case kRegDrvHead:  return drv_head_;
        case kRegStatus:   IrqClearLocked(); return status_;
        case kRegDevCtl:   return status_;        /* alternate status */
        case kRegData: {
            if (!(status_ & kStDrq)) return 0xFFu;
            const uint8_t v = buf_[buf_pos_];
            if (++buf_pos_ >= 512u) {
                if (--sectors_left_ == 0) {
                    status_ = kStReady | kStSeek;
                } else {
                    AdvanceSectorLocked();
                    if (ReadSectorLocked(CurrentLbaLocked(), buf_.data())) {
                        buf_pos_ = 0;
                    } else {
                        error_ = 0x10;
                        status_ = kStReady | kStError;
                        sectors_left_ = 0;
                    }
                    IrqAssertLocked();
                }
            }
            return v;
        }
        default:           return 0xFFu;
    }
}

uint16_t CompactFlashCard::ReadData16Locked() {
    if (!(status_ & kStDrq)) return 0xFFFFu;
    const uint16_t v = cerf::le::U16(buf_.data(), buf_pos_);
    buf_pos_ += 2u;
    if (buf_pos_ >= 512u) {
        if (--sectors_left_ == 0) {
            status_ = kStReady | kStSeek;
        } else {
            AdvanceSectorLocked();
            if (ReadSectorLocked(CurrentLbaLocked(), buf_.data())) {
                buf_pos_ = 0;
            } else {
                error_ = 0x10;
                status_ = kStReady | kStError;
                sectors_left_ = 0;
            }
            IrqAssertLocked();
        }
    }
    return v;
}

uint8_t CompactFlashCard::ReadIo8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadRegLocked(DecodeIoLocked(offset));
}

uint16_t CompactFlashCard::ReadIo16(uint32_t offset) {
    std::lock_guard<std::mutex> lk(mtx_);
    const int reg = DecodeIoLocked(offset);
    if (reg == kRegData) return ReadData16Locked();
    return static_cast<uint16_t>(ReadRegLocked(reg));
}

void CompactFlashCard::WriteRegLocked(int reg, uint8_t value) {
    switch (reg) {
        case kRegFeature:  feature_  = value; return;
        case kRegSectCnt:  sect_cnt_ = value; return;
        case kRegSectNum:  sect_num_ = value; return;
        case kRegCylLow:   cyl_low_  = value; return;
        case kRegCylHigh:  cyl_high_ = value; return;
        case kRegDrvHead:  drv_head_ = value; return;
        case kRegDevCtl:   dev_ctrl_ = value; return;
        case kRegData:     WriteData8Locked(value); return;   /* 8-bit PIO data */
        case kRegCommand: {
            IrqClearLocked();
            error_ = 0;
            if (value == kCmdIdentify) {
                BuildIdentifyLocked();
                buf_pos_ = 0;
                sectors_left_ = 1u;
                status_ = kStReady | kStSeek | kStDrq;
                IrqAssertLocked();
            } else if (value == kCmdRead) {
                StartReadLocked();
            } else if (value == kCmdWrite) {
                StartWriteLocked();
            } else if ((value & 0xF0u) == kCmdRecalib || value == kCmdSeek ||
                       value == kCmdSetParm || value == kCmdIdle) {
                status_ = kStReady | kStSeek;           /* no-op, succeeds */
                IrqAssertLocked();
            } else {
                error_ = 0x04;                          /* ABORTED */
                status_ = kStReady | kStError;
                IrqAssertLocked();
            }
            return;
        }
        default:           return;
    }
}

void CompactFlashCard::WriteData16Locked(uint16_t value) {
    if (!writing_ || !(status_ & kStDrq)) return;
    cerf::le::Put16(buf_.data() + buf_pos_, value);
    buf_pos_ += 2u;
    if (buf_pos_ >= 512u) CompleteWriteSectorLocked();
}

void CompactFlashCard::WriteData8Locked(uint8_t value) {
    if (!writing_ || !(status_ & kStDrq)) return;
    buf_[buf_pos_] = value;
    if (++buf_pos_ >= 512u) CompleteWriteSectorLocked();
}

void CompactFlashCard::WriteIo8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    WriteRegLocked(DecodeIoLocked(offset), value);
}

/* file_/image_path_/total_sectors_ are the host-file binding (the disk
   content persists on disk); the ATA task-file + PIO buffer is card state. */
void CompactFlashCard::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write(feature_); w.Write(error_); w.Write(sect_cnt_); w.Write(sect_num_);
    w.Write(cyl_low_); w.Write(cyl_high_); w.Write(drv_head_); w.Write(status_);
    w.Write(dev_ctrl_); w.Write(chs_heads_); w.Write(chs_sectors_);
    w.WriteBytes(buf_.data(), buf_.size());
    w.Write(buf_pos_); w.Write(sectors_left_);
    w.Write<uint8_t>(writing_ ? 1u : 0u);
    w.Write(cor_);
    w.Write<uint8_t>(irq_line_ ? 1u : 0u);
}

void CompactFlashCard::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read(feature_); r.Read(error_); r.Read(sect_cnt_); r.Read(sect_num_);
    r.Read(cyl_low_); r.Read(cyl_high_); r.Read(drv_head_); r.Read(status_);
    r.Read(dev_ctrl_); r.Read(chs_heads_); r.Read(chs_sectors_);
    r.ReadBytes(buf_.data(), buf_.size());
    r.Read(buf_pos_); r.Read(sectors_left_);
    uint8_t wr = 0; r.Read(wr); writing_ = (wr != 0);
    r.Read(cor_);
    uint8_t irq = 0; r.Read(irq); irq_line_ = (irq != 0);
}

/* IrqAssertLocked short-circuits on an already-set irq_line_, so the restored level is
   driven onto the socket directly. */
void CompactFlashCard::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (irq_line_) slot_->RaiseIrq();
    else           slot_->ClearIrq();
}

void CompactFlashCard::WriteIo16(uint32_t offset, uint16_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    const int reg = DecodeIoLocked(offset);
    if (reg == kRegData) WriteData16Locked(value);
    else WriteRegLocked(reg, static_cast<uint8_t>(value & 0xFFu));
}
