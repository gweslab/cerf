#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

constexpr uint32_t kBase    = 0x4E000000u;
constexpr uint32_t kRegSize = 0x00100000u; /* covers the full 1 MB OAT section */

constexpr uint32_t kOfsNFCONF = 0x00u;
constexpr uint32_t kOfsNFCMD  = 0x04u;
constexpr uint32_t kOfsNFADDR = 0x08u;
constexpr uint32_t kOfsNFDATA = 0x0Cu;
constexpr uint32_t kOfsNFSTAT = 0x10u;

constexpr uint32_t kBytesPerSector  = 520u;
constexpr uint32_t kSectorsPerBlock = 32u;
constexpr uint32_t kBlockCount      = 4096u;
constexpr uint32_t kSectorsTotal    = kSectorsPerBlock * kBlockCount;
constexpr size_t   kFlashBytes      = (size_t)kBytesPerSector * kSectorsTotal;
constexpr uint32_t kOobOffset       = 512u;
constexpr uint32_t kBlockBytes      = kSectorsPerBlock * kBytesPerSector;

/* Samsung K9F1208 chip ID — manufacturer 0xEC, device 0x76 — returned
   in 2 bytes on CMD_READID (NFCMD = 0x90 then two NFDATA reads).
   FMD_Init at references/.../SMARTMEDIA/FMD/fmd.cpp tests
   ((Mfg << 8) | Dev) == 0xEC76 and bails out otherwise. */
constexpr uint8_t kChipIdMfg = 0xECu;
constexpr uint8_t kChipIdDev = 0x76u;

/* Command opcodes per references/.../SMARTMEDIA/FMD/nand.h. */
constexpr uint8_t kCmdRead   = 0x00u;
constexpr uint8_t kCmdWrite2 = 0x10u;
constexpr uint8_t kCmdRead2  = 0x50u;
constexpr uint8_t kCmdErase  = 0x60u;
constexpr uint8_t kCmdStatus = 0x70u; /* CE6 only */
constexpr uint8_t kCmdWrite  = 0x80u;
constexpr uint8_t kCmdReadid = 0x90u;
constexpr uint8_t kCmdErase2 = 0xD0u;
constexpr uint8_t kCmdReset  = 0xFFu;

class S3C2410NandFlash : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }
    void OnReady() override {
        flash_.assign(kFlashBytes, 0xFFu);
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(SocNand, "init: %zu bytes (%u blocks x %u sectors x %u bytes), 0xFF-filled\n",
            kFlashBytes, kBlockCount, kSectorsPerBlock, kBytesPerSector);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kRegSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t nfconf_ = 0;
    uint8_t  nfcmd_  = 0;
    uint32_t nfaddr_ = 0;

    /* NFSTAT bit 0 = ready. We never simulate busy — commands
       complete instantly — so bit 0 is always set. FMD's NF_WAITRB
       polls this in a tight loop until it sees 1. */
    uint32_t nfstat_ = 1u;

    /* Cursor for sequential NFDATA reads/writes within the active
       command. Reset to 0 on every NFCMD write; READ2 / WRITE-after-
       READ2 seek it to kOobOffset. */
    uint32_t bytes_read_ = 0;

    std::vector<uint8_t> flash_;
};

void S3C2410NandFlash::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t ofs = addr - MmioBase();
    if (ofs == kOfsNFCONF) {
        nfconf_ = value;
        LOG(SocNand, "write NFCONF = 0x%08X\n", value);
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void S3C2410NandFlash::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t ofs = addr - MmioBase();

    if (ofs == kOfsNFCMD) {
        const uint8_t prev_cmd = nfcmd_;
        bytes_read_ = 0;
        nfcmd_      = value;

        switch (value) {
        case kCmdReset:
            nfaddr_ = 0;
            break;
        case kCmdReadid:
            /* No address-cycle setup; READID returns chip ID directly. */
            break;
        case kCmdRead:
            /* 4-cycle address follows. */
            nfaddr_ = 0;
            break;
        case kCmdRead2:
            /* Seek to OOB area within the addressed page. */
            bytes_read_ = kOobOffset;
            break;
        case kCmdErase:
            /* 3-cycle page-row address follows. */
            nfaddr_ = 0;
            break;
        case kCmdErase2: {
            const uint32_t page_index  = nfaddr_ >> 8;
            const uint32_t block_index = page_index / kSectorsPerBlock;
            if (block_index < kBlockCount) {
                const size_t off = (size_t)block_index * kBlockBytes;
                std::memset(flash_.data() + off, 0xFFu, kBlockBytes);
            }
            LOG(SocNand, "ERASE2 page=%u block=%u\n",
                page_index, block_index);
            break;
        }
        case kCmdWrite:
            if (prev_cmd == kCmdRead2) {
                bytes_read_ = kOobOffset;
            }
            nfaddr_ = 0;
            break;
        case kCmdWrite2:
            /* Phase-2 confirm — next NFDATA read returns success. */
            break;
        case kCmdStatus:
            /* CE6-only opcode. Next NFDATA read returns status byte. */
            break;
        default:
            HaltUnsupportedAccess("WriteByte NFCMD opcode", addr, value);
        }

        /* Commands complete instantly — leave the ready bit set. */
        nfstat_ |= 1u;
        LOG(SocNand, "write NFCMD = 0x%02X\n", value);
        return;
    }

    if (ofs == kOfsNFADDR) {
        nfaddr_ = (nfaddr_ >> 8) | ((uint32_t)value << 24);
        return;
    }

    if (ofs == kOfsNFDATA) {
        /* Page-data byte write — only valid during CMD_WRITE. The
           driver writes 512 data bytes + 8 OOB bytes = 520 bytes
           sequentially through NFDATA after loading the 4-cycle
           address. */
        if (nfcmd_ != kCmdWrite) {
            HaltUnsupportedAccess("WriteByte NFDATA without WRITE",
                                  addr, value);
        }
        const uint32_t page_index = nfaddr_ >> 8;
        if (page_index >= kSectorsTotal || bytes_read_ >= kBytesPerSector) {
            HaltUnsupportedAccess("WriteByte NFDATA out of range",
                                  addr, value);
        }
        const size_t off = (size_t)page_index * kBytesPerSector + bytes_read_;
        flash_[off] = value;
        ++bytes_read_;
        return;
    }

    HaltUnsupportedAccess("WriteByte", addr, value);
}

uint32_t S3C2410NandFlash::ReadWord(uint32_t addr) {
    const uint32_t ofs = addr - MmioBase();
    if (ofs == kOfsNFCONF) {
        return nfconf_;
    }
    if (ofs == kOfsNFSTAT) {
        return nfstat_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

uint8_t S3C2410NandFlash::ReadByte(uint32_t addr) {
    const uint32_t ofs = addr - MmioBase();
    if (ofs != kOfsNFDATA) {
        HaltUnsupportedAccess("ReadByte", addr, 0);
    }

    switch (nfcmd_) {
    case kCmdReadid: {
        const uint8_t v = (bytes_read_ == 0) ? kChipIdMfg : kChipIdDev;
        ++bytes_read_;
        return v;
    }
    case kCmdRead: {
        const uint32_t page_index = nfaddr_ >> 8;
        if (page_index >= kSectorsTotal || bytes_read_ >= kBytesPerSector) {
            HaltUnsupportedAccess("ReadByte NFDATA CMD_READ out of range",
                                  addr, 0);
        }
        const size_t off = (size_t)page_index * kBytesPerSector + bytes_read_;
        ++bytes_read_;
        return flash_[off];
    }
    case kCmdRead2: {
        const uint32_t page_index = nfaddr_ >> 8;
        if (page_index >= kSectorsTotal) {
            return 0x00u;
        }
        if (bytes_read_ >= kBytesPerSector) {
            return 0x01u;
        }
        const size_t off = (size_t)page_index * kBytesPerSector + bytes_read_;
        ++bytes_read_;
        return flash_[off];
    }
    case kCmdStatus:
        return 0xC0u;
    case kCmdErase2:
    case kCmdWrite2:
        /* CE5 path: driver reads NFDATA directly after ERASE2 /
           WRITE2 (without sending CMD_STATUS). Bit 0 = 0 → success. */
        return 0x00u;
    default:
        HaltUnsupportedAccess("ReadByte NFDATA in unknown CMD", addr, 0);
    }
}

}  /* namespace */

REGISTER_SERVICE(S3C2410NandFlash);
