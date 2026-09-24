#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* S3C2410A UM pp. 6-6..6-8 "SPECIAL FUNCTION REGISTERS": NFCONF at 0x4E000000,
   NFCMD 0x4E000004, NFADDR 0x4E000008, NFDATA 0x4E00000C, NFSTAT 0x4E000010,
   NFECC 0x4E000014. */
constexpr uint32_t kBase = 0x4E000000u;
constexpr uint32_t kSpan = 0x18u;

constexpr uint32_t kOffConf = 0x00u;
constexpr uint32_t kOffCmd  = 0x04u;
constexpr uint32_t kOffAddr = 0x08u;
constexpr uint32_t kOffData = 0x0Cu;
constexpr uint32_t kOffStat = 0x10u;

/* UM p. 6-6 NFCONF: [15] NAND flash controller enable, [12] initialize ECC,
   [11] nFCE (0 = L active), [10:8] TACLS, [6:4] TWRPH0, [2:0] TWRPH1;
   [14:13], [7] and [3] Reserved. */
constexpr uint32_t kConfWritable = 0x00009F77u;

/* UM p. 6-8 NFSTAT: [0] RnB, "1 = NAND flash memory ready to operate". */
constexpr uint32_t kStatReady = 1u << 0;

/* Linux 2.6.25 include/linux/mtd/nand.h:71-83, the legacy command set. */
constexpr uint32_t kNoCommand = 0x100u;

constexpr uint8_t kCmdRead0   = 0x00u;
constexpr uint8_t kCmdRead1   = 0x01u;
constexpr uint8_t kCmdReadOob = 0x50u;
constexpr uint8_t kCmdReadId  = 0x90u;
constexpr uint8_t kCmdReset   = 0xFFu;

/* Linux 2.6.25 drivers/mtd/nand/nand_ids.c:57 gives device code 0x76 as the
   64 MiB 3.3 V 8-bit part with a 512-byte page and a 0x4000 erase block;
   nand.h:428 and nand_ids.c:137 give maker code 0xEC, Samsung. */
constexpr uint8_t  kMakerCode  = 0xECu;
constexpr uint8_t  kDeviceCode = 0x76u;
constexpr uint32_t kPageData   = 512u;
constexpr uint32_t kPageSpare  = 16u;
constexpr uint32_t kPageBytes  = kPageData + kPageSpare;
constexpr uint32_t kPageCount  = (64u * 1024u * 1024u) / kPageData;

/* Linux 2.6.25 drivers/mtd/nand/nand_base.c nand_command(). */
constexpr uint32_t kColumnBaseRead0   = 0u;
constexpr uint32_t kColumnBaseRead1   = 256u;
constexpr uint32_t kColumnBaseReadOob = kPageData;
constexpr uint32_t kAddressCycles     = 4u;

/* Linux 2.6.25 drivers/mtd/nand/nand_base.c nand_block_bad(). */
constexpr uint8_t kErasedByte = 0xFFu;

class S3C2410NandFlash : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSpan; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override {
        w.Write<uint32_t>("conf", conf_);
        w.Write<uint32_t>("command", command_);
        w.Write<uint32_t>("id_index", id_index_);
        w.Write<uint32_t>("addr_cycle", addr_cycle_);
        w.Write<uint32_t>("column_base", column_base_);
        w.Write<uint32_t>("column", column_);
        w.Write<uint32_t>("page", page_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("conf", conf_);
        r.Read("command", command_);
        r.Read("id_index", id_index_);
        r.Read("addr_cycle", addr_cycle_);
        r.Read("column_base", column_base_);
        r.Read("column", column_);
        r.Read("page", page_);
    }

private:
    bool IsReadCommand() const {
        return command_ == kCmdRead0 || command_ == kCmdRead1 ||
               command_ == kCmdReadOob;
    }

    uint32_t conf_        = 0;
    uint32_t command_     = kNoCommand;
    uint32_t id_index_    = 0;
    uint32_t addr_cycle_  = 0;
    uint32_t column_base_ = 0;
    uint32_t column_      = 0;
    uint32_t page_        = 0;
};

void S3C2410NandFlash::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    if (off != kOffConf)
        HaltUnsupportedAccess("WriteWord", addr, value);
    conf_ = value & kConfWritable;
}

uint32_t S3C2410NandFlash::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    switch (off) {
        case kOffConf: return conf_;
        case kOffStat: return kStatReady;
        default:
            HaltUnsupportedAccess("ReadWord", addr, 0);
    }
}

void S3C2410NandFlash::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (off == kOffCmd) {
        switch (value) {
            case kCmdReset:
            case kCmdReadId:                                        break;
            case kCmdRead0:   column_base_ = kColumnBaseRead0;      break;
            case kCmdRead1:   column_base_ = kColumnBaseRead1;      break;
            case kCmdReadOob: column_base_ = kColumnBaseReadOob;    break;
            default:
                emu_.Get<Fatal>().Die(
                    "S3C2410 NAND: unimplemented command 0x%02X written to NFCMD",
                    value);
        }
        command_    = value;
        id_index_   = 0;
        addr_cycle_ = 0;
        column_     = 0;
        page_       = 0;
        return;
    }
    if (off == kOffAddr) {
        if (command_ == kCmdReadId) {
            if (value != 0x00u)
                emu_.Get<Fatal>().Die(
                    "S3C2410 NAND: READ ID address 0x%02X is unimplemented", value);
            return;
        }
        if (!IsReadCommand())
            emu_.Get<Fatal>().Die(
                "S3C2410 NAND: address cycle under unimplemented command 0x%02X",
                command_);
        switch (addr_cycle_++) {
            case 0: column_ = value;                             break;
            case 1: page_   = value;                             break;
            case 2: page_  |= static_cast<uint32_t>(value) << 8;  break;
            case 3: page_  |= static_cast<uint32_t>(value) << 16; break;
            default:
                emu_.Get<Fatal>().Die(
                    "S3C2410 NAND: address cycle %u past the %u this part takes",
                    addr_cycle_ - 1u, kAddressCycles);
        }
        if (addr_cycle_ == kAddressCycles && page_ >= kPageCount)
            emu_.Get<Fatal>().Die(
                "S3C2410 NAND: page %u past the %u-page device", page_, kPageCount);
        return;
    }
    HaltUnsupportedAccess("WriteByte", addr, value);
}

uint8_t S3C2410NandFlash::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (off != kOffData)
        HaltUnsupportedAccess("ReadByte", addr, 0);
    if (command_ == kCmdReadId) {
        switch (id_index_++) {
            case 0: return kMakerCode;
            case 1: return kDeviceCode;
            default:
                emu_.Get<Fatal>().Die(
                    "S3C2410 NAND: READ ID byte %u is unimplemented",
                    id_index_ - 1u);
        }
    }
    if (!IsReadCommand())
        emu_.Get<Fatal>().Die(
            "S3C2410 NAND: NFDATA read under unimplemented command 0x%02X",
            command_);
    if (addr_cycle_ != kAddressCycles)
        emu_.Get<Fatal>().Die(
            "S3C2410 NAND: NFDATA read after %u of %u address cycles",
            addr_cycle_, kAddressCycles);
    const uint32_t offset = column_base_ + column_;
    if (offset >= kPageBytes)
        emu_.Get<Fatal>().Die(
            "S3C2410 NAND: read at offset %u past the %u-byte page",
            offset, kPageBytes);
    ++column_;
    return kErasedByte;
}

}  /* namespace */

REGISTER_SERVICE(S3C2410NandFlash);
