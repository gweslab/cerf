#include "../peripheral_base.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/falcon_pc3xx/falcon_4220_id.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "msystems_docg3_base.h"

#include <cstdint>
#include <cstring>
#include <vector>

/* M-Systems DiskOnChip G3 NAND controller (register/command map from the Linux
   mtd docg3 driver). The Falcon OAL probe (nk.exe sub_800F3FFC) sets READADDRESS
   to 0x1000 then reads CHIPID, accepting 0x200 (DOC_CHIPID_G3); that read gates
   DOC detection and the whole TrueFFS config, so CHIPID must read 0x200. */

namespace {

constexpr uint32_t kIoSpaceData = 0x0800u;   /* DOC_IOSPACE_DATA */
constexpr uint32_t kIoSpaceIpl  = 0x0000u;   /* DOC_IOSPACE_IPL  */
constexpr uint32_t kWindowSize  = 0x2000u;   /* DOC_IOSPACE_SIZE */

/* Registers (docg3.h). */
constexpr uint32_t kRegChipId         = 0x1000u;
constexpr uint32_t kRegTest           = 0x1004u;
constexpr uint32_t kRegBuslock        = 0x1006u;
constexpr uint32_t kRegEndianControl  = 0x1008u;
constexpr uint32_t kRegDeviceSelect   = 0x100Au;
constexpr uint32_t kRegAsicMode       = 0x100Cu;
constexpr uint32_t kRegConfiguration  = 0x100Eu;
constexpr uint32_t kRegReadAddress    = 0x101Au;
constexpr uint32_t kRegFlashSequence  = 0x1032u;
constexpr uint32_t kRegFlashCommand   = 0x1034u;
constexpr uint32_t kRegFlashAddress   = 0x1036u;
constexpr uint32_t kRegFlashControl   = 0x1038u;
constexpr uint32_t kRegNop            = 0x103Eu;
constexpr uint32_t kRegEccConf0       = 0x1040u;
constexpr uint32_t kRegEccConf1       = 0x1042u;
constexpr uint32_t kRegAsicModeConfirm= 0x1072u;
constexpr uint32_t kRegChipIdInv      = 0x1074u;
constexpr uint32_t kRegPowerMode      = 0x107Cu;

constexpr uint16_t kChipIdG3 = 0x0200u;   /* DOC_CHIPID_G3; OAL reads CHIPID == 0x200 */

/* DOC_FLASHCONTROL bits (docg3.h). */
constexpr uint8_t kCtrlCe          = 0x10u;
constexpr uint8_t kCtrlFlashReady  = 0x01u;

/* DOC_ECCCONF1: BCH syndrome-error bit. Emulated flash never bit-flips, so this
   bit stays clear and the driver's ECC path finds nothing to correct. */
constexpr uint8_t kEccConf1SyndromeErr = 0x80u;

/* Flash command opcodes (docg3.h) the address/data engine reacts to. */
constexpr uint8_t kCmdReset        = 0xFFu;
constexpr uint8_t kCmdReadPlane1   = 0x00u;
constexpr uint8_t kCmdReadPlane2   = 0x50u;
constexpr uint8_t kCmdReadAllPlanes= 0x30u;
constexpr uint8_t kCmdProgBlockAddr= 0x60u;
constexpr uint8_t kCmdProgCycle1   = 0x80u;
constexpr uint8_t kCmdProgCycle3   = 0x11u;
constexpr uint8_t kCmdEraseCycle2  = 0xD0u;

/* Page geometry (docg3.h). A physical page is 512 data + 16 OOB; the controller
   stores them contiguously per page. 64 pages per block, 2 planes. */
constexpr uint32_t kPageData      = 512u;
constexpr uint32_t kOobSize       = 16u;
constexpr uint32_t kPageStored    = kPageData + kOobSize;   /* 528 */
constexpr uint32_t kPagesPerBlock = 64u;
constexpr uint32_t kAddrPageMask  = 0x3Fu;                  /* DOC_ADDR_PAGE_MASK */
constexpr uint32_t kAddrBlockShift= 6u;                     /* DOC_ADDR_BLOCK_SHIFT */

class MsystemsDocG3 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        /* Off-chip part: register on each board that wires it. The matching
           board supplies its base via MsystemsDocG3Base. */
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Falcon4220;
    }

    void OnReady() override {
        auto& cfg = emu_.Get<MsystemsDocG3Base>();
        base_       = cfg.WindowPa();
        block_count_= cfg.BlockCount();
        nand_.assign(static_cast<size_t>(block_count_) * kPagesPerBlock * kPageStored,
                     0xFFu);
        cfg.LoadInto(nand_.data(), nand_.size());
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(SocNand, "[DOCG3] init: base=0x%08X, %u blocks x %u pages x %u bytes\n",
            base_, block_count_, kPagesPerBlock, kPageStored);
    }

    uint32_t MmioBase() const override { return base_; }
    uint32_t MmioSize() const override { return kWindowSize; }

    uint8_t  ReadByte (uint32_t addr) override {
        return static_cast<uint8_t>(ReadReg(addr - base_, false));
    }
    uint16_t ReadHalf (uint32_t addr) override { return ReadReg(addr - base_, true); }
    void     WriteByte(uint32_t addr, uint8_t  v) override { WriteReg(addr - base_, v); }
    void     WriteHalf(uint32_t addr, uint16_t v) override { WriteReg(addr - base_, v); }

private:
    /* The data window auto-increments a cursor over the addressed page's stored
       bytes; register reads return latched state. `first` data reads arrive via
       a DOC_READADDRESS write of 0x0800, which arms data_cursor_. */
    uint16_t ReadReg(uint32_t off, bool wide) {
#if CERF_DEV_MODE
        if (dbg_accesses_ < 80) {
            ++dbg_accesses_;
            LOG(SocNand, "[DOCG3] RD off=0x%04X wide=%d\n", off, wide ? 1 : 0);
        }
#endif
        if (off >= kIoSpaceData && off < kIoSpaceData + kPageData) {
            const uint8_t lo = NextDataByte();
            if (!wide) return lo;
            const uint8_t hi = NextDataByte();
            return static_cast<uint16_t>(lo | (hi << 8));
        }
        if (off >= kIoSpaceIpl && off < kIoSpaceIpl + 0x800u) {
            /* IPL pre-read: doc_set_asic_mode reads 12 IPL bytes as a warmup. */
            return 0xFFu;
        }
        switch (off) {
            case kRegChipId:          return kChipIdG3;
            case kRegChipIdInv:       return static_cast<uint16_t>(~kChipIdG3);
            case kRegTest:            return test_reg_;
            case kRegConfiguration:   return config_reg_;
            case kRegFlashControl:    return flash_control_ | kCtrlFlashReady;
            case kRegEccConf1:        return ecc_conf1_ & ~kEccConf1SyndromeErr;
            case kRegDeviceSelect:    return device_select_;
            case kRegPowerMode:       return 0x80u;   /* DOC_POWERDOWN_READY */
            default:                  return 0u;
        }
    }

    void WriteReg(uint32_t off, uint16_t v) {
#if CERF_DEV_MODE
        if (dbg_accesses_ < 80) {
            ++dbg_accesses_;
            LOG(SocNand, "[DOCG3] WR off=0x%04X v=0x%04X\n", off, v);
        }
#endif
        if (off >= kIoSpaceData && off < kIoSpaceData + kPageData) {
            StoreDataByte(static_cast<uint8_t>(v));
            if (data_wide_pending_) StoreDataByte(static_cast<uint8_t>(v >> 8));
            return;
        }
        switch (off) {
            case kRegReadAddress:
                /* Arms sequential data access when pointed at the data window. */
                read_address_ = v;
                if ((v & 0x1FFFu) == kIoSpaceData) { data_cursor_ = data_base_; }
                return;
            case kRegFlashSequence:   flash_sequence_ = static_cast<uint8_t>(v); return;
            case kRegFlashCommand:    HandleCommand(static_cast<uint8_t>(v));     return;
            case kRegFlashAddress:    PushAddress(static_cast<uint8_t>(v));       return;
            case kRegFlashControl:    flash_control_ = static_cast<uint8_t>(v) & ~kCtrlFlashReady; return;
            case kRegTest:            test_reg_      = static_cast<uint8_t>(v); return;
            case kRegConfiguration:   config_reg_    = static_cast<uint8_t>(v); return;
            case kRegDeviceSelect:    device_select_ = static_cast<uint8_t>(v); return;
            case kRegAsicMode:        asic_mode_     = static_cast<uint8_t>(v); return;
            case kRegEccConf0:        ecc_conf0_     = v;                       return;
            case kRegEccConf1:        ecc_conf1_     = static_cast<uint8_t>(v); return;
            case kRegNop: case kRegBuslock: case kRegEndianControl:
            case kRegAsicModeConfirm: case kRegPowerMode:
                return;
            default:
                return;
        }
    }

    /* Address bytes accumulate LSB-first; the command that consumes them
       (READ_ALL_PLANES / ERASE / PROG) latches the resulting page. */
    void PushAddress(uint8_t a) {
        if (addr_len_ < 4) addr_bytes_[addr_len_] = a;
        ++addr_len_;
    }

    uint32_t LatchedSector() const {
        return cerf::le::U24(addr_bytes_);
    }

    void HandleCommand(uint8_t cmd) {
        flash_command_ = cmd;
        switch (cmd) {
            case kCmdReset:
                addr_len_ = 0;
                break;
            case kCmdProgBlockAddr:
            case kCmdProgCycle1:
                addr_len_ = 0;          /* address cycles follow */
                break;
            case kCmdReadAllPlanes:
            case kCmdProgCycle3:
                SeekToLatchedPage();    /* arms data_base_ for the page */
                addr_len_ = 0;
                break;
            case kCmdEraseCycle2:
                EraseLatchedBlock();
                addr_len_ = 0;
                break;
            default:
                break;
        }
    }

    void SeekToLatchedPage() {
        const uint32_t sector = LatchedSector();
        const uint32_t block  = sector >> kAddrBlockShift;
        const uint32_t page   = sector & kAddrPageMask;
        if (block >= block_count_) { data_base_ = nand_.size(); data_cursor_ = data_base_; return; }
        data_base_   = (static_cast<size_t>(block) * kPagesPerBlock + page) * kPageStored;
        data_cursor_ = data_base_;
        data_wide_pending_ = true;
    }

    void EraseLatchedBlock() {
        const uint32_t block = LatchedSector() >> kAddrBlockShift;
        if (block >= block_count_) return;
        const size_t off = static_cast<size_t>(block) * kPagesPerBlock * kPageStored;
        std::memset(nand_.data() + off, 0xFFu, kPagesPerBlock * kPageStored);
    }

    uint8_t NextDataByte() {
        if (data_cursor_ >= nand_.size()) return 0xFFu;
        return nand_[data_cursor_++];
    }
    void StoreDataByte(uint8_t v) {
        if (data_cursor_ < nand_.size()) nand_[data_cursor_++] = v;
    }

    void SaveState(StateWriter& w) override {
        w.Write(base_);
        w.Write(block_count_);
        w.Write<uint64_t>(nand_.size());
        if (!nand_.empty()) w.WriteBytes(nand_.data(), nand_.size());
        w.Write(read_address_);
        w.Write(flash_sequence_);
        w.Write(flash_command_);
        w.Write(flash_control_);
        w.Write(test_reg_);
        w.Write(config_reg_);
        w.Write(device_select_);
        w.Write(asic_mode_);
        w.Write(ecc_conf0_);
        w.Write(ecc_conf1_);
        w.WriteBytes(addr_bytes_, sizeof(addr_bytes_));
        w.Write<int32_t>(addr_len_);
        w.Write<uint64_t>(data_base_);
        w.Write<uint64_t>(data_cursor_);
        w.Write<uint8_t>(data_wide_pending_ ? 1u : 0u);
    }
    void RestoreState(StateReader& r) override {
        r.Read(base_);
        r.Read(block_count_);
        uint64_t n = 0;
        r.Read(n);
        nand_.assign(static_cast<size_t>(n), 0u);
        if (n) r.ReadBytes(nand_.data(), static_cast<size_t>(n));
        r.Read(read_address_);
        r.Read(flash_sequence_);
        r.Read(flash_command_);
        r.Read(flash_control_);
        r.Read(test_reg_);
        r.Read(config_reg_);
        r.Read(device_select_);
        r.Read(asic_mode_);
        r.Read(ecc_conf0_);
        r.Read(ecc_conf1_);
        r.ReadBytes(addr_bytes_, sizeof(addr_bytes_));
        int32_t al = 0; r.Read(al); addr_len_ = al;
        uint64_t db = 0, dc = 0;
        r.Read(db); data_base_ = static_cast<size_t>(db);
        r.Read(dc); data_cursor_ = static_cast<size_t>(dc);
        uint8_t wp = 0; r.Read(wp); data_wide_pending_ = (wp != 0);
    }

    uint32_t base_        = 0;
    uint32_t block_count_ = 0;
    std::vector<uint8_t> nand_;

    uint16_t read_address_   = 0;
    uint8_t  flash_sequence_ = 0, flash_command_ = 0;
    uint8_t  flash_control_  = kCtrlCe;
    uint8_t  test_reg_ = 0, config_reg_ = 0, device_select_ = 0, asic_mode_ = 0;
    uint16_t ecc_conf0_ = 0; uint8_t ecc_conf1_ = 0;

    uint8_t  addr_bytes_[4] = {}; int addr_len_ = 0;
    size_t   data_base_ = 0, data_cursor_ = 0;
    bool     data_wide_pending_ = false;
#if CERF_DEV_MODE
    int      dbg_accesses_ = 0;
#endif
};

}  /* namespace */

REGISTER_SERVICE(MsystemsDocG3);
