#include "imx51_nfc.h"
#include "imx51_nand_store.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace {

constexpr uint32_t kIpBase = 0x83FDB000u;
constexpr uint32_t kIpSize = 0x00001000u;

constexpr uint32_t kIpWrProtect = 0x00u;
constexpr uint32_t kIpUnlock0   = 0x04u;
constexpr uint32_t kIpUnlock7   = 0x20u;
constexpr uint32_t kIpCfg2      = 0x24u;
constexpr uint32_t kIpCfg3      = 0x28u;
constexpr uint32_t kIpIpc       = 0x2Cu;
constexpr uint32_t kIpAxiError  = 0x30u;
constexpr uint32_t kIpDelayLine = 0x34u;

constexpr uint32_t kAxiBase       = 0xCFFF0000u;
constexpr uint32_t kAxiWindowBase = 0xCFFF1000u;
constexpr uint32_t kAxiWindowSize = 0x00001000u;

constexpr uint32_t kAxiSpareBase = 0x1000u;
constexpr uint32_t kAxiSpareEnd  = 0x1200u;
constexpr uint32_t kAxiNandCmd   = 0x1E00u;
constexpr uint32_t kAxiNandAdd0  = 0x1E04u;
constexpr uint32_t kAxiNandAdd11 = 0x1E30u;
constexpr uint32_t kAxiCfg1      = 0x1E34u;
constexpr uint32_t kAxiEccStatus = 0x1E38u;
constexpr uint32_t kAxiStatusSum = 0x1E3Cu;
constexpr uint32_t kAxiLaunch    = 0x1E40u;

constexpr uint32_t kLaunchFcmd     = 1u << 0;
constexpr uint32_t kLaunchFadd     = 1u << 1;
constexpr uint32_t kLaunchFdiMask  = 1u << 2;
constexpr uint32_t kLaunchFdoMask  = 0x7u << 3;
constexpr uint32_t kLaunchAutoProg  = 1u << 6;   /* AUTO_PROG  (RM Table 45-29) */
constexpr uint32_t kLaunchAutoRead  = 1u << 7;   /* AUTO_READ  (RM Table 45-29) */
constexpr uint32_t kLaunchAutoErase = 1u << 9;   /* AUTO_ERASE (RM Table 45-29) */
constexpr uint32_t kLaunchAutoMask  = 0xFFu << 6;

/* FDO field (LAUNCH_NFC[5:3]) selects the data-output type: FDO=001 = NAND data
   output (MCIMX51RM Fig 45-42, §45.9.2.5), FDO=010 = NAND ID output (Fig 45-43,
   §45.9.2.6). The output depends on the FDO field, NOT on a prior READ-ID. */
constexpr uint32_t kFdoDataOutput = 0x1u;
constexpr uint32_t kFdoIdOutput   = 0x2u;
constexpr uint32_t kFdoStatus     = 0x4u;   /* FDO=100 NAND status output */

constexpr uint32_t kIpcInt  = 1u << 31;
constexpr uint32_t kIpcRbB  = 1u << 28;
constexpr uint32_t kIpcCack = 1u << 1;
constexpr uint32_t kIpcCreq = 1u << 0;

constexpr uint8_t  kNandCmdReadStart    = 0x00u;
constexpr uint8_t  kNandCmdReadConfirm  = 0x30u;
constexpr uint8_t  kNandCmdReadCacheSeq = 0x31u;   /* NAND Read Cache Sequential */
constexpr uint8_t  kNandCmdReadCacheEnd = 0x3Fu;   /* NAND Read Cache End (last page) */
constexpr uint8_t  kNandCmdReadId       = 0x90u;
constexpr uint8_t  kNandCmdReadStatus   = 0x70u;   /* NAND READ STATUS */
constexpr uint8_t  kNandCmdReset        = 0xFFu;   /* NAND RESET */

constexpr uint32_t kMainPageBytes = 0x1000u;

/* READ ID (0x90): byte 0 = 0x2C = Micron (MT29F datasheet Table 7); byte 1 = 0x48
   = the device ID the Sync2 board's NAND reports (board identity like the OAT, not
   an MT29F2G08 value 0xAA/0xBA/0xDA/0xCA); SBOOT matches READ-ID against its media table. */
constexpr std::array<uint8_t, 5> kReadIdBytes = {0x2Cu, 0x48u, 0x00u, 0x00u, 0x00u};

/* Decode the five NAND address cycles (little-endian [col_lo, col_hi, row_lo,
   row_mid, row_hi]) to a linear flash byte offset: 12-bit column (4 KB page) +
   19-bit row (the 2 GB Micron part = 0x80000 pages; READ ID 0x2C/0x48 above). */
uint64_t DecodeNandAddr(const std::array<uint8_t, 5>& a) {
    const uint32_t column = cerf::le::U16(a.data()) & 0x0FFFu;
    const uint32_t row    = cerf::le::U24(a.data() + 2) & 0x7FFFFu;
    return (static_cast<uint64_t>(row) << 12) | column;
}

}  /* namespace */

REGISTER_SERVICE(Imx51Nfc);

bool Imx51Nfc::ShouldRegister() {
    return emu_.TryGet<Imx51NandStore>() != nullptr;
}

void Imx51Nfc::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Imx51Nfc::MmioBase() const { return kIpBase; }
uint32_t Imx51Nfc::MmioSize() const { return kIpSize; }

uint8_t  Imx51Nfc::ReadByte (uint32_t addr) { return static_cast<uint8_t>(NfcRead(addr, 1)); }
uint16_t Imx51Nfc::ReadHalf (uint32_t addr) { return static_cast<uint16_t>(NfcRead(addr, 2)); }
uint32_t Imx51Nfc::ReadWord (uint32_t addr) { return NfcRead(addr, 4); }
void Imx51Nfc::WriteByte (uint32_t addr, uint8_t  value) { NfcWrite(addr, value, 1); }
void Imx51Nfc::WriteHalf (uint32_t addr, uint16_t value) { NfcWrite(addr, value, 2); }
void Imx51Nfc::WriteWord (uint32_t addr, uint32_t value) { NfcWrite(addr, value, 4); }

uint32_t Imx51Nfc::NfcRead(uint32_t addr, uint32_t width) {
    if (addr >= kAxiWindowBase && addr < kAxiWindowBase + kAxiWindowSize) {
        const uint32_t off = addr - kAxiBase;
        if (off >= kAxiSpareBase && off < kAxiSpareEnd) {
            uint32_t v = 0;
            for (uint32_t i = 0; i < width; ++i)
                v |= static_cast<uint32_t>(spare_[(off - kAxiSpareBase) + i]) << (8 * i);
            return v;
        }
        if (off >= kAxiNandAdd0 && off <= kAxiNandAdd11)
            return nand_add_[(off - kAxiNandAdd0) / 4];
        switch (off) {
            case kAxiNandCmd:   return nand_cmd_;
            case kAxiCfg1:      return cfg1_;
            case kAxiEccStatus: return ecc_status_;
            case kAxiStatusSum: return status_sum_;
            case kAxiLaunch:    return launch_;
        }
        HaltUnsupportedAccess("NfcRead(AXI)", addr, 0);
    }

    const uint32_t off = addr - kIpBase;
    if (off >= kIpUnlock0 && off <= kIpUnlock7) return unlock_[(off - kIpUnlock0) / 4];
    switch (off) {
        case kIpWrProtect: return wr_protect_;
        case kIpCfg2:      return cfg2_;
        case kIpCfg3:      return cfg3_;
        case kIpIpc: {
            const uint32_t ipc = (int_pending_ ? kIpcInt : 0) | kIpcRbB |
                                 (creq_ ? (kIpcCreq | kIpcCack) : 0);
            return ipc;
        }
        case kIpAxiError:  return axi_error_;
        case kIpDelayLine: return delay_line_;
    }
    HaltUnsupportedAccess("NfcRead(IP)", addr, 0);
}

void Imx51Nfc::NfcWrite(uint32_t addr, uint32_t value, uint32_t width) {
    if (addr >= kAxiWindowBase && addr < kAxiWindowBase + kAxiWindowSize) {
        const uint32_t off = addr - kAxiBase;
        if (off >= kAxiSpareBase && off < kAxiSpareEnd) {
            for (uint32_t i = 0; i < width; ++i)
                spare_[(off - kAxiSpareBase) + i] = static_cast<uint8_t>(value >> (8 * i));
            return;
        }
        if (off >= kAxiNandAdd0 && off <= kAxiNandAdd11) {
            nand_add_[(off - kAxiNandAdd0) / 4] = value; return;
        }
        switch (off) {
            case kAxiNandCmd:   nand_cmd_   = static_cast<uint8_t>(value); return;
            case kAxiCfg1:      cfg1_       = value;                       return;
            case kAxiEccStatus: ecc_status_ = value;                      return;
            case kAxiStatusSum: status_sum_ = value;                      return;
            case kAxiLaunch:    Launch(value);                            return;
        }
        HaltUnsupportedAccess("NfcWrite(AXI)", addr, value);
    }

    const uint32_t off = addr - kIpBase;
    if (off >= kIpUnlock0 && off <= kIpUnlock7) { unlock_[(off - kIpUnlock0) / 4] = value; return; }
    switch (off) {
        case kIpWrProtect: wr_protect_ = value; return;
        case kIpCfg2:      cfg2_       = value; return;
        case kIpCfg3:      cfg3_       = value; return;
        case kIpIpc:
            int_pending_ = (value & kIpcInt) != 0;
            creq_        = (value & kIpcCreq) != 0;
            return;
        case kIpAxiError:  axi_error_  = value; return;
        case kIpDelayLine: delay_line_ = value; return;
    }
    HaltUnsupportedAccess("NfcWrite(IP)", addr, value);
}

void Imx51Nfc::Launch(uint32_t value) {
    launch_ = value;
    if (value & kLaunchFcmd) {
        switch (nand_cmd_) {
            case kNandCmdReadStart:        /* read-setup / read-id start a fresh */
            case kNandCmdReadId:           /* address cycle                       */
                addr_idx_ = 0;
                break;
            case kNandCmdReadConfirm:      /* read-confirm keeps the loaded address */
            case kNandCmdReadStatus:       /* READ STATUS: command-input only; the   */
                break;                     /* FDO=100 phase outputs the status byte  */
            case kNandCmdReadCacheSeq:
                seq_cache_off_ = seq_data_off_;
                seq_data_off_ += kMainPageBytes;
                break;
            case kNandCmdReadCacheEnd:
                seq_cache_off_ = seq_data_off_;
                break;
            case kNandCmdReset:            /* RESET: return to read mode, drop any */
                addr_idx_      = 0;        /* in-progress address cycle + Read-Cache */
                seq_data_off_  = 0;        /* sequence                              */
                seq_cache_off_ = 0;
                break;
            default:
                LOG(Caution, "Imx51Nfc: unhandled FCMD NAND_CMD=0x%02X (LAUNCH 0x%08X)\n",
                    nand_cmd_, value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        int_pending_ = true;
        return;
    }
    if (value & kLaunchFadd) {
        if (addr_idx_ < addr_bytes_.size())
            addr_bytes_[addr_idx_++] = static_cast<uint8_t>(nand_add_[0]);
        int_pending_ = true;
        return;
    }
    if (value & kLaunchFdoMask) {
        const uint32_t fdo = (value & kLaunchFdoMask) >> 3;
        if (fdo == kFdoIdOutput)        ReadId();
        else if (fdo == kFdoDataOutput) ReadPage();
        else if (fdo == kFdoStatus)     ReadStatus();
        else {
            LOG(Caution, "Imx51Nfc: unhandled FDO field %u in LAUNCH_NFC 0x%08X (cmd=0x%02X)\n",
                fdo, value, nand_cmd_);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        int_pending_ = true;
        return;
    }
    if (value & kLaunchAutoRead) {
        AutoRead();
        int_pending_ = true;
        return;
    }
    if (value & kLaunchAutoProg) {
        AutoProg();
        int_pending_ = true;
        return;
    }
    if (value & kLaunchAutoErase) {
        AutoErase();
        int_pending_ = true;
        return;
    }
    if (value & (kLaunchFdiMask | kLaunchAutoMask)) {
        LOG(Caution, "Imx51Nfc: unhandled LAUNCH_NFC 0x%08X (cmd=0x%02X)\n",
            value, nand_cmd_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    int_pending_ = true;
}

uint64_t Imx51Nfc::FlashOffset() const {
    return DecodeNandAddr(addr_bytes_);
}

void Imx51Nfc::FillPageBuffer(uint64_t flash_off) {
    std::array<uint8_t, kMainPageBytes> page{};
    /* The NAND is the writable nand.img store (seeded boot region + guest-flashed OS
       region); an unwritten/erased page reads 0xFF. Stored RAW (pre-BBI-swap). */
    emu_.Get<Imx51NandStore>().ReadPage(flash_off, page.data(), spare_.data());
    /* Factory BBI is in the NFC main page (NXP AN_MX_NAND_BAD_BLOCK §3: read at
       main[0xF4A]); present 0xFF and displace the stored byte to spare, else the FMD
       bad-block check (which reads main[0xF4A]) marks every block bad. */
    std::swap(page[0xF4Au], spare_[0x1C1u]);
    emu_.Get<EmulatedMemory>().CopyIn(kAxiBase, page.data(), page.size());
}

void Imx51Nfc::ReadPage() {
    const bool cache = (nand_cmd_ == kNandCmdReadCacheSeq || nand_cmd_ == kNandCmdReadCacheEnd);
    FillPageBuffer(cache ? seq_cache_off_ : FlashOffset());
}

void Imx51Nfc::AutoRead() {
    /* AUTO_READ: full page-read into the internal RAM buffer (MCIMX51RM §45.9.1.2).
       A 4 KB page forces RBA=000 (NFC_CONFIGURATION1, Table 45-26), so the page
       lands at the AXI buffer base; a non-000 RBA would need a sub-buffer offset. */
    const uint32_t iterations = (cfg1_ >> 8) & 0xFu;
    if (iterations != 0) {
        LOG(Caution, "Imx51Nfc: AUTO_READ NUM_OF_ITERATIONS=%u unsupported (cfg1=0x%08X)\n",
            iterations, cfg1_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    /* AUTO_READ issues the address phases (MCIMX51RM §45.9.1.2), latching the NAND
       address; a later manual FDO data-output (FDO=001) outputs that same latched
       page, so mirror it into addr_bytes_ - without this the FDO reads stale bytes. */
    addr_bytes_    = AutoAddrBytes();
    addr_idx_      = static_cast<uint32_t>(addr_bytes_.size());
    seq_data_off_  = AutoFlashOffset();   /* start page for a following Read-Cache sequence */
    FillPageBuffer(seq_data_off_);
}

void Imx51Nfc::AutoProg() {
    /* AUTO_PROG (LAUNCH_NFC bit 6, MCIMX51RM §45.9.1.1 + Table 45-29): program the
       NFC buffer to the addressed page (NAND_ADDRESS0 group). NAND command = PROGRAM
       PAGE 0x80/0x10 (Micron MT29F datasheet Table 5). */
    std::array<uint8_t, kMainPageBytes> page{};
    emu_.Get<EmulatedMemory>().CopyOut(kAxiBase, page.data(), page.size());
    /* Inverse of the ReadPage factory-BBI swap (NXP AN §3): the guest prepared the
       served form (main[0xF4A]<->spare[0x1C1]); store RAW so a later read of this
       page returns these exact bytes (round-trip). */
    std::swap(page[0xF4Au], spare_[0x1C1u]);
    emu_.Get<Imx51NandStore>().WritePage(AutoFlashOffset(), page.data(), spare_.data());
}

void Imx51Nfc::AutoErase() {
    /* AUTO_ERASE (LAUNCH_NFC bit 9, MCIMX51RM §45.9.1.3 + Table 45-29): NAND command
       = ERASE BLOCK 0x60/0xD0 (Micron MT29F datasheet Table 5), which takes 3 address
       cycles = a pure row (block) address with no column, so the block byte offset =
       NAND_ADD0 << 12 (4 KB page). */
    emu_.Get<Imx51NandStore>().EraseBlock(static_cast<uint64_t>(nand_add_[0]) << 12);
}

uint64_t Imx51Nfc::AutoFlashOffset() const {
    /* AUTO_READ address from the active group NAND_ADDRESS0 (Table 45-11):
       NAND_ADD0 = ADDRESS0[31:0], NAND_ADD8[7:0] = ADDRESS0[39:32]. */
    return DecodeNandAddr(AutoAddrBytes());
}

std::array<uint8_t, 5> Imx51Nfc::AutoAddrBytes() const {
    std::array<uint8_t, 5> a{};
    cerf::le::Put32(a.data(), nand_add_[0]);
    a[4] = static_cast<uint8_t>(nand_add_[8]);
    return a;
}

void Imx51Nfc::ReadId() {
    std::array<uint8_t, kMainPageBytes> buf{};
    std::copy(kReadIdBytes.begin(), kReadIdBytes.end(), buf.begin());
    emu_.Get<EmulatedMemory>().CopyIn(kAxiBase, buf.data(), buf.size());
}

void Imx51Nfc::ReadStatus() {
    /* FDO=100 status output (MCIMX51RM §45.9.2.7 Fig 45-46): present the last NAND
       status in NFC_CONFIGURATION1.NF_STATUS [23:16] (Table 45-26). Emulated NAND is
       always ready + pass -> Micron MT29F idle status (datasheet Table 15): SR7 WP_n=1,
       SR6 RDY=1, SR5 ARDY=1, SR0 FAIL=0 = 0xE0. */
    constexpr uint32_t kNandStatusReadyPass = 0xE0u;
    cfg1_ = (cfg1_ & ~0x00FF0000u) | (kNandStatusReadyPass << 16);
}

void Imx51Nfc::SaveState(StateWriter& w) {
    w.WriteBytes("spare", spare_.data(), spare_.size());
    w.Write("nand_cmd", nand_cmd_);
    for (uint32_t v : nand_add_) w.Write("nand_add", v);
    w.Write("cfg1", cfg1_);
    w.Write("ecc_status", ecc_status_);
    w.Write("status_sum", status_sum_);
    w.Write("launch", launch_);
    w.Write("wr_protect", wr_protect_);
    for (uint32_t v : unlock_) w.Write("unlock", v);
    w.Write("cfg2", cfg2_);
    w.Write("cfg3", cfg3_);
    w.Write("axi_error", axi_error_);
    w.Write("delay_line", delay_line_);
    w.Write<uint8_t>("int_pending", int_pending_ ? 1 : 0);
    w.Write<uint8_t>("creq", creq_ ? 1 : 0);
    w.WriteBytes("addr_bytes", addr_bytes_.data(), addr_bytes_.size());
    w.Write("addr_idx", addr_idx_);
    w.Write("seq_data_off", seq_data_off_);
    w.Write("seq_cache_off", seq_cache_off_);
}

void Imx51Nfc::RestoreState(StateReader& r) {
    r.ReadBytes("spare", spare_.data(), spare_.size());
    r.Read("nand_cmd", nand_cmd_);
    for (uint32_t& v : nand_add_) r.Read("nand_add", v);
    r.Read("cfg1", cfg1_);
    r.Read("ecc_status", ecc_status_);
    r.Read("status_sum", status_sum_);
    r.Read("launch", launch_);
    r.Read("wr_protect", wr_protect_);
    for (uint32_t& v : unlock_) r.Read("unlock", v);
    r.Read("cfg2", cfg2_);
    r.Read("cfg3", cfg3_);
    r.Read("axi_error", axi_error_);
    r.Read("delay_line", delay_line_);
    uint8_t b = 0;
    r.Read("int_pending", b); int_pending_ = b != 0;
    r.Read("creq", b); creq_ = b != 0;
    r.ReadBytes("addr_bytes", addr_bytes_.data(), addr_bytes_.size());
    r.Read("addr_idx", addr_idx_);
    r.Read("seq_data_off", seq_data_off_);
    r.Read("seq_cache_off", seq_cache_off_);
}
