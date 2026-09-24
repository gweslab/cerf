#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../boards/siemens_p177/siemens_p177_id.h"
#include "../../state/state_stream.h"

#include <cstdint>

/* SMSC LAN9115 Ethernet controller (TP177B, S3C2410 nGCS5). Reported present +
   ready so lan9115.dll MiniportInitialize succeeds; an absent model fails its
   chip-rev check and NDIS faults (BVA 0x504D4466). No TX/RX/IRQ - boot needs init
   success, not traffic. */

namespace {

/* IoBaseAddress = nGCS5 base = 0x28000000 (registry default.hv
   LAN9115\IoBaseAddress = 0x28000000). lan9115.dll reads ID_REV +0x50, BYTE_TEST
   +0x64, IRQ_CFG +0x54 - the runtime +0x54 write confirms base 0x28000000. */
constexpr uint32_t kBankBase = 0x28000000u;   /* nGCS5 (OAT 0x8E000000->0x28000000, 32 MB) */
constexpr uint32_t kBankSize = 0x02000000u;
constexpr uint32_t kNicOff   = 0x0u;          /* IoBaseAddress == bank base */
constexpr uint32_t kNicLen   = 0x100u;        /* NdisMRegisterIoPortRange(.., 256) */

/* LAN9115 directly-addressed registers (offset from IoBaseAddress). */
constexpr uint32_t kIdRev      = 0x50u;
constexpr uint32_t kByteTest   = 0x64u;
constexpr uint32_t kHwCfg      = 0x74u;
constexpr uint32_t kReg84      = 0x84u;
constexpr uint32_t kMacCsrCmd  = 0xA4u;
constexpr uint32_t kMacCsrData = 0xA8u;
constexpr uint32_t kE2pCmd     = 0xB0u;

constexpr uint32_t kIdRevValue   = 0x01150000u;  /* hi16 0x0115 = LAN9115 */
constexpr uint32_t kByteTestVal  = 0x87654321u;
constexpr uint32_t kHwCfgSrst    = 1u << 0;      /* self-clearing soft reset */
constexpr uint32_t kCsrBusy      = 1u << 31;
constexpr uint32_t kCsrRead      = 1u << 30;
constexpr uint32_t kMiiBusy      = 1u << 0;      /* MAC-CSR 6 (MII_ACC) MIIBZY */

class SmscLan9115 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SiemensP177;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBankBase; }
    uint32_t MmioSize() const override { return kBankSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t boff = addr - kBankBase;
        if (boff < kNicOff || boff >= kNicOff + kNicLen) return 0u;  /* bank outside NIC */
        switch (boff - kNicOff) {
        case kIdRev:      return kIdRevValue;
        case kByteTest:   return kByteTestVal;
        case kHwCfg:      return regs_[kHwCfg / 4u] & ~kHwCfgSrst;   /* SRST done */
        case kReg84:      return 0u;                                 /* no-reset branch */
        case kE2pCmd:     return 0u;                                 /* not busy, no EEPROM */
        case kMacCsrCmd:  return mac_csr_cmd_;                       /* busy clear */
        case kMacCsrData: return mac_csr_data_;
        default:          return regs_[(boff - kNicOff) / 4u];
        }
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t boff = addr - kBankBase;
        if (boff < kNicOff || boff >= kNicOff + kNicLen) return;     /* bank outside NIC */
        switch (boff - kNicOff) {
        case kIdRev:
        case kByteTest:   return;                                    /* read-only */
        case kMacCsrData: mac_csr_data_ = value; return;
        case kMacCsrCmd:  DoMacCsr(value); return;
        default:          regs_[(boff - kNicOff) / 4u] = value; return;
        }
    }

    /* The driver is 32-bit only; route narrow accesses through the word path. */
    uint8_t  ReadByte(uint32_t a) override { return (uint8_t)(ReadWord(a & ~3u) >> (8u * (a & 3u))); }
    uint16_t ReadHalf(uint32_t a) override { return (uint16_t)(ReadWord(a & ~3u) >> (8u * (a & 3u))); }
    void WriteByte(uint32_t a, uint8_t v) override { RmwNarrow(a, v, 0xFFu, 1u); }
    void WriteHalf(uint32_t a, uint16_t v) override { RmwNarrow(a, v, 0xFFFFu, 2u); }

    void SaveState(StateWriter& w) override {
        for (auto r : regs_)    w.Write("regs", r);
        for (auto r : mac_csr_) w.Write("mac_csr", r);
        w.Write("mac_csr_cmd", mac_csr_cmd_);
        w.Write("mac_csr_data", mac_csr_data_);
    }
    void RestoreState(StateReader& r) override {
        for (auto& v : regs_)    r.Read("regs", v);
        for (auto& v : mac_csr_) r.Read("mac_csr", v);
        r.Read("mac_csr_cmd", mac_csr_cmd_);
        r.Read("mac_csr_data", mac_csr_data_);
    }

private:
    void RmwNarrow(uint32_t a, uint32_t v, uint32_t mask, uint32_t bytes) {
        const uint32_t sh = 8u * (a & 3u);
        const uint32_t w  = ReadWord(a & ~3u);
        WriteWord(a & ~3u, (w & ~(mask << sh)) | ((v & mask) << sh));
        (void)bytes;
    }

    /* Indirect MAC-CSR access (sub_33F1E98/sub_33F1EF8): BUSY self-clears. */
    void DoMacCsr(uint32_t cmd) {
        const uint32_t idx = cmd & 0xFFu;
        if (cmd & kCsrRead) mac_csr_data_ = mac_csr_[idx];
        else                WriteMacCsr(idx, mac_csr_data_);
        mac_csr_cmd_ = cmd & ~kCsrBusy;
    }
    void WriteMacCsr(uint32_t idx, uint32_t val) {
        mac_csr_[idx] = val;
        if (idx == 6u) {                       /* MII_ACC: start MII access */
            mac_csr_[7] = PhyReg((val >> 6) & 0x1Fu);   /* MII_DATA */
            mac_csr_[6] = val & ~kMiiBusy;              /* MIIBZY self-clears */
        }
    }
    static uint32_t PhyReg(uint32_t reg) {
        if (reg == 2u) return 0x0007u;   /* PHY ID1 */
        if (reg == 3u) return 0xC0D1u;   /* PHY ID2 */
        return 0u;
    }

    uint32_t regs_[kNicLen / 4u] = {};   /* directly-addressed NIC registers */
    uint32_t mac_csr_[256]       = {};   /* indirect MAC-CSR file */
    uint32_t mac_csr_cmd_        = 0u;
    uint32_t mac_csr_data_       = 0u;
};

}  /* namespace */

REGISTER_SERVICE(SmscLan9115);
