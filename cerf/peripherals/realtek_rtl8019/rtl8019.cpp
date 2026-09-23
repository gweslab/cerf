#include "rtl8019.h"

#include "../pcmcia/pcmcia_slot.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../core/string_utils.h"
#include "../../net/ipv4_packet.h"
#include "../../net/mac_address.h"
#include "../../net/network_backend.h"
#include "../../state/state_stream.h"

#include <cstdio>
#include <cstring>

namespace {

const uint8_t kCisData[] = {
    /* linux-2.6.25 drivers/pcmcia/cistpl.c parse_device();
       cistpl.h:91 DTYPE_NULL, :99 DTYPE_FUNCSPEC. */
    0x01, 5, 0x00, 0x39, 0xD0, 0x39, 0xFF,
    0x17, 3, 0xD8, 0x08, 0xFF,
    /* linux-2.6.25 drivers/pcmcia/cistpl.h CISTPL_FUNCID_NETWORK. */
    0x21, 2, 0x06, 0x00,
    /* linux-2.6.25 drivers/net/pcmcia/pcnet_cs.c:1703
       PCMCIA_DEVICE_PROD_ID12("PCMCIA", "Ethernet Card", ...). */
    0x15, 24, 0x04, 0x01,
              'P', 'C', 'M', 'C', 'I', 'A', 0x00,
              'E', 't', 'h', 'e', 'r', 'n', 'e', 't', ' ',
              'C', 'a', 'r', 'd', 0x00,
              0xFF,
    /* linux-2.6.25 drivers/pcmcia/cistpl.c parse_config(). */
    0x1A, 5, 0x01, 0x01, 0x00, 0x01, 0x03,
    /* linux-2.6.25 drivers/pcmcia/cistpl.c parse_cftable_entry(),
       parse_power(). DP8390D Preliminary DC Specifications, printed
       1-168: VCC = 5V +/-5%. */
    0x1B, 5, 0xC1, 0x01, 0x01, 0x01, 0x55,
    /* linux-2.6.25 drivers/pcmcia/cistpl.c parse_io();
       cistpl.h:414-417. Base 0x300 is where
       drivers/net/pcmcia/pcnet_cs.c try_io_port() begins its probe. */
    0x1B, 7, 0x01, 0x08, 0xEA, 0x60, 0x00, 0x03, 0x1F,
    /* linux-2.6.25 drivers/pcmcia/cistpl.c:445. */
    0x14, 0,
    0xFF, 0,
};
constexpr std::size_t kCisSize = sizeof(kCisData);

/* PC Card Standard Vol. 2 Electrical, 4.15 note 1: the configuration
   registers sit at the base the CIS Configuration Tuple TPCC_RADR
   declares; COR at base + 0, CCSR at base + 2 per the 4.15 register
   table. */
constexpr uint32_t kCorOffset  = 0x100;
constexpr uint32_t kCcsrOffset = 0x102;

/* PC Card Standard Vol. 2 Electrical, 4.15.1 Table 4-29. */
constexpr uint8_t kCorSreset  = 0x80;
constexpr uint8_t kCorLevIreq = 0x40;
constexpr uint8_t kCorIndex   = 0x3F;

/* PC Card Standard Vol. 2 Electrical, 4.15.2 Table 4-30. */
constexpr uint8_t kCcsrIntrAck = 0x01;
constexpr uint8_t kCcsrIntr    = 0x02;
constexpr uint8_t kCcsrPwrDwn  = 0x04;
constexpr uint8_t kCcsrIoIs8   = 0x20;
constexpr uint8_t kCcsrChanged = 0x80;

/* linux-2.6.25 drivers/net/pcmcia/pcnet_cs.c:503 try_io_port() probes
   from 0x300 in steps of 0x20. */
constexpr uint8_t  kCorConfigIndex = 0x01;
constexpr uint32_t kIoBlockBase    = 0x300;
constexpr uint32_t kIoBlockSize    = 0x20;

}

Rtl8019::Rtl8019(CerfEmulator& emu)
    : PcmciaCard(emu), nic_(*this, card_rom_, card_ram_),
      receiver_(nic_, card_ram_) {
    guest_mac_ = emu_.Get<NetworkBackend>().GuestMacAddress();
    WriteMacProm();

    std::lock_guard<std::mutex> lk(state_mutex_);
    nic_.ResetLocked();
}

Rtl8019::~Rtl8019() { DetachRx(); }

void Rtl8019::DetachRx() {
    if (!rx_installed_) return;
    emu_.Get<NetworkBackend>().DetachReceiver(rx_id_);
    rx_installed_ = false;
}

void Rtl8019::OnShutdown() {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const bool was_driving = powered_ && irq_line_;
        powered_  = false;
        irq_line_ = false;
        if (was_driving) slot_->ClearIrq();
    }
    DetachRx();
}

void Rtl8019::WriteMacProm() {
    /* QEMU hw/net/ne2000.c ne2000_reset PROM layout;
       linux-2.6.25 drivers/net/pcmcia/pcnet_cs.c get_prom()
       binds iff prom[28] == 0x57 && prom[30] == 0x57. */
    std::array<uint8_t, 16> prom{};
    for (std::size_t i = 0; i < kMacLen; ++i) {
        prom[i] = guest_mac_[i];
    }
    prom[14] = 0x57;
    prom[15] = 0x57;
    for (std::size_t i = 0; i < prom.size(); ++i) {
        card_rom_[2 * i]     = prom[i];
        card_rom_[2 * i + 1] = prom[i];
    }
}

std::string Rtl8019::ReceiverId() const {
    return "ne2000:" + WideToUtf8(slot_->WidgetName());
}

void Rtl8019::OnInserted() {
    rx_id_ = ReceiverId();
    guest_mac_ = emu_.Get<NetworkBackend>().AttachReceiver(
        rx_id_, NetworkBackend::ReceiverKind::Ethernet,
        [this](const uint8_t* frame, std::size_t len) {
            OnRxFrame(frame, len);
        });
    WriteMacProm();
    rx_installed_ = true;
    LOG(Net, "[NE2000] inserted: MAC=%s\n", cerf::inet::FormatMac(guest_mac_.data()).s);
}

void Rtl8019::PowerOn() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    powered_ = true;
    card_ram_.fill(0);
    PowerUpLocked();
    LOG(Net, "[NE2000] power-on\n");
}

void Rtl8019::PowerUpLocked() {
    ccsr_ = 0u;
    nic_.PowerUpLocked();
}

void Rtl8019::PowerOff() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const bool was_driving = powered_ && irq_line_;
    powered_  = false;
    irq_line_ = false;
    if (was_driving) slot_->ClearIrq();
    /* PC Card Standard Vol. 2 Electrical, 4.3.2: the Memory Only
       interface is the default selected after the application of VCC. */
    cor_ = 0u;
    LOG(Net, "[NE2000] power-off\n");
}

void Rtl8019::SetIrqLineLocked(bool level) {
    if (!powered_) return;
    if (level == irq_line_) return;
    irq_line_ = level;
    if (level) slot_->RaiseIrq();
    else       slot_->ClearIrq();
}

void Rtl8019::OnRxFrame(const uint8_t* frame, std::size_t len) {
    /* linux-2.6.25 drivers/net/lib8390.c ei_receive() - the 8390 driver
       rejects ring packets outside 60..1518 bytes as "bogus packet size". */
    if (len > cerf::inet::kEthMaxFrameSize) {
        emu_.Get<Fatal>().Die("[NE2000] RX frame len=%u exceeds %u",
                              static_cast<unsigned>(len),
                              static_cast<unsigned>(cerf::inet::kEthMaxFrameSize));
    }
    uint8_t padded[60];
    if (len < sizeof(padded)) {
        std::memcpy(padded, frame, len);
        std::memset(padded + len, 0, sizeof(padded) - len);
        frame = padded;
        len = sizeof(padded);
    }

    std::lock_guard<std::mutex> lk(state_mutex_);
    /* PC Card Standard Vol. 2 Electrical, 4.15.2 CCSR.PwrDwn: "the
       function shall enter a power-down state ... While this field is
       one (1), the host shall not access the function". */
    if (ccsr_ & kCcsrPwrDwn) return;
    if (receiver_.OnFrameLocked(frame, len)) {
        slot_->MarkRx();
    }
}

uint8_t Rtl8019::ReadAttribute8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (offset == kCorOffset) {
        return cor_;
    }
    if (offset == kCcsrOffset) {
        const uint8_t intr = nic_.IrqPendingLocked() ? kCcsrIntr : 0u;
        return static_cast<uint8_t>((ccsr_ & ~kCcsrIntr) | intr);
    }
    if (offset < kCisSize * 2u) {
        /* PC Card Standard Vol. 2 Electrical, Attribute Memory Read
           function: "only even byte data is valid". */
        return kCisData[offset / 2u];
    }
    return kBusFloat8;
}

void Rtl8019::WriteAttribute8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (offset == kCorOffset) {
        LOG(Net, "[NE2000] COR = 0x%02X (config index 0x%02X)\n",
            value, value & 0x3Fu);
        /* PC Card Standard Vol. 2 Electrical, 4.12.2: on SRESET "a card
           shall return to the power-up state"; 4.15.1: the index "shall
           be reset to zero (0) by the PC Card when the host sets the
           SRESET field to one (1)". */
        if (value & kCorSreset) {
            PowerUpLocked();
            cor_ = kCorSreset;
            return;
        }
        /* PC Card Standard Vol. 2 Electrical, 4.15.1 Table 4-29:
           LevIREQ selects Level vs Pulse Mode Interrupt; the card
           models the level form only. */
        if ((value & kCorIndex) != 0u && !(value & kCorLevIreq)) {
            emu_.Get<Fatal>().Die("[NE2000] COR = 0x%02X selects pulse-mode "
                                  "IREQ - unimplemented", value);
        }
        cor_ = value;
        return;
    }
    if (offset == kCcsrOffset) {
        /* PC Card Standard Vol. 2 Electrical, 4.15.2 Table 4-30 field
           text: IntrAck ignored by single-function cards, Changed/Intr
           R/O, IOIs8 and PwrDwn stored. */
        if (value & static_cast<uint8_t>(
                ~(kCcsrIoIs8 | kCcsrPwrDwn | kCcsrIntrAck | kCcsrIntr |
                  kCcsrChanged))) {
            emu_.Get<Fatal>().Die("[NE2000] CCSR = 0x%02X - SigChg/Audio/RFU "
                                  "unimplemented", value);
        }
        ccsr_ = value & static_cast<uint8_t>(kCcsrIoIs8 | kCcsrPwrDwn);
        return;
    }
    emu_.Get<Fatal>().Die("[NE2000] write attribute offset 0x%X = 0x%02X - "
                          "unsupported register", offset, value);
}

/* linux-2.6.25 drivers/net/pcmcia/pcnet_cs.c:1481-1516
   setup_shmem_window(): packet RAM as a common-memory window at
   start_pg << 8. */
uint8_t Rtl8019::ReadCommon8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (offset >= Dp8390::kRamBase &&
        offset < Dp8390::kRamBase + Dp8390::kRamSize) {
        return card_ram_[offset - Dp8390::kRamBase];
    }
    return kBusFloat8;
}

uint16_t Rtl8019::ReadCommon16(uint32_t offset) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const uint32_t base = offset & ~1u;
    if (base >= Dp8390::kRamBase &&
        base + 1u < Dp8390::kRamBase + Dp8390::kRamSize) {
        return cerf::le::U16(card_ram_.data(), base - Dp8390::kRamBase);
    }
    return kBusFloat16;
}

void Rtl8019::WriteCommon8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (offset >= Dp8390::kRamBase &&
        offset < Dp8390::kRamBase + Dp8390::kRamSize) {
        card_ram_[offset - Dp8390::kRamBase] = value;
        return;
    }
    emu_.Get<Fatal>().Die("[NE2000] write8 common offset 0x%X = 0x%02X "
                          "outside the packet RAM window 0x%X..0x%X", offset,
                          value, Dp8390::kRamBase,
                          Dp8390::kRamBase + Dp8390::kRamSize);
}

void Rtl8019::WriteCommon16(uint32_t offset, uint16_t value) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const uint32_t base = offset & ~1u;
    if (base >= Dp8390::kRamBase &&
        base + 1u < Dp8390::kRamBase + Dp8390::kRamSize) {
        cerf::le::Put16(card_ram_.data() + (base - Dp8390::kRamBase), value);
        return;
    }
    emu_.Get<Fatal>().Die("[NE2000] write16 common offset 0x%X = 0x%04X "
                          "outside the packet RAM window 0x%X..0x%X", offset,
                          value, Dp8390::kRamBase,
                          Dp8390::kRamBase + Dp8390::kRamSize);
}

bool Rtl8019::IoIgnoredLocked() const {
    /* PC Card Standard Vol. 2 Electrical, 4.3.2: the Memory Only
       interface is the default at insertion and after VCC/RESET; the
       function decodes no I/O until a configuration index is set. */
    return (cor_ & kCorIndex) == 0u;
}

bool Rtl8019::MapCardIoLocked(uint32_t card_io, uint32_t* reg) const {
    const uint8_t index = cor_ & kCorIndex;
    if (index != kCorConfigIndex) return false;
    if (card_io < kIoBlockBase ||
        card_io >= kIoBlockBase + kIoBlockSize) return false;
    *reg = card_io - kIoBlockBase;
    return true;
}

uint8_t Rtl8019::ReadIo8(uint32_t card_io) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (IoIgnoredLocked()) return kBusFloat8;
    uint32_t offset;
    if (!MapCardIoLocked(card_io, &offset)) {
        emu_.Get<Fatal>().Die("[NE2000] read8 io 0x%X outside configured "
                              "block (COR=0x%02X)", card_io, cor_);
    }
    return nic_.IoRead8Locked(offset);
}

uint16_t Rtl8019::ReadIo16(uint32_t card_io) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (IoIgnoredLocked()) return kBusFloat16;
    uint32_t offset;
    if (!MapCardIoLocked(card_io, &offset)) {
        emu_.Get<Fatal>().Die("[NE2000] read16 io 0x%X outside configured "
                              "block (COR=0x%02X)", card_io, cor_);
    }
    return nic_.IoRead16Locked(offset);
}

void Rtl8019::WriteIo8(uint32_t card_io, uint8_t value) {
    std::vector<uint8_t> tx_pending;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (IoIgnoredLocked()) return;
        uint32_t offset;
        if (!MapCardIoLocked(card_io, &offset)) {
            emu_.Get<Fatal>().Die("[NE2000] write8 io 0x%X = 0x%02X outside "
                                  "configured block (COR=0x%02X)",
                                  card_io, value, cor_);
        }
        nic_.IoWrite8Locked(offset, value, tx_pending);
    }
    if (!tx_pending.empty()) {
        emu_.Get<NetworkBackend>().SendFrame(tx_pending.data(),
                                             tx_pending.size());
        slot_->MarkTx();
        std::lock_guard<std::mutex> lk(state_mutex_);
        nic_.CompleteTxLocked();
    }
}

void Rtl8019::WriteIo16(uint32_t card_io, uint16_t value) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (IoIgnoredLocked()) return;
    uint32_t offset;
    if (!MapCardIoLocked(card_io, &offset)) {
        emu_.Get<Fatal>().Die("[NE2000] write16 io 0x%X = 0x%04X outside "
                              "configured block (COR=0x%02X)",
                              card_io, value, cor_);
    }
    nic_.IoWrite16Locked(offset, value);
}

std::wstring Rtl8019::TooltipDetail() const {
    wchar_t buf[64];
    swprintf_s(buf, L"Ethernet  %hs", cerf::inet::FormatMac(guest_mac_.data()).s);
    return buf;
}

std::vector<WidgetMenuItem> Rtl8019::BuildCardMenu() {
    wchar_t buf[64];
    swprintf_s(buf, L"MAC  %hs", cerf::inet::FormatMac(guest_mac_.data()).s);
    WidgetMenuItem mac;
    mac.label   = buf;
    mac.enabled = false;
    return { std::move(mac) };
}

void Rtl8019::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.WriteBytes(guest_mac_.data(), guest_mac_.size());
    nic_.SaveState(w);
    w.Write(cor_); w.Write(ccsr_);
    w.WriteBytes(card_rom_.data(), card_rom_.size());
    w.WriteBytes(card_ram_.data(), card_ram_.size());
}

void Rtl8019::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    r.ReadBytes(guest_mac_.data(), guest_mac_.size());
    nic_.RestoreState(r);
    r.Read(cor_); r.Read(ccsr_);
    r.ReadBytes(card_rom_.data(), card_rom_.size());
    r.ReadBytes(card_ram_.data(), card_ram_.size());
}

void Rtl8019::PostRestore() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    irq_line_ = false;
    nic_.RecomputeIrqLocked();
}
