#include "rtl8019.h"

#include "../cirrus_pd6710/pd6710_controller.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../host/host_widget_registry.h"
#include "../../net/network_backend.h"

#include <cstdio>
#include <cstring>

namespace {

/* NIC_INTR_STATUS / NIC_INTR_MASK bits (NE2000 register set, matching
   the IONE2000 bitfield unions in the DeviceEmulator host runtime). */
constexpr uint8_t kIsrRcvBit      = 0x01;
constexpr uint8_t kIsrXmitBit     = 0x02;
constexpr uint8_t kIsrOverflowBit = 0x10;
constexpr uint8_t kIsrResetBit    = 0x80;

/* NIC_COMMAND bits (NE2000 register set). */
constexpr uint8_t kCrStop  = 0x01;
constexpr uint8_t kCrStart = 0x02;

/* NIC_RCV_CONFIG bits (RCR). */
constexpr uint8_t kRcrBroadcast = 0x04;
constexpr uint8_t kRcrMulticast = 0x08;
constexpr uint8_t kRcrMonitor   = 0x20;

/* IEEE 802.3 CRC32 polynomial (bit-reversed). Used by the NE2000
   multicast hash filter (NIC_MC_ADDR is an 8-byte = 64-bit hash
   table indexed by bits 6..14 of the dest-MAC CRC32 — the chip
   accepts a multicast frame iff its index bit is set). */
constexpr uint32_t kCrc32Poly = 0xEDB88320u;

/* NIC_DATA_CONFIG bits (DCR). */
constexpr uint8_t kDcrNormal = 0x08;

/* NIC_RCV_STATUS bits (RSR). */
constexpr uint8_t kRsrPacketOk  = 0x01;

/* FCSR bits per PCMCIA function-control register spec. */
constexpr uint8_t kFcsrIntrAck = 0x01;
constexpr uint8_t kFcsrIntr    = 0x02;

constexpr std::size_t kMacLen = 6;

}  /* namespace */

bool Rtl8019::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
}

void Rtl8019::OnReady() {
    net_ = &emu_.Get<NetworkBackend>();
    pd_  = &emu_.Get<Pd6710Controller>();

    guest_mac_ = net_->GuestMacAddress();
    for (std::size_t i = 0; i < kMacLen; ++i) {
        card_rom_[i * 2] = guest_mac_[i];
    }
    /* 'W' 'W' at offsets 14/15 — CardSlotTest() reads these to
       distinguish 8-bit cards from 16-bit cards. We're 16-bit. */
    card_rom_[14] = 'W';
    card_rom_[15] = 'W';

    /* Install RX callback. The lambda's `this` capture stays valid
       for the lifetime of the Rtl8019; the NetworkBackend's poll
       thread joins in ~SlirpBackend before any service is destroyed. */
    net_->SetReceiveCallback(
        [this](const uint8_t* frame, std::size_t len) {
            OnRxFrame(frame, len);
        });

    emu_.Get<HostWidgetRegistry>().Register(this);

    LOG(Net, "[NE2000] ready: MAC=%02X:%02X:%02X:%02X:%02X:%02X "
             "(socket awaits power-on)\n",
        guest_mac_[0], guest_mac_[1], guest_mac_[2],
        guest_mac_[3], guest_mac_[4], guest_mac_[5]);
}

void Rtl8019::PowerOn() {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        ResetLocked();
    }
    if (!first_power_on_done_) {
        /* The NE2000 is power-cycled several times during PCMCIA
           enumeration; the host-side network setup only needs to
           happen once. */
        first_power_on_done_ = true;
        LOG(Net, "[NE2000] first power-on complete\n");
    } else {
        LOG(Net, "[NE2000] power-on (re-cycle)\n");
    }
}

void Rtl8019::PowerOff() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    nic_command_ = kCrStop;
    LOG(Net, "[NE2000] power-off\n");
}

void Rtl8019::ResetLocked() {
    nic_command_     = kCrStop;
    nic_page_start_  = 0u;
    nic_page_stop_   = 0u;
    nic_boundary_    = 0u;
    nic_xmit_status_ = 0u;
    nic_xmit_start_  = 0u;
    nic_xmit_count_  = 0u;
    nic_fifo_        = 0u;
    nic_intr_status_ = kIsrResetBit;     /* documented post-reset state */
    nic_crda_        = 0u;
    nic_rmt_addr_    = 0u;
    nic_rmt_count_   = 0u;
    nic_rcv_config_  = 0u;
    nic_rcv_status_  = 0u;
    /* Post-reset XCR has both loopback bits set per the datasheet,
       so the driver must explicitly clear them to start normal TX. */
    nic_xmit_config_ = 0x06u;
    nic_fae_err_     = 0u;
    nic_data_config_ = 0u;
    nic_crc_err_     = 0u;
    nic_current_     = 0u;
    nic_phys_addr_.fill(0);
    card_ram_.fill(0);
    dma_count_       = 0u;
    dma_offset_      = 0u;
}

void Rtl8019::RaiseInterruptLocked(uint8_t bits) {
    nic_intr_status_ |= bits;
    fcsr_ |= kFcsrIntr;
    /* Drive the PD6710 IRQ steering only when the bit is unmasked
       AND we're not propagating ISR_RESET (the reset bit is a
       status indicator, not a real interrupt source — pcmcia.sys
       polls for it during init, doesn't want an IRQ). */
    if (bits != kIsrResetBit && (nic_intr_mask_ & bits) != 0u) {
        if (pd_) pd_->RaiseCardIrq();
    }
}

void Rtl8019::ClearInterruptIfDrainedLocked() {
    if ((nic_intr_status_ & nic_intr_mask_) != 0u) return;
    if (pd_) pd_->ClearCardIrq();
}

void Rtl8019::OnRxFrame(const uint8_t* frame, std::size_t len) {
    if (len < kMacLen * 2u) return;  /* impossibly short Ethernet frame */
    if (len > 1518u) len = 1518u;    /* clamp to NIC max */

    std::lock_guard<std::mutex> lk(state_mutex_);

    if (nic_command_ & kCrStop)                         return;  /* card stopped */
    if (!(nic_data_config_ & kDcrNormal))               return;  /* loopback mode */
    if (nic_rcv_config_ & kRcrMonitor)                  return;

    /* Multicast filter — when RCR_MULTICAST is set, a multicast
       frame is accepted only if it passes the chip's CRC-hashed
       lookup against NIC_MC_ADDR (or is a broadcast and
       RCR_BROADCAST is set). Unicast frames bypass this filter. */
    if ((nic_rcv_config_ & kRcrMulticast) &&
        (frame[0] & 0x01u) != 0u) {
        if (!ShouldIndicateMulticastPacketLocked(frame)) return;
    }

    const uint8_t kPageMin = kRamBase >> 8;
    const uint8_t kPageMax = (kRamBase + kRamSize) >> 8;
    if (nic_page_start_ < kPageMin || nic_page_start_ >= kPageMax ||
        nic_page_stop_  < kPageMin || nic_page_stop_  >  kPageMax ||
        nic_current_    < kPageMin || nic_current_    >= kPageMax) {
        LOG(Net, "[NE2000] RX dropped (PSTART/PSTOP/PCUR out of range)\n");
        return;
    }

    const uint32_t total_with_header = static_cast<uint32_t>(len) + 4u;
    const uint8_t  pages_used =
        static_cast<uint8_t>((total_with_header + 0xFFu) >> 8);
    uint8_t next_page = nic_current_ + pages_used;

    if (next_page >= nic_page_stop_) {
        next_page = nic_page_start_ + (next_page - nic_page_stop_);
    }

    /* Overflow check: if NextPage would cross NIC_BOUNDARY, drop
       the frame and raise OVERFLOW. The driver's BOUNDARY tracks
       the oldest unread page; overlapping it would clobber unread
       data. */
    if (nic_boundary_ != nic_current_) {
        if ((next_page > nic_current_ && nic_boundary_ > nic_current_
                                      && nic_boundary_ <= next_page) ||
            (next_page < nic_current_ && (nic_boundary_ > nic_current_ ||
                                          nic_boundary_ <= next_page))) {
            RaiseInterruptLocked(kIsrOverflowBit);
            return;
        }
    }

    /* Copy: 4-byte header at CardRAM[NIC_CURRENT << 8 - kRamBase],
       then frame bytes. If the copy crosses the ring wrap point
       (between NIC_PAGE_STOP and NIC_PAGE_START), split into two
       memcpys. */
    const uint32_t start_off = (uint32_t)nic_current_ * 256u - kRamBase;
    const uint32_t stop_off  = (uint32_t)nic_page_stop_ * 256u - kRamBase;

    auto write_into_ring = [&](uint32_t off, const uint8_t* src, std::size_t n) {
        const uint32_t first = (off + n <= stop_off)
                               ? static_cast<uint32_t>(n)
                               : (stop_off - off);
        std::memcpy(card_ram_.data() + off, src, first);
        if (first < n) {
            const uint32_t wrap_off =
                (uint32_t)nic_page_start_ * 256u - kRamBase;
            std::memcpy(card_ram_.data() + wrap_off,
                        src + first, n - first);
        }
    };

    const uint8_t header[4] = {
        kRsrPacketOk,
        next_page,
        static_cast<uint8_t>(total_with_header & 0xFFu),
        static_cast<uint8_t>(total_with_header >> 8),
    };
    write_into_ring(start_off, header, 4);
    /* Frame bytes go in immediately after the header; the wrap math
       in write_into_ring handles a crossing here too. */
    uint32_t body_off = start_off + 4u;
    if (body_off >= stop_off) {
        body_off = (uint32_t)nic_page_start_ * 256u - kRamBase
                 + (body_off - stop_off);
    }
    write_into_ring(body_off, frame, len);

    nic_current_ = next_page;
    nic_rcv_status_ = kRsrPacketOk;
    MarkRx();
    RaiseInterruptLocked(kIsrRcvBit);
}

std::wstring Rtl8019::Tooltip() const {
    wchar_t buf[64];
    swprintf_s(buf, L"PCMCIA #1 — Ethernet  %02X:%02X:%02X:%02X:%02X:%02X",
               guest_mac_[0], guest_mac_[1], guest_mac_[2],
               guest_mac_[3], guest_mac_[4], guest_mac_[5]);
    return buf;
}

std::vector<WidgetMenuItem> Rtl8019::BuildMenu() {
    WidgetMenuItem hdr;
    hdr.label   = L"NE2000 Ethernet (RTL8019)";
    hdr.enabled = false;
    return { std::move(hdr) };
}

bool Rtl8019::IsEnabled() const {
    return emu_.Get<DeviceConfig>().network_enabled;
}

void Rtl8019::DrawIcon(HDC dc, const RECT& box) const {
    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    RECT body = { cx - 8, cy - 6, cx + 8, cy + 6 };

    HBRUSH  fill = CreateSolidBrush(RGB(36, 50, 44));
    HPEN    pen  = CreatePen(PS_SOLID, 1, RGB(150, 160, 150));
    HGDIOBJ ob   = SelectObject(dc, fill);
    HGDIOBJ op   = SelectObject(dc, pen);
    Rectangle(dc, body.left, body.top, body.right, body.bottom);
    /* RJ45 connector notch on the left edge. */
    HBRUSH conn = CreateSolidBrush(RGB(170, 175, 185));
    RECT jack = { body.left - 2, cy - 3, body.left + 2, cy + 3 };
    FillRect(dc, &jack, conn);
    DeleteObject(conn);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(fill);
    DeleteObject(pen);
}

bool Rtl8019::ShouldIndicateMulticastPacketLocked(const uint8_t* dest_mac) const {
    /* Broadcast (FF:FF:FF:FF:FF:FF) is the all-ones special case;
       passes only when RCR_BROADCAST is set. */
    bool is_broadcast = true;
    for (std::size_t i = 0; i < kMacLen; ++i) {
        if (dest_mac[i] != 0xFFu) { is_broadcast = false; break; }
    }
    if (is_broadcast) {
        return (nic_rcv_config_ & kRcrBroadcast) != 0u;
    }

    uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < kMacLen; ++i) {
        uint8_t byte = dest_mac[i];
        for (int b = 0; b < 8; ++b, byte = static_cast<uint8_t>(byte >> 1)) {
            if (((crc ^ byte) & 0x01u) != 0u) {
                crc = (crc >> 1) ^ kCrc32Poly;
            } else {
                crc >>= 1;
            }
        }
    }
    crc &= 0x1FFu;
    return ((nic_mc_addr_[crc >> 3] >> (crc & 7u)) & 0x01u) != 0u;
}

void Rtl8019::TransmitFromCardRamLocked(std::vector<uint8_t>& out_frame) {
    out_frame.clear();
    const uint32_t start = (uint32_t)nic_xmit_start_ * 256u;
    const uint16_t count = nic_xmit_count_;
    if (start < kRamBase || start + count > kRamBase + kRamSize) {
        LOG(Net, "[NE2000] TX dropped (xmit range out of CardRAM)\n");
        nic_command_ &= ~0x04u;  /* clear CR_XMIT (synchronously, on drop) */
        return;
    }
    out_frame.assign(card_ram_.begin() + (start - kRamBase),
                     card_ram_.begin() + (start - kRamBase) + count);
}

REGISTER_SERVICE_AS(Rtl8019, Pd6710Card);
