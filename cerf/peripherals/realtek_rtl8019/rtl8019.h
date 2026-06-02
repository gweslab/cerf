#pragma once

#include "../cirrus_pd6710/pd6710_card.h"
#include "../../host/host_widget.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

class NetworkBackend;
class Pd6710Controller;

class Rtl8019 : public Pd6710Card, public HostWidget {
public:
    using Pd6710Card::Pd6710Card;

    bool ShouldRegister() override;
    void OnReady() override;

    void PowerOn () override;
    void PowerOff() override;

    /* HostWidget. RX = a frame indicated to the guest (OnRxFrame), TX = a
       frame sent to the wire (SendFrame). */
    std::wstring WidgetName() const override { return L"Network"; }
    WidgetGroup  Group() const override { return WidgetGroup::Pcmcia; }
    std::wstring Tooltip() const override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    bool IsEnabled() const override;   /* dimmed when networking is off */

    uint8_t  ReadByte  (uint32_t offset)                       override;
    uint16_t ReadHalf  (uint32_t offset)                       override;
    void     WriteByte (uint32_t offset, uint8_t  value)       override;
    void     WriteHalf (uint32_t offset, uint16_t value)       override;

    uint8_t  ReadMemoryByte  (uint32_t offset)                 override;
    uint16_t ReadMemoryHalf  (uint32_t offset)                 override;
    void     WriteMemoryByte (uint32_t offset, uint8_t  value) override;
    void     WriteMemoryHalf (uint32_t offset, uint16_t value) override;

private:
    void OnRxFrame(const uint8_t* frame, std::size_t len);

    void TransmitFromCardRamLocked(std::vector<uint8_t>& out_frame);

    /* Update NIC_INTR_STATUS + drive the IRQ line. Both methods
       assume the caller holds state_mutex_; they take their own
       brief read of the IRQ mask, then release before calling into
       the Pd6710Controller (which has its own lock). */
    void RaiseInterruptLocked(uint8_t bits);
    void ClearInterruptIfDrainedLocked();

    /* The full NIC_RESET behavior — invoked both by guest writes to
       NIC_RESET (offset 0x1F) and by PowerOn at boot. Resets every
       register to documented power-on defaults, clears CardRAM,
       sets CR_STOP and ISR_RESET. */
    void ResetLocked();

    bool ShouldIndicateMulticastPacketLocked(const uint8_t* dest_mac) const;

    NetworkBackend*   net_ = nullptr;
    Pd6710Controller* pd_  = nullptr;

    /* Cached MAC address taken from NetworkBackend at OnReady. Also
       laid into CardROM so the driver reads it via the CIS path. */
    std::array<uint8_t, 6> guest_mac_{};
    bool first_power_on_done_ = false;

    mutable std::mutex state_mutex_;

    /* NIC_COMMAND register at offset 0 — selects page for offsets
       1..0x0F via bits 6-7. */
    uint8_t nic_command_ = 0u;

    /* Page 0 — control + RX/TX. */
    uint8_t  nic_page_start_  = 0u;
    uint8_t  nic_page_stop_   = 0u;
    uint8_t  nic_boundary_    = 0u;
    uint8_t  nic_xmit_status_ = 0u;
    uint8_t  nic_xmit_start_  = 0u;
    uint16_t nic_xmit_count_  = 0u;
    uint8_t  nic_fifo_        = 0u;
    uint8_t  nic_intr_status_ = 0u;
    uint16_t nic_crda_        = 0u;
    uint16_t nic_rmt_addr_    = 0u;
    uint16_t nic_rmt_count_   = 0u;
    uint8_t  nic_rcv_config_  = 0u;
    uint8_t  nic_rcv_status_  = 0u;
    uint8_t  nic_xmit_config_ = 0u;
    uint8_t  nic_fae_err_     = 0u;
    uint8_t  nic_data_config_ = 0u;
    uint8_t  nic_crc_err_     = 0u;
    uint8_t  nic_intr_mask_   = 0u;
    uint8_t  nic_missed_cnt_  = 0u;

    /* Page 1 — physical MAC + multicast filter + current page. */
    std::array<uint8_t, 6> nic_phys_addr_{};
    std::array<uint8_t, 8> nic_mc_addr_{};
    uint8_t                nic_current_ = 0u;

    /* DMA state for the NIC_RACK_NIC remote-DMA register at offset
       0x10 — driver sets nic_rmt_addr_/nic_rmt_count_ + CR_DMA_*,
       then byte-streams through this register. */
    uint16_t dma_count_  = 0u;
    uint16_t dma_offset_ = 0u;

    /* FCSR (Function Control / Status Register) at card-memory
       offset 0x3FA — PCMCIA function register the driver reads to
       check whether the on-card INT is pending. */
    uint8_t fcsr_ = 0u;

    static constexpr std::size_t kCardRomSize = 32;
    std::array<uint8_t, kCardRomSize> card_rom_{};

    /* On-card RAM at card-memory offset 0x4000, 16 KB. RX writes
       4-byte prefix + frame bytes into here at NIC_CURRENT << 8;
       TX reads from NIC_XMIT_START << 8. */
    static constexpr uint32_t kRamBase = 0x4000u;
    static constexpr uint32_t kRamSize = 0x4000u;
    std::array<uint8_t, kRamSize> card_ram_{};
};
