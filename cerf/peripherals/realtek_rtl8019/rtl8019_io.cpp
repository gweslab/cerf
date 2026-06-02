#include "rtl8019.h"

#include "../cirrus_pd6710/pd6710_controller.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../net/network_backend.h"

#include <cstring>
#include <vector>

namespace {

constexpr uint8_t kCrStop      = 0x01;
constexpr uint8_t kCrStart     = 0x02;
constexpr uint8_t kCrXmit      = 0x04;
constexpr uint8_t kCrDmaRead   = 0x08;
constexpr uint8_t kCrDmaWrite  = 0x10;
constexpr uint8_t kCrNoDma     = 0x20;

constexpr uint8_t kPageMask    = 0xC0;
constexpr uint8_t kPageShift   = 6;

/* NIC_DATA_CONFIG bits (DCR). */
constexpr uint8_t kDcrWordWide = 0x01;

constexpr uint8_t kIsrXmitBit     = 0x02;
constexpr uint8_t kIsrDmaDoneBit  = 0x40;
constexpr uint8_t kIsrResetBit    = 0x80;

/* Card RAM live at card-memory offset kRamBase, 16 KB. The DMA
   wrap target is NIC_PAGE_START * 256 (page→byte conversion). */
constexpr uint32_t kRamBase = 0x4000;
constexpr uint32_t kRamSize = 0x4000;

/* Card ROM is 32 bytes at card-memory offset 0. Driver may read
   it through the DMA path when DMAOffset < 32. */
constexpr uint32_t kRomSize = 32;

uint8_t PageOf(uint8_t cmd) {
    return (cmd & kPageMask) >> kPageShift;
}

[[noreturn]] void HaltUnsupported(const char* op, uint32_t offset,
                                  uint8_t page, uint32_t value) {
    LOG(Caution, "[NE2000] %s offset 0x%02X page %u value 0x%X — "
            "unsupported register access; halting (matches host "
            "runtime TerminateWithMessage behavior)\n",
            op, offset, page, value);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

}  /* namespace */

uint8_t Rtl8019::ReadByte(uint32_t offset) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const uint8_t page = PageOf(nic_command_);

    switch (offset) {
        case 0x00: return nic_command_;

        case 0x01:
            if (page == 1) return nic_phys_addr_[0];
            HaltUnsupported("read", offset, page, 0);

        case 0x02:
            if (page == 1) return nic_phys_addr_[1];
            HaltUnsupported("read", offset, page, 0);

        case 0x03:
            if (page == 0) return nic_boundary_;
            if (page == 1) return nic_phys_addr_[2];
            HaltUnsupported("read", offset, page, 0);

        case 0x04:
            if (page == 0) return nic_xmit_status_;
            if (page == 1) return nic_phys_addr_[3];
            HaltUnsupported("read", offset, page, 0);

        case 0x05:
            if (page == 1) return nic_phys_addr_[4];
            HaltUnsupported("read", offset, page, 0);

        case 0x06:
            if (page == 0) return nic_fifo_;
            if (page == 1) return nic_phys_addr_[5];
            HaltUnsupported("read", offset, page, 0);

        case 0x07:
            if (page == 0) {
                /* Reset polling loop: when CR_STOP is set and ISR_RESET
                   is clear, the driver's CardInitialize() spins waiting
                   for ISR_RESET to come back. Re-set it here. */
                if ((nic_command_ & kCrStop) &&
                    (nic_intr_status_ & kIsrResetBit) == 0u) {
                    nic_intr_status_ |= kIsrResetBit;
                }
                return nic_intr_status_;
            }
            if (page == 1) return nic_current_;
            HaltUnsupported("read", offset, page, 0);

        case 0x08:
            if (page == 0) return static_cast<uint8_t>(nic_crda_ & 0xFFu);
            if (page == 1) return nic_mc_addr_[0];
            HaltUnsupported("read", offset, page, 0);

        case 0x09:
            if (page == 0) return static_cast<uint8_t>(nic_crda_ >> 8);
            if (page == 1) return nic_mc_addr_[1];
            HaltUnsupported("read", offset, page, 0);

        case 0x0A:
            if (page == 1) return nic_mc_addr_[2];
            HaltUnsupported("read", offset, page, 0);

        case 0x0B:
            if (page == 1) return nic_mc_addr_[3];
            HaltUnsupported("read", offset, page, 0);

        case 0x0C:
            if (page == 0) return nic_rcv_status_;
            if (page == 1) return nic_mc_addr_[4];
            HaltUnsupported("read", offset, page, 0);

        case 0x0D:
            if (page == 0) return nic_fae_err_;
            if (page == 1) return nic_mc_addr_[5];
            HaltUnsupported("read", offset, page, 0);

        case 0x0E:
            if (page == 0) return nic_crc_err_;
            if (page == 1) return nic_mc_addr_[6];
            HaltUnsupported("read", offset, page, 0);

        case 0x0F:
            if (page == 0) return nic_missed_cnt_;
            if (page == 1) return nic_mc_addr_[7];
            HaltUnsupported("read", offset, page, 0);

        case 0x10: {
            /* NIC_RACK_NIC byte-wide DMA read. Driver set up
               NIC_RMT_ADDR + NIC_RMT_COUNT + CR_DMA_READ; we
               stream bytes from card RAM (or card ROM if the
               address falls in the first 32 bytes). */
            if (dma_count_ == 0u) return 0u;
            uint8_t value = 0u;
            if (dma_offset_ >= kRamBase && dma_offset_ < kRamBase + kRamSize) {
                value = card_ram_[dma_offset_ - kRamBase];
            } else if (dma_offset_ < kRomSize) {
                const uint16_t i = (nic_data_config_ & kDcrWordWide)
                                   ? (dma_offset_ & ~uint16_t{1})
                                   : dma_offset_;
                value = card_rom_[i];
            }
            const uint16_t step = (nic_data_config_ & kDcrWordWide) ? 2u : 1u;
            dma_count_  -= step;
            dma_offset_ += step;
            if (dma_count_ == 0u) {
                RaiseInterruptLocked(kIsrDmaDoneBit);
            }
            if (dma_offset_ >= (uint16_t)nic_page_stop_ * 256u) {
                dma_offset_ = (uint16_t)nic_page_start_ * 256u +
                              (dma_offset_ - (uint16_t)nic_page_stop_ * 256u);
            }
            return value;
        }

        case 0x1F:  /* NIC_RESET: read returns 0 */
            return 0u;

        default:
            HaltUnsupported("read", offset, page, 0);
    }
}

uint16_t Rtl8019::ReadHalf(uint32_t offset) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (offset != 0x10) {
        LOG(Caution, "[NE2000] read16 unsupported offset 0x%02X — only "
                "NIC_RACK_NIC supports 16-bit reads; halting\n", offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    /* 16-bit DMA read from NIC_RACK_NIC. */
    if (dma_count_ == 0u) return 0u;
    uint16_t value = 0u;
    if (dma_offset_ >= kRamBase && dma_offset_ < kRamBase + kRamSize) {
        const uint32_t off = dma_offset_ - kRamBase;
        value = static_cast<uint16_t>(card_ram_[off]) |
                (static_cast<uint16_t>(card_ram_[off + 1]) << 8);
    } else if (dma_offset_ < kRomSize) {
        const uint16_t i = (nic_data_config_ & kDcrWordWide)
                           ? (dma_offset_ & ~uint16_t{1})
                           : dma_offset_;
        value = static_cast<uint16_t>(card_rom_[i]) |
                (static_cast<uint16_t>(card_rom_[i + 1]) << 8);
    }
    dma_count_  -= 2u;
    dma_offset_ += 2u;
    if (dma_count_ == 0u) RaiseInterruptLocked(kIsrDmaDoneBit);
    if (dma_offset_ >= (uint16_t)nic_page_stop_ * 256u) {
        dma_offset_ = (uint16_t)nic_page_start_ * 256u +
                      (dma_offset_ - (uint16_t)nic_page_stop_ * 256u);
    }
    return value;
}

void Rtl8019::WriteByte(uint32_t offset, uint8_t value) {
    std::vector<uint8_t> tx_pending;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint8_t old_command = nic_command_;
        const uint8_t page = PageOf(nic_command_);

        switch (offset) {
            case 0x00: {
                nic_command_ = value;
                if (nic_command_ & kCrStart) {
                    if ((old_command & kCrStop) && (nic_command_ & kCrStop) == 0u) {
                        /* Exiting reset — NetworkBackend RX callback
                           is already installed, no kickoff needed
                           (slirp poll thread runs continuously). */
                    }
                    if (nic_command_ & kCrNoDma) {
                        dma_count_ = 0u;
                    }
                    if (nic_command_ & kCrXmit) {
                        /* Clear TSR at TX start (host-runtime
                           pattern — TSR is left at 0 throughout;
                           completion is signaled by ISR_XMIT only). */
                        nic_xmit_status_ = 0u;
                        const bool loopback =
                            (nic_data_config_ & 0x08u) == 0u ||
                            (nic_xmit_config_ & 0x02u) != 0u;  /* DCR_NORMAL clear or TCR_NIC_LBK set */
                        if (!loopback) {
                            TransmitFromCardRamLocked(tx_pending);
                        } else {
                            /* Loopback configured — silently complete
                               without going to the wire. */
                            nic_command_ &= ~kCrXmit;
                            RaiseInterruptLocked(kIsrXmitBit);
                        }
                    }
                    if (nic_command_ & (kCrDmaRead | kCrDmaWrite)) {
                        dma_count_  = nic_rmt_count_;
                        dma_offset_ = nic_rmt_addr_;
                    }
                }
                if (nic_command_ & kCrStop) {
                    nic_intr_status_ &= ~kIsrResetBit;
                    RaiseInterruptLocked(kIsrResetBit);
                }
                break;
            }

            case 0x01:
                if (page == 0)      nic_page_start_   = value;
                else if (page == 1) nic_phys_addr_[0] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x02:
                if (page == 0)      nic_page_stop_    = value;
                else if (page == 1) nic_phys_addr_[1] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x03:
                if (page == 0) {
                    nic_intr_status_ &= ~kIsrResetBit;
                    nic_boundary_ = value;
                } else if (page == 1) {
                    nic_phys_addr_[2] = value;
                } else {
                    HaltUnsupported("write", offset, page, value);
                }
                break;

            case 0x04:
                if (page == 0)      nic_xmit_start_   = value;
                else if (page == 1) nic_phys_addr_[3] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x05:
                if (page == 0)      nic_xmit_count_   = (nic_xmit_count_ & 0xFF00u) | value;
                else if (page == 1) nic_phys_addr_[4] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x06:
                if (page == 0)      nic_xmit_count_   = (nic_xmit_count_ & 0x00FFu) |
                                                        (static_cast<uint16_t>(value) << 8);
                else if (page == 1) nic_phys_addr_[5] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x07:
                if (page == 0) {
                    nic_intr_status_ &= ~value;  /* W1C — ack */
                    ClearInterruptIfDrainedLocked();
                } else if (page == 1) {
                    nic_current_ = value;
                } else {
                    HaltUnsupported("write", offset, page, value);
                }
                break;

            case 0x08:
                if (page == 0)      nic_rmt_addr_   = (nic_rmt_addr_ & 0xFF00u) | value;
                else if (page == 1) nic_mc_addr_[0] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x09:
                if (page == 0)      nic_rmt_addr_   = (nic_rmt_addr_ & 0x00FFu) |
                                                      (static_cast<uint16_t>(value) << 8);
                else if (page == 1) nic_mc_addr_[1] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x0A:
                if (page == 0)      nic_rmt_count_  = (nic_rmt_count_ & 0xFF00u) | value;
                else if (page == 1) nic_mc_addr_[2] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x0B:
                if (page == 0)      nic_rmt_count_  = (nic_rmt_count_ & 0x00FFu) |
                                                      (static_cast<uint16_t>(value) << 8);
                else if (page == 1) nic_mc_addr_[3] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x0C:
                if (page == 0)      nic_rcv_config_ = value;
                else if (page == 1) nic_mc_addr_[4] = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x0D:
                if (page == 0)      nic_xmit_config_ = value;
                else if (page == 1) nic_mc_addr_[5]  = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x0E:
                if (page == 0)      nic_data_config_ = value;
                else if (page == 1) nic_mc_addr_[6]  = value;
                else                HaltUnsupported("write", offset, page, value);
                break;

            case 0x0F:
                if (page == 0) {
                    nic_intr_mask_ = value;
                    if (nic_intr_mask_ & nic_intr_status_) {
                        if (pd_) pd_->RaiseCardIrq();
                    } else {
                        if (pd_) pd_->ClearCardIrq();
                    }
                } else if (page == 1) {
                    nic_mc_addr_[7] = value;
                } else {
                    HaltUnsupported("write", offset, page, value);
                }
                break;

            case 0x10: {
                if (dma_count_ == 0u) break;
                if (dma_offset_ >= kRamBase && dma_offset_ < kRamBase + kRamSize) {
                    card_ram_[dma_offset_ - kRamBase] = value;
                }
                const uint16_t step = (nic_data_config_ & kDcrWordWide) ? 2u : 1u;
                dma_count_  -= step;
                dma_offset_ += step;
                if (dma_count_ == 0u) RaiseInterruptLocked(kIsrDmaDoneBit);
                if (dma_offset_ >= (uint16_t)nic_page_stop_ * 256u) {
                    dma_offset_ = (uint16_t)nic_page_start_ * 256u +
                                  (dma_offset_ - (uint16_t)nic_page_stop_ * 256u);
                }
                break;
            }

            case 0x1F:  /* NIC_RESET — any write triggers chip reset */
                ResetLocked();
                break;

            default:
                HaltUnsupported("write", offset, page, value);
        }
    }
    if (!tx_pending.empty() && net_) {
        net_->SendFrame(tx_pending.data(), tx_pending.size());
        MarkTx();
        std::lock_guard<std::mutex> lk(state_mutex_);
        if ((nic_command_ & kCrStop) == 0u) {
            nic_command_ &= ~kCrXmit;
            RaiseInterruptLocked(kIsrXmitBit);
        }
    }
}

void Rtl8019::WriteHalf(uint32_t offset, uint16_t value) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (offset != 0x10) {
        LOG(Caution, "[NE2000] write16 unsupported offset 0x%02X = 0x%04X — "
                "only NIC_RACK_NIC supports 16-bit writes; halting\n",
                offset, value);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    /* 16-bit DMA write into CardRAM. */
    if (dma_count_ == 0u) return;
    if (dma_offset_ >= kRamBase && dma_offset_ < kRamBase + kRamSize) {
        const uint32_t off = (dma_offset_ & ~uint16_t{1}) - kRamBase;
        card_ram_[off]     = static_cast<uint8_t>(value & 0xFFu);
        card_ram_[off + 1] = static_cast<uint8_t>(value >> 8);
    }
    if (dma_count_ <= 2u) {
        dma_count_ = 0u;
        RaiseInterruptLocked(kIsrDmaDoneBit);
    } else {
        dma_count_  -= 2u;
        dma_offset_ += 2u;
        if (dma_offset_ >= (uint16_t)nic_page_stop_ * 256u) {
            dma_offset_ = (uint16_t)nic_page_start_ * 256u +
                          (dma_offset_ - (uint16_t)nic_page_stop_ * 256u);
        }
    }
}
