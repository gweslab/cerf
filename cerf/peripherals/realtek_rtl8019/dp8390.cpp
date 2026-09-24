#include "dp8390.h"

#include "rtl8019.h"

#include "../../core/log.h"
#include "../../state/state_stream.h"

using namespace dp8390;

namespace {

constexpr uint8_t kPageShift = 6;

[[noreturn]] void HaltUnsupported(const char* op, uint32_t offset,
                                  uint8_t page, uint32_t value) {
    LOG(Caution, "[NE2000] %s offset 0x%02X page %u value 0x%X - "
            "unsupported register access; halting\n",
            op, offset, page, value);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

}

Dp8390::Dp8390(Rtl8019& card,
               std::array<uint8_t, kRomSize>& rom,
               std::array<uint8_t, kRamSize>& ram)
    : card_(card), rom_(rom), ram_(ram) {}

void Dp8390::PowerUpLocked() {
    cr_ = 0u;
    pstart_ = 0u; pstop_ = 0u; bnry_ = 0u;
    tsr_ = 0u; tpsr_ = 0u; ncr_ = 0u;
    isr_ = 0u; rcr_ = 0u; tcr_ = 0u; dcr_ = 0u; rsr_ = 0u; imr_ = 0u;
    tbcr_ = 0u; rsar_ = 0u; rbcr_ = 0u; crda_ = 0u;
    cntr0_ = 0u; cntr1_ = 0u; cntr2_ = 0u;
    par_.fill(0);
    mar_.fill(0);
    curr_ = 0u;
    dma_remaining_ = 0u;
    rst_overflow_ = false;
    ResetLocked();
}

void Dp8390::ResetLocked() {
    /* DP8390D datasheet, 1992 National LAN databook, 11.0 p. 1-159:
       reset clears CR TXP,STA and sets RD2,STP; sets ISR RST; clears
       all IMR bits; sets DCR LAS; clears TCR LB1,LB0. */
    cr_  = static_cast<uint8_t>((cr_ & ~(kCrTxp | kCrSta)) | kCrRd2 | kCrStp);
    isr_ |= kIsrRst;
    imr_  = 0u;
    dcr_ |= kDcrLongAddress;
    tcr_ &= static_cast<uint8_t>(~kTcrLoopbackBits);
    dma_remaining_ = 0u;
    RecomputeIrqLocked();
}

/* DP8390D datasheet, 1992 National LAN databook, ISR p. 1-150: "The
   INT signal is active as long as any unmasked signal is set, and
   will not go low until all unmasked bits in this register have been
   cleared"; RST "does not generate an interrupt". */
bool Dp8390::IrqPendingLocked() const {
    return (isr_ & imr_ & 0x7Fu) != 0u;
}

void Dp8390::RecomputeIrqLocked() {
    card_.SetIrqLineLocked(IrqPendingLocked());
}

void Dp8390::RaiseIsrLocked(uint8_t bits) {
    isr_ |= bits;
    RecomputeIrqLocked();
}

/* DP8390D datasheet, 1992 National LAN databook, CNTR2 p. 1-159
   ("incremented if a packet cannot be received due to lack of buffer
   resources", max count 192) and ISR.CNT p. 1-150 ("Set when MSB of
   one or more of the Network Tally Counters has been set"). */
void Dp8390::BumpCntr2Locked() {
    if (cntr2_ < kTallyMax) ++cntr2_;
    if (cntr2_ & 0x80u) RaiseIsrLocked(kIsrCnt);
}

/* QEMU hw/net/ne2000.c ne2000_dma_update - reimplemented model. */
void Dp8390::DmaAdvanceLocked(uint16_t step) {
    crda_ = static_cast<uint16_t>(crda_ + step);
    if (crda_ == static_cast<uint16_t>((uint16_t)pstop_ << 8)) {
        crda_ = static_cast<uint16_t>((uint16_t)pstart_ << 8);
    }
    if (dma_remaining_ <= step) {
        dma_remaining_ = 0u;
        RaiseIsrLocked(kIsrRdc);
    } else {
        dma_remaining_ = static_cast<uint16_t>(dma_remaining_ - step);
    }
}

/* QEMU hw/net/ne2000.c ne2000_mem_readb / ne2000_mem_writeb -
   reimplemented model: the PROM window and the packet RAM window are
   served, everything else reads 0xFF and drops writes. */
uint8_t Dp8390::DmaMemReadLocked(uint16_t addr) const {
    if (addr >= kRamBase && addr < kRamBase + kRamSize) {
        return ram_[addr - kRamBase];
    }
    if (addr < kRomSize) {
        return rom_[addr];
    }
    return PcmciaCard::kBusFloat8;
}

void Dp8390::DmaMemWriteLocked(uint16_t addr, uint8_t value) {
    if (addr >= kRamBase && addr < kRamBase + kRamSize) {
        ram_[addr - kRamBase] = value;
    }
}

uint8_t Dp8390::IoRead8Locked(uint32_t offset) {
    const uint8_t page = (cr_ >> kPageShift) & 0x3u;

    if (offset == 0x00u) return cr_;

    if (offset == 0x10u) {
        /* QEMU hw/net/ne2000.c ne2000_asic_ioport_read - reimplemented
           model: the read side carries no byte-count guard. */
        const uint8_t value = DmaMemReadLocked(crda_);
        DmaAdvanceLocked((dcr_ & kDcrWts) ? 2u : 1u);
        return value;
    }

    if (offset == 0x1Fu) {
        /* QEMU hw/net/ne2000.c ne2000_reset_ioport_read - reimplemented
           model: a read of the reset port performs the reset. */
        ResetLocked();
        return 0u;
    }

    if (page == 0u) {
        /* DP8390D datasheet, 1992 National LAN databook, page 0 read
           column p. 1-147. */
        switch (offset) {
            case 0x03u: return bnry_;
            case 0x04u: return tsr_;
            case 0x05u: return ncr_;
            case 0x07u: return isr_;
            case 0x08u: return static_cast<uint8_t>(crda_ & 0xFFu);
            case 0x09u: return static_cast<uint8_t>(crda_ >> 8);
            case 0x0Cu: return rsr_;
            /* DP8390D datasheet, 1992 National LAN databook, tally
               counters p. 1-159: "cleared when read by the CPU". */
            case 0x0Du: { const uint8_t v = cntr0_; cntr0_ = 0u; return v; }
            case 0x0Eu: { const uint8_t v = cntr1_; cntr1_ = 0u; return v; }
            case 0x0Fu: { const uint8_t v = cntr2_; cntr2_ = 0u; return v; }
            default: HaltUnsupported("read", offset, page, 0);
        }
    }
    if (page == 1u) {
        /* DP8390D datasheet, 1992 National LAN databook, page 1
           assignments p. 1-147. */
        if (offset >= 0x01u && offset <= 0x06u) return par_[offset - 1u];
        if (offset == 0x07u) return curr_;
        if (offset >= 0x08u && offset <= 0x0Fu) return mar_[offset - 8u];
    }
    HaltUnsupported("read", offset, page, 0);
}

uint16_t Dp8390::IoRead16Locked(uint32_t offset) {
    if (offset != 0x10u) {
        LOG(Caution, "[NE2000] read16 unsupported offset 0x%02X; "
                "halting\n", offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    /* QEMU hw/net/ne2000.c ne2000_asic_ioport_read (no byte-count
       guard on the read side) + ne2000_mem_readw (addr &= ~1). */
    const uint16_t base = crda_ & static_cast<uint16_t>(~uint16_t{1});
    const uint16_t value =
        static_cast<uint16_t>(DmaMemReadLocked(base)) |
        (static_cast<uint16_t>(
             DmaMemReadLocked(static_cast<uint16_t>(base + 1u))) << 8);
    DmaAdvanceLocked(2u);
    return value;
}

void Dp8390::IoWrite8Locked(uint32_t offset, uint8_t value,
                            std::vector<uint8_t>& tx_pending) {
    const uint8_t page = (cr_ >> kPageShift) & 0x3u;

    if (offset == 0x00u) {
        /* DP8390D datasheet, 1992 National LAN databook, CR p. 1-149;
           its STP note: "If the NIC has previously been in start mode
           and the STP is set, both the STP and STA bits will remain
           set". */
        const bool was_started = (cr_ & kCrSta) != 0u;
        cr_ = value;
        if ((value & kCrStp) && was_started) {
            cr_ |= kCrSta;
        }
        if (value & kCrStp) {
            isr_ |= kIsrRst;
            RecomputeIrqLocked();
        } else if (value & kCrSta) {
            /* p. 1-150 ISR.RST: "cleared when a Start Command is
               issued to the CR". */
            isr_ &= static_cast<uint8_t>(~kIsrRst);
            rst_overflow_ = false;
            RecomputeIrqLocked();
        }
        const uint8_t rd = (value >> 3) & 0x7u;
        switch (rd) {
            case 0u:
                /* QEMU hw/net/ne2000.c ne2000_ioport_write -
                   reimplemented model: a remote DMA starts only on the
                   RREAD/RWRITE bits. */
                break;
            case 1u:
            case 2u:
                crda_          = rsar_;
                dma_remaining_ = rbcr_;
                /* QEMU hw/net/ne2000.c ne2000_ioport_write -
                   reimplemented model: a remote DMA command with a zero
                   byte count completes immediately. */
                if (dma_remaining_ == 0u) RaiseIsrLocked(kIsrRdc);
                break;
            case 3u:
                LOG(Caution, "[NE2000] CR=0x%02X Send Packet command "
                        "unimplemented; halting\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            default:
                /* p. 1-149: RD2 set aborts/completes remote DMA. */
                dma_remaining_ = 0u;
                break;
        }
        if (value & kCrTxp) {
            /* p. 1-149 TXP note: "Before the transmit command is
               given, the STA bit must be set and the STP bit reset". */
            if (!(value & kCrSta) || (value & kCrStp)) {
                LOG(Caution, "[NE2000] CR=0x%02X TXP without STA (or "
                        "with STP); halting\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            if (tbcr_ == 0u) {
                LOG(Caution, "[NE2000] CR=0x%02X TXP with TBCR=0; "
                        "halting\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            /* p. 1-159: "The NCR is cleared after the TXP bit in the CR
               is set"; p. 1-154: TSR "is cleared when the next
               transmission is initiated". */
            ncr_ = 0u;
            tsr_ = 0u;
            const bool loopback = !(dcr_ & kDcrLoopbackSelect) ||
                                  (tcr_ & kTcrLoopbackBits) != 0u;
            if (loopback) {
                cr_ &= static_cast<uint8_t>(~kCrTxp);
                tsr_ = 0x01u;
                RaiseIsrLocked(kIsrPtx);
            } else {
                TransmitLocked(tx_pending);
            }
        }
        return;
    }

    if (offset == 0x10u) {
        if (dma_remaining_ == 0u) return;
        if (dcr_ & kDcrWts) {
            /* QEMU hw/net/ne2000.c:523-525 ne2000_asic_ioport_write -
               a word-mode data-port write stores the full 16-bit value
               (le16: an 8-bit write stores 0 in the high byte). */
            DmaMemWriteLocked(crda_, value);
            DmaMemWriteLocked(static_cast<uint16_t>(crda_ + 1u), 0u);
            DmaAdvanceLocked(2u);
        } else {
            DmaMemWriteLocked(crda_, value);
            DmaAdvanceLocked(1u);
        }
        return;
    }

    if (offset == 0x1Fu) {
        /* QEMU hw/net/ne2000.c ne2000_reset_ioport_write - reimplemented
           model: "nothing to do (end of reset pulse)". */
        return;
    }

    if (page == 0u) {
        /* DP8390D datasheet, 1992 National LAN databook, page 0 write
           column p. 1-147. */
        switch (offset) {
            case 0x01u: pstart_ = value; return;
            case 0x02u: pstop_  = value; return;
            case 0x03u:
                bnry_ = value;
                /* p. 1-150 ISR.RST: the ring-overflow instance "is
                   cleared when one or more packets have been removed
                   from the ring". */
                if (rst_overflow_) {
                    rst_overflow_ = false;
                    isr_ &= static_cast<uint8_t>(~kIsrRst);
                    RecomputeIrqLocked();
                }
                return;
            case 0x04u: tpsr_   = value; return;
            case 0x05u:
                tbcr_ = static_cast<uint16_t>((tbcr_ & 0xFF00u) | value);
                return;
            case 0x06u:
                tbcr_ = static_cast<uint16_t>((tbcr_ & 0x00FFu) |
                                              ((uint16_t)value << 8));
                return;
            case 0x07u:
                /* p. 1-150: "Individual interrupt bits are cleared by
                   writing a 1 into the corresponding bit"; RST "Writing
                   to this bit has no effect". */
                isr_ &= static_cast<uint8_t>(~(value & 0x7Fu));
                RecomputeIrqLocked();
                return;
            case 0x08u:
                rsar_ = static_cast<uint16_t>((rsar_ & 0xFF00u) | value);
                return;
            case 0x09u:
                rsar_ = static_cast<uint16_t>((rsar_ & 0x00FFu) |
                                              ((uint16_t)value << 8));
                return;
            case 0x0Au:
                rbcr_ = static_cast<uint16_t>((rbcr_ & 0xFF00u) | value);
                return;
            case 0x0Bu:
                rbcr_ = static_cast<uint16_t>((rbcr_ & 0x00FFu) |
                                              ((uint16_t)value << 8));
                return;
            case 0x0Cu:
                if (value & (kRcrSaveErrored | kRcrAcceptRunt)) {
                    LOG(Caution, "[NE2000] RCR=0x%02X SEP/AR "
                            "unimplemented; halting\n", value);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
                rcr_ = value;
                /* DP8390D datasheet, 1992 National LAN databook,
                   RSR.DIS p. 1-156: set when the receiver is disabled
                   by entering monitor mode, reset on exit. */
                if (value & kRcrMonitor) rsr_ |= kRsrDis;
                else                     rsr_ &= static_cast<uint8_t>(~kRsrDis);
                return;
            case 0x0Du:
                if (value & (kTcrAtd | kTcrOfst)) {
                    LOG(Caution, "[NE2000] TCR=0x%02X ATD/OFST "
                            "unimplemented; halting\n", value);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
                tcr_ = value;
                return;
            case 0x0Eu:
                if (value & kDcrBos) {
                    LOG(Caution, "[NE2000] DCR=0x%02X BOS byte-swap "
                            "unimplemented; halting\n", value);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
                dcr_ = value;
                return;
            case 0x0Fu:
                /* DP8390D datasheet, 1992 National LAN databook, IMR
                   p. 1-151: D7 reserved. */
                imr_ = value & 0x7Fu;
                RecomputeIrqLocked();
                return;
            default: HaltUnsupported("write", offset, page, value);
        }
    }
    if (page == 1u) {
        if (offset >= 0x01u && offset <= 0x06u) {
            par_[offset - 1u] = value;
            return;
        }
        if (offset == 0x07u) {
            curr_ = value;
            return;
        }
        if (offset >= 0x08u && offset <= 0x0Fu) {
            mar_[offset - 8u] = value;
            return;
        }
    }
    HaltUnsupported("write", offset, page, value);
}

void Dp8390::IoWrite16Locked(uint32_t offset, uint16_t value) {
    if (offset != 0x10u) {
        LOG(Caution, "[NE2000] write16 unsupported offset 0x%02X = "
                "0x%04X; halting\n", offset, value);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (dma_remaining_ == 0u) return;
    const uint16_t base = crda_ & static_cast<uint16_t>(~uint16_t{1});
    DmaMemWriteLocked(base, static_cast<uint8_t>(value & 0xFFu));
    DmaMemWriteLocked(static_cast<uint16_t>(base + 1u),
                      static_cast<uint8_t>(value >> 8));
    DmaAdvanceLocked(2u);
}

void Dp8390::TransmitLocked(std::vector<uint8_t>& out_frame) {
    out_frame.clear();
    const uint32_t start = (uint32_t)tpsr_ * 256u;
    const uint16_t count = tbcr_;
    if (start < kRamBase || start + count > kRamBase + kRamSize) {
        LOG(Caution, "[NE2000] TX with TPSR=0x%02X TBCR=0x%04X outside "
                "card RAM; halting\n", tpsr_, count);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    out_frame.assign(ram_.begin() + (start - kRamBase),
                     ram_.begin() + (start - kRamBase) + count);
}

void Dp8390::CompleteTxLocked() {
    cr_ &= static_cast<uint8_t>(~kCrTxp);
    /* DP8390D datasheet, 1992 National LAN databook, TSR.PTX
       p. 1-154. */
    tsr_ = 0x01u;
    RaiseIsrLocked(kIsrPtx);
}

void Dp8390::SaveState(StateWriter& w) {
    w.Write("cr", cr_);
    w.Write("pstart", pstart_); w.Write("pstop", pstop_); w.Write("bnry", bnry_);
    w.Write("tsr", tsr_); w.Write("tpsr", tpsr_); w.Write("ncr", ncr_);
    w.Write("isr", isr_); w.Write("rcr", rcr_); w.Write("tcr", tcr_); w.Write("dcr", dcr_);
    w.Write("rsr", rsr_); w.Write("imr", imr_);
    w.Write("tbcr", tbcr_); w.Write("rsar", rsar_); w.Write("rbcr", rbcr_); w.Write("crda", crda_);
    w.Write("cntr0", cntr0_); w.Write("cntr1", cntr1_); w.Write("cntr2", cntr2_);
    w.WriteBytes("par", par_.data(), par_.size());
    w.WriteBytes("mar", mar_.data(), mar_.size());
    w.Write("curr", curr_);
    w.Write("dma_remaining", dma_remaining_);
    w.Write("rst_overflow", rst_overflow_);
}

void Dp8390::RestoreState(StateReader& r) {
    r.Read("cr", cr_);
    r.Read("pstart", pstart_); r.Read("pstop", pstop_); r.Read("bnry", bnry_);
    r.Read("tsr", tsr_); r.Read("tpsr", tpsr_); r.Read("ncr", ncr_);
    r.Read("isr", isr_); r.Read("rcr", rcr_); r.Read("tcr", tcr_); r.Read("dcr", dcr_);
    r.Read("rsr", rsr_); r.Read("imr", imr_);
    r.Read("tbcr", tbcr_); r.Read("rsar", rsar_); r.Read("rbcr", rbcr_); r.Read("crda", crda_);
    r.Read("cntr0", cntr0_); r.Read("cntr1", cntr1_); r.Read("cntr2", cntr2_);
    r.ReadBytes("par", par_.data(), par_.size());
    r.ReadBytes("mar", mar_.data(), mar_.size());
    r.Read("curr", curr_);
    r.Read("dma_remaining", dma_remaining_);
    r.Read("rst_overflow", rst_overflow_);
}
