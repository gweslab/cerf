#include "pxa27x_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"

#include <cstring>

void Pxa27xDma::WriteDcsrLocked(uint32_t ch, uint32_t value) {
    uint32_t cur = dcsr_[ch] & ~(value & kDcsrW1c);
    const bool was_run = (cur & RUN) != 0;
    /* Table 5-18 (page 5-43) "1 = Software (programmed I/O write) cannot modify
       DCSR[RUN] during a write transaction in which DCSR[MaskRun] is 1." */
    const uint32_t rw = (value & MASKRUN) ? (kDcsrRw & ~RUN) : kDcsrRw;
    cur = (cur & ~rw) | (value & rw);
    /* Table 5-18 (page 5-43) "Setting CLRCMPST clears DCSRx[CMPST]"; (page 5-44)
       "If software attempts to concurrently set and clear CMPST by setting both
       DCSRx[SETCMPST] and DCSRx[CLRCMPST], DCSRx[SETCMPST] has higher
       precedence." */
    if (value & CLRCMPST) cur &= ~CMPST;
    if (value & SETCMPST) cur |= CMPST;
    dcsr_[ch] = cur;
    if (!was_run && (cur & RUN)) StartChannelLocked(ch);
    UpdateIrqLocked();
}

/* Table 5-19 (page 5-48) "31:0 R CHLINTRx Channel Interrupt Indicates that DMA
   channel x has been interrupted: 0 = No interrupt / 1 = Interrupt". */
uint32_t Pxa27xDma::Dint() const {
    uint32_t d = 0;
    for (uint32_t ch = 0; ch < kNumChannels; ++ch)
        if (ChannelIrq(ch)) d |= (1u << ch);
    return d;
}

/* Section 5.5.9 (page 5-48) lists the conditions that generate a DMA interrupt. */
bool Pxa27xDma::ChannelIrq(uint32_t ch) const {
    const uint32_t d = dcsr_[ch];
    if (d & (BUSERRINTR | STARTINTR | ENDINTR)) return true;
    /* Section 5.5.9 (page 5-48) "DCSRx[EORIRQEN] is set and DCSRx[EORINT] is set
       (EOR signaled by a peripheral)." */
    if ((d & EORINT) && (d & EORIRQEN)) return true;
    /* Section 5.5.9 (page 5-48) "DCSRx[RASIrqEn] is set and the peripheral makes
       a DMA request after the channel has stopped." */
    if ((d & RASINTR) && (d & RASIRQEN)) return true;
    /* Section 5.5.9 (page 5-48) "DCSRx[STOPERQEN] is set and the channel is in an
       uninitialized or stopped state." */
    return !(d & RUN) && (d & STOPIRQEN);
}

void Pxa27xDma::UpdateIrqLocked() {
    bool any = false;
    for (uint32_t ch = 0; ch < kNumChannels && !any; ++ch) any = ChannelIrq(ch);
    auto& intc = emu_.Get<IrqController>();
    if (any) intc.AssertIrq  (static_cast<int>(kIntcDmaBit));
    else     intc.DeAssertIrq(static_cast<int>(kIntcDmaBit));
}

/* Table 5-5 (page 5-6) "Set DCSRx[Run] after writing to DDADRx (recommended
   flow). 1 0 Descriptor fetch, running." */
void Pxa27xDma::StartChannelLocked(uint32_t ch) {
    LOG(SocDma, "ch%u RUN DDADR=0x%08X DCSR=0x%08X nodesc=%u\n", ch, ddadr_[ch],
        dcsr_[ch], (dcsr_[ch] & NODESCFETCH) ? 1u : 0u);
    RunChannelSyncLocked(ch);
}

/* Table 5-12 (page 5-32) "If both DDADRx[BREN] and DCSRx[CMPST] are set, the DMA
   controller fetches the next descriptor from (DDADRx + 32 bytes). If either of
   the bits is cleared, DMA controller fetches the next descriptor from the
   DDADRx register." */
uint32_t Pxa27xDma::DescriptorAddressLocked(uint32_t ch) const {
    const uint32_t base = ddadr_[ch] & kDescAddrMask;
    if ((ddadr_[ch] & DDADR_BREN) && (dcsr_[ch] & CMPST)) return base + kBranchOffset;
    return base;
}

/* Table 5-20 (page 5-49) "0 = Source and target addresses of channel x are
   default aligned (internal peripherals default to 4 byte alignment; external bus
   addresses default to 8 byte alignment). 1 = Source and target addresses of
   channel x are as defined by user (byte-aligned)." */
uint32_t Pxa27xDma::AlignBaseLocked(uint32_t ch, uint32_t pa) {
    if (dalgn_ & (1u << ch)) return pa;
    const bool peripheral = emu_.Get<PeripheralDispatcher>().IsPeripheralAddress(pa);
    return pa & (peripheral ? kAlignPeripheral : kAlignExternal);
}

/* Section 5.4.2 (page 5-7) "A DMA descriptor is a four-word (32-bit) block,
   aligned on a 16-byte boundary in memory: Word [0] contains a value for the
   DDADRx register and a single flag bit (STOP). Word [1] contains a value for the
   DSADRx register. Word [2] ... DTADRx ... Word [3] ... DCMDx register." */
void Pxa27xDma::RunChannelSyncLocked(uint32_t ch) {
    uint32_t n = 0;
    for (; n < kMaxDescriptors; ++n) {
        if (!(dcsr_[ch] & RUN)) break;
        const bool nodesc = (dcsr_[ch] & NODESCFETCH) != 0;
        if (!nodesc) {
            /* Table 5-12 (page 5-32) "1 = Stop channel after completely processing
               this descriptor and before fetching the next descriptor". */
            if (ddadr_[ch] & DDADR_STOP) break;
            const uint32_t desc = DescriptorAddressLocked(ch);
            uint32_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
            if (!ReadPhys32(desc, &w0) || !ReadPhys32(desc + 0x4u, &w1) ||
                !ReadPhys32(desc + 0x8u, &w2) || !ReadPhys32(desc + 0xCu, &w3)) {
                dcsr_[ch] |= BUSERRINTR;
                break;
            }
            ddadr_[ch] = w0 & kDdadrMask;
            dsadr_[ch] = w1;
            dtadr_[ch] = w2;
            dcmd_[ch]  = w3 & kDcmdMask;
            /* Table 5-15 (page 5-37) "1 = Set interrupt bit for that channel in
               the DINT[CHLINTR] when the descriptor (4 words) for the channel is
               loaded."; "In no-descriptor-fetch transfers, this bit is reserved." */
            if (dcmd_[ch] & STARTIRQEN) dcsr_[ch] |= STARTINTR;
        }
        if (dcmd_[ch] & CMPEN) {
            if (!RunCompareLocked(ch)) { dcsr_[ch] |= BUSERRINTR; break; }
            if (nodesc) break;
            continue;
        }
        if ((dcmd_[ch] & kDcmdLengthMask) == 0) {
            /* Table 5-15 (page 5-38) "LEN = 0 is an invalid setting for
               no-descriptor-fetch transactions." */
            if (nodesc) {
                LOG(Caution, "Pxa27xDma: ch%u no-descriptor-fetch with DCMD[LEN]=0 "
                    "(DCMD=0x%08X) - stopping\n", ch, dcmd_[ch]);
                break;
            }
            /* Table 5-15 (page 5-38) "Programming LEN = 0 in the descriptor-fetch
               mode when DCMD[CmpEn] is clear ... causes the channel to immediately
               discard the descriptor after it is fetched from memory." */
            continue;
        }
        if (!RunTransfer(ch)) { dcsr_[ch] |= BUSERRINTR; break; }
        dcmd_[ch] &= ~kDcmdLengthMask;
        /* Table 5-15 (page 5-37) "1 = Set the DINT interrupt bit for the channel
           when LENGTH decrements to zero." */
        if (dcmd_[ch] & ENDIRQEN) dcsr_[ch] |= ENDINTR;
        if (nodesc) break;
    }
    if (n == kMaxDescriptors)
        LOG(Caution, "Pxa27xDma: ch%u chain exceeded %u descriptors (last DSADR=0x%08X "
            "DTADR=0x%08X DCMD=0x%08X DDADR=0x%08X) - stopping\n", ch, kMaxDescriptors,
            dsadr_[ch], dtadr_[ch], dcmd_[ch], ddadr_[ch]);
    /* Table 5-18 (page 5-45) "1 = The channel is in uninitialized or stopped
       state." */
    dcsr_[ch] &= ~RUN;
}

/* Table 5-15 (page 5-38) "15:14 R/W WIDTH ... 0b00 = reserved for on-chip
   peripheral-related transactions / 0b01 = 1 byte / 0b10 = Half-word (2 bytes) /
   0b11 = Word (4 Bytes)"; "WIDTH must be 0b00 for memory-to-memory moves or
   companion-chip-related operations." */
uint32_t Pxa27xDma::UnitWidth(uint32_t dcmd) {
    switch ((dcmd >> kDcmdWidthShift) & kDcmdWidthMask) {
    case 0x1u: return 1u;
    case 0x2u: return 2u;
    default:   return 4u;
    }
}

/* Table 5-15 (page 5-35) "31 R/W INCSRCADDR Source Address Increment", "30 R/W
   INCTRGADDR Target Address Increment". */
bool Pxa27xDma::RunTransfer(uint32_t ch) {
    const uint32_t len = dcmd_[ch] & kDcmdLengthMask;
    const uint32_t sa = AlignBaseLocked(ch, dsadr_[ch]);
    const uint32_t da = AlignBaseLocked(ch, dtadr_[ch]);
    const bool inc_s = (dcmd_[ch] & INCSRCADDR) != 0;
    const bool inc_t = (dcmd_[ch] & INCTRGADDR) != 0;
    const uint32_t w = UnitWidth(dcmd_[ch]);
    for (uint32_t off = 0; off < len; off += w) {
        const uint32_t s = inc_s ? sa + off : sa;
        const uint32_t t = inc_t ? da + off : da;
        uint32_t unit = 0;
        if (!ReadPhys(s, w, &unit) || !WritePhys(t, w, unit)) return false;
    }
    return true;
}

/* Table 5-15 (page 5-36) "1 = DMA recognizes the current descriptor as a special
   case and compares data based on the source address and target address fields.
   If the compare is true, the channel's DCSRx[CMPST] bit is set. If the compare
   is false, DCSRx[CMPST] is cleared." */
bool Pxa27xDma::RunCompareLocked(uint32_t ch) {
    const uint32_t w = UnitWidth(dcmd_[ch]);
    uint32_t src = 0, trg = dtadr_[ch];
    if (!ReadPhys(AlignBaseLocked(ch, dsadr_[ch]), w, &src)) return false;
    /* Table 5-15 (page 5-36) "0 = Source address field contains address, and
       target address field contains address. 1 = Source address field contains
       address, and target address field contains data." */
    if (!(dcmd_[ch] & ADDRMODE) &&
        !ReadPhys(AlignBaseLocked(ch, dtadr_[ch]), w, &trg))
        return false;
    if (src == trg) dcsr_[ch] |= CMPST;
    else            dcsr_[ch] &= ~CMPST;
    return true;
}

bool Pxa27xDma::ReadPhys32(uint32_t pa, uint32_t* out) { return ReadPhys(pa, 4u, out); }

bool Pxa27xDma::ReadPhys(uint32_t pa, uint32_t width, uint32_t* out) {
    auto& mem = emu_.Get<EmulatedMemory>();
    if (uint8_t* p = mem.TryTranslate(pa)) {
        std::memcpy(out, p, width);
        return true;
    }
    auto& disp = emu_.Get<PeripheralDispatcher>();
    if (!disp.IsPeripheralAddress(pa)) return false;
    *out = (width == 1u) ? disp.ReadByte(pa)
         : (width == 2u) ? disp.ReadHalf(pa) : disp.ReadWord(pa);
    return true;
}

bool Pxa27xDma::WritePhys(uint32_t pa, uint32_t width, uint32_t value) {
    auto& mem = emu_.Get<EmulatedMemory>();
    if (uint8_t* p = mem.TryTranslateWrite(pa)) {
        std::memcpy(p, &value, width);
        return true;
    }
    auto& disp = emu_.Get<PeripheralDispatcher>();
    if (!disp.IsPeripheralAddress(pa)) return false;
    if (width == 1u)      disp.WriteByte(pa, static_cast<uint8_t>(value));
    else if (width == 2u) disp.WriteHalf(pa, static_cast<uint16_t>(value));
    else                  disp.WriteWord(pa, value);
    return true;
}

void Pxa27xDma::PostRestore() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    for (uint32_t ch = 0; ch < kNumChannels; ++ch)
        if (dcsr_[ch] & RUN) StartChannelLocked(ch);
    UpdateIrqLocked();
}
