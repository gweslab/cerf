#include "../pxa2xx/pxa2xx_dma.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "pxa270_id.h"

#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 5-22 (pages 5-51 through
   5-58) "DMA Controller Register Summary" address column. */
enum : uint32_t {
    kDcsrEnd    = 0x0080u,
    kDalgn      = 0x00A0u,
    kDpcsr      = 0x00A4u,
    kDrqsr0     = 0x00E0u,
    kDrqsr1     = 0x00E4u,
    kDrqsr2     = 0x00E8u,
    kDint       = 0x00F0u,
    kDrcmrLo    = 0x0100u,
    kDrcmrLoEnd = 0x0200u,
    kDrcmr23    = 0x015Cu,
    kChanFirst  = 0x0200u,
    kChanEnd    = 0x0400u,
    kDrcmrHi    = 0x1100u,
    kDrcmrHiEnd = 0x111Cu,
    kDrcmr74    = 0x1128u,
};

/* Table 5-22 (pages 5-53 through 5-58) "0x4000_0200 DDADR0", "0x4000_0204
   DSADR0", "0x4000_0208 DTADR0", "0x4000_020C DCMD0". */
enum : uint32_t {
    kChanStride = 0x10u,
    kOffDdadr = 0x0u, kOffDsadr = 0x4u, kOffDtadr = 0x8u,
};

class Pxa27xDma : public Pxa2xxDma {
public:
    using Pxa2xxDma::Pxa2xxDma;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa270;
    }

    /* Intel PXA27x Developer's Manual Table 3-2 (page 3-12): "Any module not listed takes the reset
       value for all of its registers" for sleep-exit, GPIO, watchdog, hardware and power-on reset. */
    void OnReady() override {
        AttachChannels(kNumChannels);
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetLine(); });
    }

    /* Table 5-22 (page 5-51) first entry "0x4000_0000 DCSR0"; (page 5-58) last
       entry "0x4000_112C-0x400F_FFFC reserved". */
    uint32_t MmioBase() const override { return 0x40000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        return ReadRegLocked(addr);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        WriteRegLocked(addr, value);
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        SaveChannels(w);
        w.WriteBytes("drcmr_lo", drcmr_lo_, sizeof(drcmr_lo_));
        w.WriteBytes("drcmr_hi", drcmr_hi_, sizeof(drcmr_hi_));
        w.Write("drcmr74", drcmr74_);
        w.Write("dalgn", dalgn_);
        w.Write("dpcsr", dpcsr_);
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        RestoreChannels(r);
        r.ReadBytes("drcmr_lo", drcmr_lo_, sizeof(drcmr_lo_));
        r.ReadBytes("drcmr_hi", drcmr_hi_, sizeof(drcmr_hi_));
        r.Read("drcmr74", drcmr74_);
        r.Read("dalgn", dalgn_);
        r.Read("dpcsr", dpcsr_);
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        PostRestoreChannelsLocked();
    }

protected:
    uint32_t DrcmrOf(uint32_t request) const override {
        if (request < 64u) return drcmr_lo_[request];
        if (request < 71u) return drcmr_hi_[request - 64u];
        return request == 74u ? drcmr74_ : 0u;
    }

    /* Table 5-12 (page 5-32) "If both DDADRx[BREN] and DCSRx[CMPST] are set, the DMA
       controller fetches the next descriptor from (DDADRx + 32 bytes)." */
    uint32_t DescriptorAddressLocked(uint32_t ch) const override {
        const uint32_t base = ddadr_[ch] & kDescAddrMask;
        if ((ddadr_[ch] & DDADR_BREN) && (dcsr_[ch] & CMPST)) return base + kBranchOffset;
        return base;
    }

    uint32_t DescriptorDdadrMask() const override { return kDdadrMask; }
    uint32_t DescriptorDcmdMask() const override { return kDcmdMask; }

    /* Section 5.5.9 (page 5-48) lists the conditions that generate a DMA interrupt. */
    bool ChannelIrq(uint32_t ch) const override {
        const uint32_t d = dcsr_[ch];
        if (d & (BUSERRINTR | STARTINTR | ENDINTR)) return true;
        return ChannelStoppedLocked(ch) && (d & STOPIRQEN);
    }

private:
    /* Table 5-18 (pages 5-41 through 5-46) DCSR0-31 bit definitions. */
    static constexpr uint32_t EORIRQEN = 1u << 28, EORJMPEN  = 1u << 27,
                              EORSTOPEN = 1u << 26, SETCMPST = 1u << 25,
                              CLRCMPST = 1u << 24, RASIRQEN  = 1u << 23,
                              MASKRUN  = 1u << 22, CMPST     = 1u << 10,
                              EORINT   = 1u <<  9,
                              RASINTR  = 1u <<  4, STOPINTR  = 1u <<  3;
    static constexpr uint32_t kDcsrRw = RUN | NODESCFETCH | STOPIRQEN | CMPST;
    static constexpr uint32_t kDcsrW1c = EORINT | ENDINTR | STARTINTR | BUSERRINTR;
    /* Table 5-18 (pages 5-42, 5-43, 5-45): RASIrqEn "when a peripheral asserts a DMA request after the
       channel has stopped", RASIntr; EORIRQEN, EORJMPEN, EORSTOPEN act "when the mapped peripheral
       signals an EOR". */
    static constexpr uint32_t kDcsrUnmodelled = EORIRQEN | EORJMPEN | EORSTOPEN | RASIRQEN | RASINTR;

    /* Table 5-15 (pages 5-35 through 5-38) DCMD0-31 bit definitions. */
    static constexpr uint32_t kDcmdMask = 0xF2FBDFFFu;

    /* Table 5-12 (page 5-32) DDADR0-31 "31:4 R/W Descriptor Address", "1 R/W
       BREN", "0 R/W STOP". */
    static constexpr uint32_t DDADR_BREN = 1u << 1;
    static constexpr uint32_t kDdadrMask = 0xFFFFFFF3u;
    static constexpr uint32_t kDescAddrMask = 0xFFFFFFF0u;
    static constexpr uint32_t kBranchOffset = 32u;

    /* Table 5-11 (page 5-31) DRCMR0-74 "7 R/W MAPVLD", "4:0 R/W CHLNUM". */
    static constexpr uint32_t kDrcmrMask = 0x9Fu;

    /* Table 5-21 (page 5-51) DPCSR "31 R/W BRGSPLT", "0 R BRGBUSY"; reset row
       prints bit 31 = 0b1. */
    static constexpr uint32_t kDpcsrRw = 0x80000000u, kDpcsrReset = 0x80000000u;

    static constexpr uint32_t kNumChannels = 32;

    /* Table 5-22 (pages 5-52 through 5-58): DRCMR0-63 at 0x4000_0100-0x4000_01FC,
       DRCMR64-70 at 0x4000_1100-0x4000_1118, DRCMR74 at 0x4000_1128. */
    uint8_t  drcmr_lo_[64] = {}, drcmr_hi_[7] = {}, drcmr74_ = 0;
    uint32_t dalgn_ = 0;
    uint32_t dpcsr_ = kDpcsrReset;

    /* Table 5-11 (page 5-31) MAPVLD and CHLNUM reset 0; Table 5-20 (page 5-49) DALGN reset 0. */
    void ResetLine() {
        std::lock_guard<std::mutex> lk(state_mutex_);
        ResetChannelsLocked();
        std::memset(drcmr_lo_, 0, sizeof(drcmr_lo_));
        std::memset(drcmr_hi_, 0, sizeof(drcmr_hi_));
        drcmr74_ = 0;
        dalgn_   = 0;
        dpcsr_   = kDpcsrReset;
    }

    /* Table 5-18 (page 5-45) "3 R STOPINTR ... 0 = The channel is running / 1 = The
       channel is in uninitialized or stopped state". */
    uint32_t DcsrValue(uint32_t ch) {
        uint32_t v = ChannelStoppedLocked(ch) ? (dcsr_[ch] | STOPINTR) : dcsr_[ch];
        if (RequestPendingLocked(ch)) v |= REQPEND;
        return v;
    }

    /* Table 5-22 (page 5-53) "0x4000_015C reserved" between "0x4000_0158 DRCMR22"
       and "0x4000_0160 DRCMR24"; (page 5-58) "0x4000_111C-0x4000_1124 reserved". */
    uint8_t* DrcmrSlot(uint32_t off) {
        if (off >= kDrcmrLo && off < kDrcmrLoEnd && off != kDrcmr23)
            return &drcmr_lo_[(off - kDrcmrLo) / 4u];
        if (off >= kDrcmrHi && off < kDrcmrHiEnd)
            return &drcmr_hi_[(off - kDrcmrHi) / 4u];
        if (off == kDrcmr74) return &drcmr74_;
        return nullptr;
    }

    uint32_t DrcmrIndex(uint32_t off) const {
        if (off >= kDrcmrLo && off < kDrcmrLoEnd) return (off - kDrcmrLo) / 4u;
        if (off >= kDrcmrHi && off < kDrcmrHiEnd) return 64u + (off - kDrcmrHi) / 4u;
        return 74u;
    }

    uint32_t ReadRegLocked(uint32_t addr) {
        const uint32_t off = addr - MmioBase();
        if (off & 0x3u) HaltUnsupportedAccess("ReadWord", addr, 0);
        if (off < kDcsrEnd) return DcsrValue(off / 4u);
        if (off >= kChanFirst && off < kChanEnd) {
            const uint32_t ch = (off - kChanFirst) / kChanStride;
            switch (off & 0xCu) {
            case kOffDdadr: return ChannelRegLocked(ch, Reg::Ddadr);
            case kOffDsadr: return ChannelRegLocked(ch, Reg::Dsadr);
            case kOffDtadr: return ChannelRegLocked(ch, Reg::Dtadr);
            default:        return ChannelRegLocked(ch, Reg::Dcmd);
            }
        }
        if (const uint8_t* slot = DrcmrSlot(off)) return *slot;
        switch (off) {
        /* Table 5-20 (page 5-49) "31:0 R/W DALGNx". */
        case kDalgn: return dalgn_;
        /* Table 5-21 (page 5-51) "31 R/W BrgSplit", "0 R BrgBusy Bridge Busy Status
           ... 0 = No pending PIO transactions across peripheral bus." */
        case kDpcsr: return dpcsr_;
        /* Table 5-17 (page 5-40) "4:0 R REQPEND Requests Pending Indicates the
           number of pending requests on DREQx." */
        case kDrqsr0: case kDrqsr1: case kDrqsr2: return 0u;
        case kDint: return Dint();
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteRegLocked(uint32_t addr, uint32_t value) {
        const uint32_t off = addr - MmioBase();
        if (off & 0x3u) HaltUnsupportedAccess("WriteWord", addr, value);
        if (off < kDcsrEnd) { WriteDcsrLocked(off / 4u, value); return; }
        if (off >= kChanFirst && off < kChanEnd) {
            const uint32_t ch = (off - kChanFirst) / kChanStride;
            switch (off & 0xCu) {
            case kOffDdadr:
                ddadr_[ch] = value & kDdadrMask;
                return;
            /* Table 5-13 (page 5-33) "31:2 R/W SRCADDR", "2 R/W SRCADDR or
               reserved", "1:0 R/W SRCADDR or reserved". */
            case kOffDsadr:
                if (!DescriptorFetchModeLocked(ch)) dsadr_[ch] = value;
                return;
            /* Table 5-14 (page 5-34) "31:2 R/W TRGADDR", "2 R/W TRGADDR or
               reserved", "1:0 R/W TRGADDR or reserved". */
            case kOffDtadr:
                if (!DescriptorFetchModeLocked(ch)) dtadr_[ch] = value;
                return;
            default:
                if (!DescriptorFetchModeLocked(ch)) dcmd_[ch] = value & kDcmdMask;
                return;
            }
        }
        if (uint8_t* slot = DrcmrSlot(off)) {
            RequireMappingStableLocked(DrcmrIndex(off), value & kDrcmrMask);
            *slot = static_cast<uint8_t>(value & kDrcmrMask);
            return;
        }
        switch (off) {
        case kDalgn: dalgn_ = value; return;
        case kDpcsr: dpcsr_ = value & kDpcsrRw; return;
        /* Table 5-17 (page 5-40) "8 W CLR ... Writing 0b1 to this bit clears
           DRQSRx[REQPEND] and thereby clears all pending requests made by the
           external DMA request pin DREQx." */
        case kDrqsr0: case kDrqsr1: case kDrqsr2: return;
        /* Table 5-19 (page 5-48) "31:0 R CHLINTRx". */
        case kDint: return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void WriteDcsrLocked(uint32_t ch, uint32_t value) {
        if ((value & kDcsrUnmodelled) != 0u) {
            emu_.Get<Fatal>().Die("Pxa27xDma ch%u: DCSR write 0x%08X sets a request-after-stop or end-of-receive "
                                  "control; not modelled", ch, value);
        }
        uint32_t cur = dcsr_[ch] & ~(value & kDcsrW1c);
        const bool was_run = (cur & RUN) != 0;
        /* Table 5-18 (page 5-43) "1 = Software (programmed I/O write) cannot modify
           DCSR[RUN] during a write transaction in which DCSR[MaskRun] is 1." */
        const uint32_t rw = (value & MASKRUN) ? (kDcsrRw & ~RUN) : kDcsrRw;
        cur = (cur & ~rw) | (value & rw);
        /* Table 5-18 (page 5-44) "If software attempts to concurrently set and clear
           CMPST by setting both DCSRx[SETCMPST] and DCSRx[CLRCMPST], DCSRx[SETCMPST]
           has higher precedence." */
        if (value & CLRCMPST) cur &= ~CMPST;
        if (value & SETCMPST) cur |= CMPST;
        dcsr_[ch] = cur;
        RunEdgeLocked(ch, was_run);
        UpdateIrqLocked();
    }

    /* Table 5-19 (page 5-48) "31:0 R CHLINTRx Channel Interrupt Indicates that DMA
       channel x has been interrupted: 0 = No interrupt / 1 = Interrupt". */
    uint32_t Dint() const {
        uint32_t d = 0;
        for (uint32_t ch = 0; ch < kNumChannels; ++ch)
            if (ChannelIrq(ch)) d |= (1u << ch);
        return d;
    }

};

}  // namespace

REGISTER_SERVICE_AS(Pxa27xDma, Pxa2xxDma);
