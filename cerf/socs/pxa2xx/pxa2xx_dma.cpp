#define NOMINMAX

#include "pxa2xx_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"
#include "pxa2xx_dma_port.h"

#include <algorithm>
#include <cstring>

namespace {

/* Intel PXA255 Developer's Manual Table 5-8 (page 5-20) DRCMR: MAPVLD bit 7, CHLNUM; Intel PXA27x
   Developer's Manual Table 5-11 (page 5-31): MAPVLD bit 7, CHLNUM 4:0. */
constexpr uint32_t kMapValid    = 1u << 7;
constexpr uint32_t kChannelMask = 0x1Fu;
/* Intel PXA255 Developer's Manual Table 5-12 (page 5-24) DCMD: INCSRCADDR, INCTRGADDR, FLOWSRC,
   FLOWTRG, STARTIRQEN, ENDIRQEN, SIZE 17:16, WIDTH 15:14, LENGTH 12:0. */
constexpr uint32_t kPortDcmdBits = 0xF063DFFFu;
constexpr uint32_t kSizeShift    = 16u;
constexpr uint32_t kWidthShift   = 14u;
constexpr uint32_t kFieldMask    = 3u;
constexpr uint32_t kWidthWord    = 3u;
constexpr uint32_t kWordBytes    = 4u;
constexpr uint32_t kDescBytes    = 16u;

}  // namespace

void Pxa2xxDma::AttachChannels(uint32_t count) {
    channels_ = count;
    clock_    = &emu_.Get<GuestCycleClock>();
    mem_      = &emu_.Get<EmulatedMemory>();
    intc_     = &emu_.Get<IrqController>();
    for (uint32_t ch = 0; ch < count; ++ch) {
        bound_request_[ch] = kNoRequest;
        done_ev_[ch]       = clock_->Add([this, ch] { OnDoneEvent(ch); });
    }
}

void Pxa2xxDma::RegisterPort(uint32_t request, Pxa2xxDmaPort* port) {
    if (request >= kMaxRequests || ports_[request] != nullptr || unmodelled_[request] != nullptr) {
        emu_.Get<Fatal>().Die("Pxa2xxDma: DMA request %u registered twice", request);
    }
    ports_[request] = port;
}

void Pxa2xxDma::RegisterUnmodelledRequest(uint32_t request, const char* name) {
    if (request >= kMaxRequests || ports_[request] != nullptr || unmodelled_[request] != nullptr) {
        emu_.Get<Fatal>().Die("Pxa2xxDma: DMA request %u registered twice", request);
    }
    unmodelled_[request] = name;
}

uint32_t Pxa2xxDma::MappedRequestLocked(uint32_t ch) {
    uint32_t found = kNoRequest;
    for (uint32_t r = 0; r < kMaxRequests; ++r) {
        if (ports_[r] == nullptr && unmodelled_[r] == nullptr) continue;
        const uint32_t v = DrcmrOf(r);
        if ((v & kMapValid) == 0u || (v & kChannelMask) != ch) continue;
        if (found != kNoRequest) {
            emu_.Get<Fatal>().Die("Pxa2xxDma ch%u: DMA requests %u and %u both map to the channel; "
                                  "not modelled", ch, found, r);
        }
        found = r;
    }
    return found;
}

/* Intel PXA255 Developer's Manual Figure 5-4 (page 5-8): Stopped returns to "Valid descriptor not
   running"; only RUN=1 from that state enters "Descriptor fetch (running)". */
void Pxa2xxDma::RunEdgeLocked(uint32_t ch, bool was_run) {
    const bool now_run = (dcsr_[ch] & RUN) != 0u;
    if (!was_run && now_run) {
        if ((dcsr_[ch] & NODESCFETCH) == 0u && (ddadr_[ch] & DDADR_STOP) != 0u) {
            stopped_run_[ch] = true;
            return;
        }
        const uint32_t r = MappedRequestLocked(ch);
        if (r == kNoRequest) {
            emu_.Get<Fatal>().Die("Pxa2xxDma ch%u: RUN (DCSR 0x%08X, DDADR 0x%08X) with no modelled DMA request "
                                  "mapped to the channel; not modelled", ch, dcsr_[ch], ddadr_[ch]);
        }
        if (unmodelled_[r] != nullptr) {
            emu_.Get<Fatal>().Die("Pxa2xxDma ch%u: %s DMA (request %u); not modelled", ch,
                                  unmodelled_[r], r);
        }
        StartPortLocked(ch, r);
        return;
    }
    if (!was_run || now_run) return;
    if (stopped_run_[ch]) {
        stopped_run_[ch] = false;
        return;
    }
    if (PortBoundLocked(ch)) StopPortLocked(ch, clock_->Cycles(), false);
}

void Pxa2xxDma::StartPortLocked(uint32_t ch, uint32_t request) {
    if ((dcsr_[ch] & NODESCFETCH) != 0u) {
        emu_.Get<Fatal>().Die("Pxa2xxDma ch%u: no-descriptor-fetch transfer for DMA request %u; "
                              "not modelled", ch, request);
    }
    bound_request_[ch] = static_cast<uint8_t>(request);
    stream_[ch].Bind(ports_[request]);
    LoadDescriptorLocked(ch, clock_->Cycles());
    ArmDoneLocked(ch);
}

/* Intel PXA255 Developer's Manual section 5.1.4.2 (page 5-7): continue or stop "as determined by the
   DDADR[STOP] bit"; Table 5-12 (page 5-25) SIZE: "If DCMDx[LENGTH] is less than DCMDx[SIZE] the data
   transfer size equals DCMDx[LENGTH]". */
void Pxa2xxDma::LoadDescriptorLocked(uint32_t ch, uint64_t at) {
    Pxa2xxDmaChannel& s    = stream_[ch];
    Pxa2xxDmaPort*    port = s.Port();
    if ((ddadr_[ch] & DDADR_STOP) != 0u) {
        StopPortLocked(ch, at, true);
        return;
    }
    const uint32_t desc = DescriptorAddressLocked(ch);
    const uint8_t* src  = mem_->TryTranslateRange(desc, kDescBytes);
    if (src == nullptr) {
        emu_.Get<Fatal>().Die("Pxa2xxDma ch%u: descriptor at 0x%08X is not in memory; not modelled",
                              ch, desc);
    }
    uint32_t w[4];
    std::memcpy(w, src, sizeof(w));
    ddadr_[ch] = w[0] & DescriptorDdadrMask();
    dsadr_[ch] = w[1];
    dtadr_[ch] = w[2];
    dcmd_[ch]  = w[3] & DescriptorDcmdMask();
    ValidateDescriptorLocked(ch, desc);
    if ((dcmd_[ch] & STARTIRQEN) != 0u) dcsr_[ch] |= STARTINTR;
    const uint32_t bytes = dcmd_[ch] & kDcmdLengthMask;
    const uint32_t burst = 1u << ((dcmd_[ch] >> kSizeShift) & kFieldMask);
    s.Begin((bytes + kWordBytes - 1u) / kWordBytes, burst);
    if (!port->Receive()) port->TransmitBlock(dsadr_[ch], bytes);
    port->SetService(at, burst, s.Remaining());
}

/* Intel PXA255 Developer's Manual sections 5.2.1.1-5.2.1.2 (page 5-12): a read cycle to an internal
   peripheral sets INCSRCADDR and FLOWTRG, a write cycle from one sets INCTRGADDR and FLOWSRC; Table
   5-12 (page 5-25) LENGTH: "the length of the transfer must be an integer multiple of the width". */
void Pxa2xxDma::ValidateDescriptorLocked(uint32_t ch, uint32_t desc) {
    Pxa2xxDmaPort* port   = stream_[ch].Port();
    const uint32_t d      = dcmd_[ch];
    const bool     rx     = port->Receive();
    const uint32_t fifo   = rx ? dsadr_[ch] : dtadr_[ch];
    const uint32_t memory = rx ? dtadr_[ch] : dsadr_[ch];
    const uint32_t bytes  = d & kDcmdLengthMask;
    /* Intel PXA255 Developer's Manual section 5.1.8 (page 5-11): if a peripheral requests, "the DMA transfers
       the number of bytes equal to the smaller of DCMD[LENGTH] or DCMD[SIZE]"; Intel PXA27x Developer's
       Manual section 5.4.6 (page 5-20): it "reads only the number of trailing bytes programmed by DCMDx[Len]". */
    const bool ok = (d & ~kPortDcmdBits) == 0u &&
                    (d & (FLOWSRC | FLOWTRG)) == (rx ? FLOWSRC : FLOWTRG) &&
                    (d & (INCSRCADDR | INCTRGADDR)) == (rx ? INCTRGADDR : INCSRCADDR) &&
                    fifo == port->FifoAddress() &&
                    ((d >> kWidthShift) & kFieldMask) == kWidthWord &&
                    ((d >> kSizeShift) & kFieldMask) != 0u &&
                    bytes != 0u && (rx || (bytes % kWordBytes) == 0u) &&
                    (memory & 0x7u) == 0u;
    if (ok) return;
    emu_.Get<Fatal>().Die("Pxa2xxDma ch%u: descriptor at 0x%08X (DSADR 0x%08X DTADR 0x%08X DCMD "
                          "0x%08X) for DMA request %u; not modelled", ch, desc, dsadr_[ch],
                          dtadr_[ch], d, bound_request_[ch]);
}

void Pxa2xxDma::EvaluateLocked(uint32_t ch, uint64_t now) {
    Pxa2xxDmaChannel& s = stream_[ch];
    while (s.Active()) {
        uint64_t done = 0;
        if (!s.DoneCycle(done) || done > now) return;
        s.Port()->Settle(done);
        CompleteLocked(ch, done);
    }
}

/* Intel PXA255 Developer's Manual Table 5-7 (page 5-19) ENDINTR: "interrupt caused because the
   current transaction was successfully completed and DCMD[LENGTH] = 0". */
void Pxa2xxDma::CompleteLocked(uint32_t ch, uint64_t at) {
    Pxa2xxDmaChannel& s     = stream_[ch];
    const uint32_t    bytes = dcmd_[ch] & kDcmdLengthMask;
    if (s.Port()->Receive()) WriteReceivedLocked(ch);
    if ((dcmd_[ch] & INCSRCADDR) != 0u) dsadr_[ch] += bytes;
    if ((dcmd_[ch] & INCTRGADDR) != 0u) dtadr_[ch] += bytes;
    dcmd_[ch] &= ~kDcmdLengthMask;
    s.Finish();
    if ((dcmd_[ch] & ENDIRQEN) != 0u) dcsr_[ch] |= ENDINTR;
    const GuestCycleClock::Rate rate = clock_->ClockRate();
    LOG(SocDma, "ch%u done request %u length %u at cycle %llu rate %llu/%llu\n", ch, bound_request_[ch],
        bytes, static_cast<unsigned long long>(at), static_cast<unsigned long long>(rate.num),
        static_cast<unsigned long long>(rate.den));
    LoadDescriptorLocked(ch, at);
}

/* Intel PXA255 Developer's Manual Table 5-7 (page 5-18) RUN: "If the run bit is cleared in the
   middle of the burst, the burst will complete before the channel is stopped." */
void Pxa2xxDma::StopPortLocked(uint32_t ch, uint64_t at, bool end_of_chain) {
    Pxa2xxDmaChannel& s    = stream_[ch];
    Pxa2xxDmaPort*    port = s.Port();
    port->Settle(at);
    if (s.Active()) {
        if (port->Receive()) WriteReceivedLocked(ch);
        const uint32_t moved = MovedBytesLocked(ch);
        if ((dcmd_[ch] & INCSRCADDR) != 0u) dsadr_[ch] += moved;
        if ((dcmd_[ch] & INCTRGADDR) != 0u) dtadr_[ch] += moved;
        dcmd_[ch] -= moved;
        s.Stop();
    }
    port->SetService(at, std::max(s.Burst(), 1u), 0u);
    dcsr_[ch] &= ~RUN;
    port->Stopped(at, end_of_chain);
    s.Unbind();
    bound_request_[ch] = kNoRequest;
    clock_->Disarm(done_ev_[ch]);
}

uint32_t Pxa2xxDma::MovedBytesLocked(uint32_t ch) const {
    return std::min(stream_[ch].WordsMoved() * kWordBytes, dcmd_[ch] & kDcmdLengthMask);
}

void Pxa2xxDma::WriteReceivedLocked(uint32_t ch) {
    Pxa2xxDmaChannel& s     = stream_[ch];
    const uint32_t    start = s.Written() * kWordBytes;
    const uint32_t    end   = MovedBytesLocked(ch);
    if (end <= start) return;
    s.Port()->ReceiveBlock(dtadr_[ch] + start, end - start);
    s.MarkWritten();
}

void Pxa2xxDma::ArmDoneLocked(uint32_t ch) {
    uint64_t at = 0;
    if (stream_[ch].DoneCycle(at)) {
        clock_->Arm(done_ev_[ch], at);
    } else {
        clock_->Disarm(done_ev_[ch]);
    }
}

void Pxa2xxDma::OnDoneEvent(uint32_t ch) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    EvaluateLocked(ch, clock_->Cycles());
    ArmDoneLocked(ch);
    UpdateIrqLocked();
}

void Pxa2xxDma::OnPortChange() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const uint64_t now = clock_->Cycles();
    for (uint32_t ch = 0; ch < channels_; ++ch) {
        if (!PortBoundLocked(ch)) continue;
        EvaluateLocked(ch, now);
        Pxa2xxDmaChannel& s = stream_[ch];
        if (s.Active()) s.Port()->SetService(now, s.Burst(), s.Remaining());
        ArmDoneLocked(ch);
    }
    UpdateIrqLocked();
}

/* Intel PXA255 Developer's Manual section 5.1.2.1 (page 5-3): PREQ is level sensitive and "The DCSR[REQPEND]
   bit indicates the status of the pending request for the channel"; Figure 5-4 (page 5-8): a request moves
   the channel only from "Wait for request". */
bool Pxa2xxDma::RequestPendingLocked(uint32_t ch) {
    if (!PortBoundLocked(ch)) return false;
    Pxa2xxDmaPort* port = stream_[ch].Port();
    port->Settle(clock_->Cycles());
    return port->RequestAsserted();
}

/* Intel PXA255 Developer's Manual section 5.2.1.1 (page 5-12): "DSADRx is increased by the smaller
   value of DCMDx[LENGTH] and DCMD[SIZE]. DCMDx[LENGTH] is decreased by the same value"; section
   5.3.5 (page 5-21): DSADRx "are read only in the Descriptor Fetch Mode". */
uint32_t Pxa2xxDma::ChannelRegLocked(uint32_t ch, Reg reg) {
    Pxa2xxDmaChannel& s = stream_[ch];
    if (!s.Active()) {
        switch (reg) {
        case Reg::Ddadr: return ddadr_[ch];
        case Reg::Dsadr: return dsadr_[ch];
        case Reg::Dtadr: return dtadr_[ch];
        default:         return dcmd_[ch];
        }
    }
    s.Port()->Settle(clock_->Cycles());
    const uint32_t moved = MovedBytesLocked(ch);
    switch (reg) {
    case Reg::Ddadr: return ddadr_[ch];
    case Reg::Dsadr: return dsadr_[ch] + ((dcmd_[ch] & INCSRCADDR) != 0u ? moved : 0u);
    case Reg::Dtadr:
        if (s.Port()->Receive()) WriteReceivedLocked(ch);
        return dtadr_[ch] + ((dcmd_[ch] & INCTRGADDR) != 0u ? moved : 0u);
    default:
        return dcmd_[ch] - moved;
    }
}

void Pxa2xxDma::RequireMappingStableLocked(uint32_t request, uint32_t value) {
    for (uint32_t ch = 0; ch < channels_; ++ch) {
        if (bound_request_[ch] != request) continue;
        if ((value & kMapValid) != 0u && (value & kChannelMask) == ch) return;
        emu_.Get<Fatal>().Die("Pxa2xxDma: DRCMR%u write 0x%08X unmaps running channel %u; not modelled",
                              request, value, ch);
    }
}

void Pxa2xxDma::UpdateIrqLocked() {
    for (uint32_t ch = 0; ch < channels_; ++ch) {
        if (!ChannelIrq(ch)) continue;
        intc_->AssertIrq(static_cast<int>(kIntcDmaBit));
        return;
    }
    intc_->DeAssertIrq(static_cast<int>(kIntcDmaBit));
}

/* Intel PXA255 Developer's Manual Table 5-7 (page 5-18) and Table 5-12 (page 5-24): DCSR and DCMD
   reset 0 apart from STOPSTATE; Table 5-9 (page 5-21): DDADR STOP resets 0, the address is
   uninitialized. */
void Pxa2xxDma::ResetChannelsLocked() {
    const uint64_t now = clock_->Cycles();
    for (uint32_t ch = 0; ch < channels_; ++ch) {
        if (PortBoundLocked(ch)) StopPortLocked(ch, now, false);
        dcsr_[ch] = 0u;
        dcmd_[ch] = 0u;
        ddadr_[ch] &= ~0x3u;
        stopped_run_[ch] = false;
    }
    UpdateIrqLocked();
}

void Pxa2xxDma::SaveChannels(StateWriter& w) {
    w.WriteBytes("dcsr", dcsr_, sizeof(dcsr_));
    w.WriteBytes("ddadr", ddadr_, sizeof(ddadr_));
    w.WriteBytes("dsadr", dsadr_, sizeof(dsadr_));
    w.WriteBytes("dtadr", dtadr_, sizeof(dtadr_));
    w.WriteBytes("dcmd", dcmd_, sizeof(dcmd_));
    w.WriteBytes("bound_request", bound_request_, sizeof(bound_request_));
    for (uint32_t ch = 0; ch < kMaxChannels; ++ch) {
        w.Write<uint8_t>("stopped_run", stopped_run_[ch] ? 1u : 0u);
        stream_[ch].Save(w);
    }
}

void Pxa2xxDma::RestoreChannels(StateReader& r) {
    r.ReadBytes("dcsr", dcsr_, sizeof(dcsr_));
    r.ReadBytes("ddadr", ddadr_, sizeof(ddadr_));
    r.ReadBytes("dsadr", dsadr_, sizeof(dsadr_));
    r.ReadBytes("dtadr", dtadr_, sizeof(dtadr_));
    r.ReadBytes("dcmd", dcmd_, sizeof(dcmd_));
    r.ReadBytes("bound_request", bound_request_, sizeof(bound_request_));
    for (uint32_t ch = 0; ch < kMaxChannels; ++ch) {
        uint8_t stopped_run = 0;
        r.Read("stopped_run", stopped_run);
        stopped_run_[ch] = stopped_run != 0u;
        const uint8_t request = bound_request_[ch];
        stream_[ch].Bind(request == kNoRequest ? nullptr : ports_[request]);
        stream_[ch].Restore(r);
    }
}

void Pxa2xxDma::PostRestoreChannelsLocked() {
    const uint64_t now = clock_->Cycles();
    for (uint32_t ch = 0; ch < channels_; ++ch) {
        Pxa2xxDmaChannel& s = stream_[ch];
        if (s.Active()) s.Port()->SetService(now, s.Burst(), s.Remaining());
        ArmDoneLocked(ch);
    }
    UpdateIrqLocked();
}
