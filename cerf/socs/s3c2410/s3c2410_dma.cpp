#include "s3c2410_dma.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/physical_bus.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

#include <vector>

namespace {

/* S3C2410A User Manual, printed pp. 8-7..8-13: four channels stepping 0x40 with
   nine registers each. */
constexpr uint32_t kBase   = 0x4B000000u;
constexpr uint32_t kStride = 0x40u;

constexpr uint32_t kDisrc     = 0x00u;
constexpr uint32_t kDisrcc    = 0x04u;
constexpr uint32_t kDidst     = 0x08u;
constexpr uint32_t kDidstc    = 0x0Cu;
constexpr uint32_t kDcon      = 0x10u;
constexpr uint32_t kDstat     = 0x14u;
constexpr uint32_t kDcsrc     = 0x18u;
constexpr uint32_t kDcdst     = 0x1Cu;
constexpr uint32_t kDmasktrig = 0x20u;

/* S3C2410A User Manual, printed pp. 8-7, 8-8: S_ADDR / D_ADDR are [30:0]. */
constexpr uint32_t kAddrMask = 0x7FFFFFFFu;
/* S3C2410A User Manual, printed pp. 8-7, 8-8: DISRCC / DIDSTC hold LOC [1] and
   INC [0], "0 = Increment  1 = Fixed". */
constexpr uint32_t kLocIncMask = 0x00000003u;
constexpr uint32_t kIncFixed   = 1u << 0;

/* S3C2410A User Manual, printed pp. 8-9, 8-10, DCON. */
constexpr uint32_t kConInt      = 1u << 29;
constexpr uint32_t kConTsz      = 1u << 28;
constexpr uint32_t kConServmode = 1u << 27;
constexpr uint32_t kConHwSrcShift = 24u;
constexpr uint32_t kConHwSrcMask  = 0x7u;
constexpr uint32_t kConSwhwSel  = 1u << 23;
constexpr uint32_t kConReload   = 1u << 22;
constexpr uint32_t kConDszShift = 20u;
constexpr uint32_t kConDszMask  = 0x3u;
constexpr uint32_t kConTcMask   = 0x000FFFFFu;

/* S3C2410A User Manual, printed p. 8-11: DSTAT holds STAT [21:20], where 00
   "indicates that DMA controller is ready for another DMA request", and CURR_TC
   [19:0], "decreased by one at the end of every atomic transfer". */
constexpr uint32_t kCurrTcMask = 0x000FFFFFu;

/* S3C2410A User Manual, printed p. 8-13, DMASKTRIG. */
constexpr uint32_t kTrigMask   = 0x00000007u;
constexpr uint32_t kTrigStop   = 1u << 2;
constexpr uint32_t kTrigOnOff  = 1u << 1;
constexpr uint32_t kTrigSwTrig = 1u << 0;

/* S3C2410A User Manual, printed p. 14-7: INT_DMA0 [17] .. INT_DMA3 [20]. */
constexpr int kIntDma0 = 17;

/* S3C2410A User Manual, printed p. 8-2, Table 8-1. */
constexpr S3C2410DmaSource kRequestSources[4][5] = {
    { S3C2410DmaSource::kXdreq0, S3C2410DmaSource::kUart0,
      S3C2410DmaSource::kSdi,    S3C2410DmaSource::kTimer,
      S3C2410DmaSource::kUsbEp1 },
    { S3C2410DmaSource::kXdreq1, S3C2410DmaSource::kUart1,
      S3C2410DmaSource::kI2sSdi, S3C2410DmaSource::kSpi0,
      S3C2410DmaSource::kUsbEp2 },
    { S3C2410DmaSource::kI2sSdo, S3C2410DmaSource::kI2sSdi,
      S3C2410DmaSource::kSdi,    S3C2410DmaSource::kTimer,
      S3C2410DmaSource::kUsbEp3 },
    { S3C2410DmaSource::kUart2,  S3C2410DmaSource::kSdi,
      S3C2410DmaSource::kSpi1,   S3C2410DmaSource::kTimer,
      S3C2410DmaSource::kUsbEp4 },
};

}  /* namespace */

bool S3C2410Dma::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::S3c2410;
}

void S3C2410Dma::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { Reset(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void S3C2410Dma::Reset() {
    std::lock_guard<std::mutex> lk(mutex_);
    for (Channel& c : ch_) c = Channel{};
}

uint32_t S3C2410Dma::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    const uint32_t n   = off / kStride;
    const uint32_t reg = off % kStride;
    if (n >= kChannelCount) HaltUnsupportedAccess("ReadWord", addr, 0);

    NotifyRequestersOfAccess();
    std::lock_guard<std::mutex> lk(mutex_);
    const Channel& c = ch_[n];
    switch (reg) {
        case kDisrc:     return c.disrc;
        case kDisrcc:    return c.disrcc;
        case kDidst:     return c.didst;
        case kDidstc:    return c.didstc;
        case kDcon:      return c.dcon;
        case kDstat:     return c.curr_tc & kCurrTcMask;
        case kDcsrc:     return c.curr_src & kAddrMask;
        case kDcdst:     return c.curr_dst & kAddrMask;
        case kDmasktrig: return c.mask;
        default: break;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void S3C2410Dma::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    const uint32_t n   = off / kStride;
    const uint32_t reg = off % kStride;
    if (n >= kChannelCount) HaltUnsupportedAccess("WriteWord", addr, value);

    NotifyRequestersOfAccess();
    bool                 software_trigger = false;
    S3C2410DmaRequester* armed_requester  = nullptr;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        Channel& c = ch_[n];
        const bool was_on = (c.mask & kTrigOnOff) != 0u;
        switch (reg) {
            case kDisrc:  c.disrc  = value & kAddrMask;   break;
            case kDisrcc: c.disrcc = value & kLocIncMask; break;
            case kDidst:  c.didst  = value & kAddrMask;   break;
            case kDidstc: c.didstc = value & kLocIncMask; break;
            case kDcon:   c.dcon   = value;               break;
            case kDmasktrig: {
                /* S3C2410A User Manual, printed p. 8-13: on STOP "The CURR_TC
                   will be 0"; SW_TRIG needs DCONn[23] S/W request mode and
                   ON_OFF 1, and self-clears when the operation starts. */
                const uint32_t next = value & kTrigMask;
                c.mask = next & ~kTrigSwTrig;
                if (next & kTrigStop) {
                    c.curr_tc = 0u;
                    c.mask   &= ~kTrigOnOff;
                }
                software_trigger = (next & kTrigSwTrig) != 0u
                                && (c.mask & kTrigOnOff) != 0u
                                && (c.dcon & kConSwhwSel) == 0u;
                break;
            }
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);
        }
        if (software_trigger) RunChannelLocked(n, ch_[n]);
        if (!was_on && (c.mask & kTrigOnOff) != 0u
            && (c.dcon & kConSwhwSel) != 0u)
            armed_requester = RequesterFor(ChannelSource(n, c));
    }
    if (armed_requester) armed_requester->OnDmaChannelArmed();
    else                 NotifyRequestersOfAccess();
}

void S3C2410Dma::NotifyRequestersOfAccess() {
    std::array<S3C2410DmaRequester*, kRequesterCount> requesters{};
    {
        std::lock_guard<std::mutex> lk(mutex_);
        requesters = requesters_;
    }
    for (S3C2410DmaRequester* r : requesters)
        if (r != nullptr) r->OnDmaAccess();
}

void S3C2410Dma::RegisterRequester(S3C2410DmaSource source,
                                   S3C2410DmaRequester* r) {
    std::lock_guard<std::mutex> lk(mutex_);
    requesters_[static_cast<uint32_t>(source)] = r;
}

S3C2410DmaRequester* S3C2410Dma::RequesterFor(S3C2410DmaSource source) const {
    return requesters_[static_cast<uint32_t>(source)];
}

S3C2410DmaSource S3C2410Dma::ChannelSource(uint32_t n, const Channel& c) {
    const uint32_t sel = (c.dcon >> kConHwSrcShift) & kConHwSrcMask;
    if (sel > 4u)
        emu_.Get<Fatal>().Die(
            "S3C2410Dma: channel %u unallocated HWSRCSEL %u DCON=0x%08X",
            n, sel, c.dcon);
    return kRequestSources[n][sel];
}

bool S3C2410Dma::ServesLocked(uint32_t n, const Channel& c, S3C2410DmaSource source) {
    /* S3C2410A User Manual, printed p. 8-13: with ON_OFF 0 the "DMA request
       to this channel is ignored". */
    if ((c.mask & kTrigOnOff) == 0u) return false;
    /* S3C2410A User Manual, printed p. 8-10: HWSRCSEL has meaning only in
       H/W request mode, selected by SWHW_SEL. */
    if ((c.dcon & kConSwhwSel) == 0u) return false;
    return ChannelSource(n, c) == source;
}

bool S3C2410Dma::ServiceRequest(S3C2410DmaSource source) {
    std::lock_guard<std::mutex> lk(mutex_);
    bool moved = false;
    for (uint32_t n = 0; n < kChannelCount; ++n) {
        Channel& c = ch_[n];
        if (!ServesLocked(n, c, source)) continue;
        /* S3C2410A User Manual, printed p. 8-10: with SERVMODE 1 "one request
           gets atomic transfers to be repeated until the transfer count
           reaches to 0", which no requester in the tree can absorb. */
        if ((c.dcon & kConServmode) != 0u) {
            emu_.Get<Fatal>().Die(
                "S3C2410Dma: whole service mode on hardware-requested channel "
                "%u (DCON=0x%08X)", n, c.dcon);
        }
        moved = RunChannelLocked(n, c) || moved;
    }
    return moved;
}

S3C2410DmaAtomicTransfer S3C2410Dma::AtomicTransfer(S3C2410DmaSource source) {
    std::lock_guard<std::mutex> lk(mutex_);
    S3C2410DmaAtomicTransfer t;
    for (uint32_t n = 0; n < kChannelCount; ++n) {
        const Channel& c = ch_[n];
        if (!ServesLocked(n, c, source)) continue;
        ++t.channels;
        t.bytes    += Beats(c) * UnitBytes(c);
        t.burst     = t.burst || Beats(c) != 1u;
        t.dst       = c.didst;
        t.dst_fixed = (c.didstc & kIncFixed) != 0u;
    }
    return t;
}

uint32_t S3C2410Dma::TransfersToTerminalCount(S3C2410DmaSource source) {
    std::lock_guard<std::mutex> lk(mutex_);
    uint32_t fewest = 0u;
    for (uint32_t n = 0; n < kChannelCount; ++n) {
        const Channel& c = ch_[n];
        if (!ServesLocked(n, c, source)) continue;
        const uint32_t left = c.curr_tc != 0u ? c.curr_tc : (c.dcon & kConTcMask);
        if (left != 0u && (fewest == 0u || left < fewest)) fewest = left;
    }
    return fewest;
}

bool S3C2410Dma::RunChannelLocked(uint32_t n, Channel& c) {
    /* S3C2410A User Manual, printed p. 8-2 state-2: "the counter (CURR_TC) is
       loaded from DCON[19:0] register", and printed p. 8-13: changes to DISRC,
       DIDST and TC "take effect only after the finish of current transfer
       (i.e. when CURR_TC becomes 0)". */
    if (c.curr_tc == 0u) LoadLocked(c);
    if (c.curr_tc == 0u) return false;

    /* S3C2410A User Manual, printed p. 8-10 SERVMODE: Single service performs
       one atomic transfer per request, Whole service repeats "until the
       transfer count reaches to 0". */
    const bool whole = (c.dcon & kConServmode) != 0u;
    bool moved = false;
    for (;;) {
        if (!RunAtomicLocked(c)) break;
        moved = true;
        --c.curr_tc;
        if (c.curr_tc == 0u) { TerminalCountLocked(n, c); break; }
        if (!whole) break;
    }
    return moved;
}

void S3C2410Dma::LoadLocked(Channel& c) {
    c.curr_tc  = c.dcon & kConTcMask;
    c.curr_src = c.disrc & kAddrMask;
    c.curr_dst = c.didst & kAddrMask;
}

void S3C2410Dma::TerminalCountLocked(uint32_t n, Channel& c) {
    /* S3C2410A User Manual, printed p. 8-9 INT: "interrupt request is generated
       when all the transfer is done (i.e. CURR_TC becomes 0)". */
    if (c.dcon & kConInt)
        emu_.Get<IrqController>().AssertIrq(kIntDma0 + static_cast<int>(n));
    /* S3C2410A User Manual, printed pp. 8-10, 8-13: RELOAD 1 turns the channel
       off, setting DMASKTRIGn[1] to 0; RELOAD 0 auto-reloads. */
    if (c.dcon & kConReload) c.mask &= ~kTrigOnOff;
}

/* S3C2410A User Manual, printed p. 8-10 DSZ and printed p. 8-9 TSZ: an atomic
   transfer is one unit or a burst of length four. */
uint32_t S3C2410Dma::UnitBytes(const Channel& c) {
    const uint32_t dsz = (c.dcon >> kConDszShift) & kConDszMask;
    if (dsz == 3u)
        emu_.Get<Fatal>().Die(
            "S3C2410Dma: DSZ 11 is reserved (DCON=0x%08X)", c.dcon);
    return 1u << dsz;
}

uint32_t S3C2410Dma::Beats(const Channel& c) {
    return (c.dcon & kConTsz) ? 4u : 1u;
}

bool S3C2410Dma::RunAtomicLocked(Channel& c) {
    const uint32_t width_bytes = UnitBytes(c);
    const BusWidth width       = static_cast<BusWidth>(width_bytes);
    const uint32_t beats       = Beats(c);

    auto& bus = emu_.Get<PhysicalBus>();
    const uint32_t src_start = c.curr_src;
    const uint32_t dst_start = c.curr_dst;
    for (uint32_t i = 0; i < beats; ++i) {
        if (SelfReferential(c.curr_src) || SelfReferential(c.curr_dst)) {
            emu_.Get<Fatal>().Die(
                "S3C2410Dma: descriptor addresses the controller itself "
                "(src=0x%08X dst=0x%08X)", c.curr_src, c.curr_dst);
        }
        uint32_t unit = 0;
        if (!bus.Read(c.curr_src, width, &unit)) {
            emu_.Get<Fatal>().Die(
                "S3C2410Dma: source address 0x%08X is neither RAM nor a "
                "peripheral", c.curr_src);
        }
        if (!bus.Write(c.curr_dst, width, unit)) {
            emu_.Get<Fatal>().Die(
                "S3C2410Dma: destination address 0x%08X is neither RAM nor a "
                "peripheral", c.curr_dst);
        }
        c.curr_src += width_bytes;
        c.curr_dst += width_bytes;
    }
    /* S3C2410A User Manual, printed p. 8-7: with INC 1 "the address is not
       changed after the transfer. (In the burst mode, address is increased
       during the burst transfer, but the address is recovered to its first
       value after the transfer.)" */
    if (c.disrcc & kIncFixed) c.curr_src = src_start;
    if (c.didstc & kIncFixed) c.curr_dst = dst_start;
    return true;
}

void S3C2410Dma::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mutex_);
    static_assert(StateVisitCoversAllBytes<Channel>(
                      [](Channel& c, StateFieldBytes& f) { Channel::Visit(c, f); }),
                  "Channel::Visit must name or skip every field of Channel");
    StateWriteField field(w);
    for (Channel& c : ch_) Channel::Visit(c, field);
}

void S3C2410Dma::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mutex_);
    StateReadField field(r);
    for (Channel& c : ch_) Channel::Visit(c, field);
    for (uint32_t n = 0; n < kChannelCount; ++n) {
        const Channel& c = ch_[n];
        if ((c.disrc | c.didst | c.curr_src | c.curr_dst) & ~kAddrMask)
            r.Reject("channel %u address past bit 30", n);
        if (((c.disrcc | c.didstc) & ~kLocIncMask) != 0u ||
            (c.mask & ~(kTrigMask & ~kTrigSwTrig)) != 0u)
            r.Reject("channel %u DISRCC 0x%X DIDSTC 0x%X DMASKTRIG 0x%X",
                     n, c.disrcc, c.didstc, c.mask);
        if (c.curr_tc > kCurrTcMask)
            r.Reject("channel %u CURR_TC 0x%X past 20 bits", n, c.curr_tc);
        const bool hw_on = (c.mask & kTrigOnOff) != 0u && (c.dcon & kConSwhwSel) != 0u;
        if (!hw_on) continue;
        if (((c.dcon >> kConDszShift) & kConDszMask) == 3u ||
            ((c.dcon >> kConHwSrcShift) & kConHwSrcMask) > 4u ||
            (c.dcon & kConServmode) != 0u)
            r.Reject("channel %u DCON 0x%08X on a hardware request: DSZ 11, unallocated "
                     "HWSRCSEL or whole service", n, c.dcon);
    }
}

void S3C2410Dma::PostRestore() {
    std::vector<S3C2410DmaRequester*> armed;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        for (uint32_t n = 0; n < kChannelCount; ++n) {
            const Channel& c = ch_[n];
            if ((c.mask & kTrigOnOff) == 0u) continue;
            if ((c.dcon & kConSwhwSel) == 0u) continue;
            if (S3C2410DmaRequester* r = RequesterFor(ChannelSource(n, c)))
                armed.push_back(r);
        }
    }
    for (S3C2410DmaRequester* r : armed) r->OnDmaChannelArmed();
}

REGISTER_SERVICE(S3C2410Dma);
