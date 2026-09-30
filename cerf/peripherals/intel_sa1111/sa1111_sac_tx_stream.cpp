#include "sa1111_sac_tx_stream.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../state/state_stream.h"

#include <algorithm>

bool Sa1111SacTxStream::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111SacTxStream::OnReady() {
    sbi_ = &emu_.Get<Sa1111Sbi>();
}

bool Sa1111SacTxStream::SetRatio(uint64_t cpu_hz, uint32_t cas, uint64_t fs_num,
                                 uint64_t fs_den) {
    if (!frames_.SetRatio(cpu_hz * fs_den, fs_num)) return false;
    cpu_hz_ = cpu_hz;
    cas_    = cas;
    fs_num_ = fs_num;
    fs_den_ = fs_den;
    return true;
}

void Sa1111SacTxStream::RequireInFlightTiming(uint64_t now, uint64_t cpu_hz) const {
    const uint32_t unlanded = Unlanded(now);
    if (unlanded == 0u || (cpu_hz == last_.hz && sbi_->CasLatency() == last_.cas)) return;
    emu_.Get<Fatal>().Die("Sa1111SacTxStream: a core rate (%llu Hz) or SMCR CAS latency (%u) "
                          "change with %u transmit DMA words in flight since a request at "
                          "%llu Hz, CAS %u, is not modelled",
                          static_cast<unsigned long long>(cpu_hz), sbi_->CasLatency(),
                          unlanded, static_cast<unsigned long long>(last_.hz), last_.cas);
}

bool Sa1111SacTxStream::Rescale(uint64_t now, uint64_t cpu_hz, uint32_t cas, uint64_t fs_num,
                                uint64_t fs_den) {
    Settle(now);
    cas_ = cas;
    if (cpu_hz == cpu_hz_ && fs_num == fs_num_ && fs_den == fs_den_) return true;
    const uint64_t pos = Position(now);
    if (!frames_.Rescale(now, cpu_hz * fs_den, fs_num)) return false;
    base_   = pos - frames_.TicksSince(now);
    cpu_hz_ = cpu_hz;
    fs_num_ = fs_num;
    fs_den_ = fs_den;
    return true;
}

uint64_t Sa1111SacTxStream::Position(uint64_t now) const {
    return base_ + frames_.TicksSince(now);
}

uint64_t Sa1111SacTxStream::Consumed(uint64_t now) const {
    return running_ ? Position(now) - skip_ : held_;
}

uint64_t Sa1111SacTxStream::ConsumeCycle(uint64_t words) const {
    return frames_.CycleOfTick(words + skip_ - base_);
}

/* §7.2.2: "the SAC requests the bus using DMA_Req<1>" when data is to be transferred
   "(generally in response to a Transmit or Receive FIFO condition)". */
uint64_t Sa1111SacTxStream::RequestCycle(uint64_t at) const {
    if (!running_) return start_cycle_;
    return std::max(ConsumeCycle(at), start_cycle_);
}

/* §7.2.2: "After a transfer burst, the SAC must give up its request so the bus can be
   returned to SA-1110 ownership." */
uint64_t Sa1111SacTxStream::WordLandCycle(const Request& rq, uint32_t word) const {
    if (word <= rq.burst[0]) return rq.issue + sbi_->BurstWordCycles(word, rq.hz, rq.cas);
    const uint64_t second = rq.issue + sbi_->BurstWordCycles(rq.burst[0], rq.hz, rq.cas) +
                            sbi_->BusReleaseCycles();
    return second + sbi_->BurstWordCycles(word - rq.burst[0], rq.hz, rq.cas);
}

uint32_t Sa1111SacTxStream::Unlanded(uint64_t now) const {
    const uint32_t words = Words(last_);
    uint32_t landed = 0u;
    while (landed < words && WordLandCycle(last_, landed + 1u) <= now) ++landed;
    return words - landed;
}

uint64_t Sa1111SacTxStream::LandedCycle() const {
    const uint32_t words = Words(last_);
    return words == 0u ? 0u : WordLandCycle(last_, words);
}

bool Sa1111SacTxStream::InFlightGap(uint64_t now) const {
    if (!running_ || resolved_ || Words(last_) == 0u) return false;
    const uint64_t consume = ConsumeCycle(last_base_ + 1u);
    return consume <= now && consume < WordLandCycle(last_, 1u);
}

/* SA-1111 Developer's Manual §7.3.2.2: "Each phase of the Left/Right signal is accompanied
   by one serial audio data sample on the data pins SDATA_IN and SDATA_OUT". */
void Sa1111SacTxStream::Run(uint64_t now) {
    skip_    = Position(now) - held_;
    running_ = true;
}

void Sa1111SacTxStream::Hold(uint64_t now) {
    Settle(now);
    held_    = Position(now) - skip_;
    running_ = false;
}

/* Table 7-10 TUR: "0 - Transmit FIFO has not experienced an under-run"; Table 11-1: 38
   AudTUR "Audio Transmit FIFO under-run interrupt". */
void Sa1111SacTxStream::ResolveGap(uint64_t now) {
    while (InFlightGap(now)) {
        underrun_ = true;
        ++skip_;
    }
    if (Words(last_) != 0u && WordLandCycle(last_, 1u) <= now) resolved_ = true;
}

void Sa1111SacTxStream::Settle(uint64_t now) {
    ResolveGap(now);
    const uint64_t pos      = Consumed(now);
    const uint32_t unlanded = Unlanded(now);
    const uint64_t landed   = pushed_ - unlanded;
    if (landed >= pos) return;
    if (unlanded != 0u) {
        emu_.Get<Fatal>().Die("Sa1111SacTxStream: the serializer consumed word %llu while %u "
                              "words of the last DMA request were still in flight",
                              static_cast<unsigned long long>(pos), unlanded);
    }
    underrun_ = true;
    pushed_   = pos;
}

bool Sa1111SacTxStream::Underrun(uint64_t now) const {
    return underrun_ || InFlightGap(now) || pushed_ - Unlanded(now) < Consumed(now);
}

void Sa1111SacTxStream::StartBlock(uint64_t now) {
    Settle(now);
    start_           = Consumed(now);
    start_cycle_     = now;
    stalled_request_ = false;
}

void Sa1111SacTxStream::Clear(uint64_t now) {
    pushed_          = Consumed(now);
    start_           = pushed_;
    last_            = Request{};
    last_base_       = pushed_;
    underrun_        = false;
    stalled_request_ = false;
}

/* SA-1111 Developer's Manual §3.2.3.1 (printed 3-9): "The SBI asserts MBREQ to the SA-1110
   processor. When the system bus is idle, the processor responds with MBGNT". */
void Sa1111SacTxStream::SetGrant(uint64_t now, Sa1111Sbi::BusGrant grant, bool checked) {
    using Grant = Sa1111Sbi::BusGrant;
    if (grant == grant_) return;
    const Grant    old      = grant_;
    const bool     waiting  = stalled_request_;
    const uint32_t unlanded = Unlanded(now);
    grant_ = grant;
    if (grant == Grant::Granted || !checked) stalled_request_ = false;
    LOG(Periph, "[Sa1111Sac] DMA bus grant %d -> %d at cyc=%llu (checked=%d unlanded=%u waiting=%d)\n",
        static_cast<int>(old), static_cast<int>(grant), static_cast<unsigned long long>(now),
        checked ? 1 : 0, unlanded, waiting ? 1 : 0);
    if (!checked) return;
    if (grant == Grant::Undetermined) {
        emu_.Get<Fatal>().Die("Sa1111SacTxStream: the MBGNT input became undetermined with the "
                              "transmit DMA running is not modelled");
    }
    if (old == Grant::Granted && unlanded != 0u) {
        emu_.Get<Fatal>().Die("Sa1111SacTxStream: the bus grant was withdrawn with %u transmit DMA "
                              "words in flight is not modelled", unlanded);
    }
    if (grant == Grant::Granted && waiting) {
        emu_.Get<Fatal>().Die("Sa1111SacTxStream: the bus grant returned with a transmit DMA "
                              "request waiting is not modelled");
    }
}

/* Table 7-10 TFS: "Transmit FIFO level is at or below TFL threshold"; §7.2.2: "the SAC requests
   the bus using DMA_Req<1>". */
bool Sa1111SacTxStream::RequestDue(uint64_t now, uint32_t threshold) const {
    uint64_t at = pushed_ > threshold ? pushed_ - threshold : 0u;
    if (at < start_) at = start_;
    return at <= Consumed(now);
}

/* Table 7-12 SASCR TUR: "Clears Transmit FIFO under-run status bit". */
void Sa1111SacTxStream::ClearUnderrun(uint64_t now) {
    Settle(now);
    underrun_ = false;
}

uint32_t Sa1111SacTxStream::Level(uint64_t now) const {
    const uint64_t pos    = Consumed(now);
    const uint64_t landed = pushed_ - Unlanded(now);
    return landed < pos ? 0u : static_cast<uint32_t>(landed - pos);
}

/* SA-1111 Developer's Manual Table 7-10 TFS: "0 - Transmit FIFO level exceeds TFL threshold,
   or SAC disabled". */
bool Sa1111SacTxStream::ServiceRequest(uint64_t now, bool enabled, uint32_t threshold) const {
    return enabled && Level(now) <= threshold;
}

/* Table 7-10: TNF bit 0, TFS bit 3, TUR bit 5, TFL 11:8 "Number of entries in Transmit
   FIFO". */
uint32_t Sa1111SacTxStream::StatusBits(uint64_t now, bool enabled, uint32_t threshold) const {
    const uint32_t level = Level(now);
    uint32_t bits = (level & 0xFu) << 8;
    if (level < kFifoDepth)                        bits |= 1u << 0;
    if (ServiceRequest(now, enabled, threshold))   bits |= 1u << 3;
    if (Underrun(now))                             bits |= 1u << 5;
    return bits;
}

/* SA-1111 Developer's Manual Table 7-10 TFS: "Transmit FIFO level is at or below TFL
   threshold"; §7.2.2: "After a transfer burst, the SAC must give up its request". */
bool Sa1111SacTxStream::Step(uint32_t threshold, uint32_t& words_left, uint64_t limit,
                             bool bounded, StepState& s) const {
    while (words_left != 0u) {
        uint64_t at = s.pushed > threshold ? s.pushed - threshold : 0u;
        if (at < s.start) at = s.start;
        if (bounded && limit < at) return false;
        ++s.requests;
        Request rq;
        rq.issue    = RequestCycle(at);
        rq.hz       = cpu_hz_;
        rq.cas      = cas_;
        s.last_base = s.pushed;
        uint32_t level = static_cast<uint32_t>(s.pushed - at);
        uint32_t n = 0u;
        while (level <= threshold && words_left != 0u) {
            if (n == 2u) {
                emu_.Get<Fatal>().Die("Sa1111SacTxStream: a third burst in one DMA request "
                                      "(FIFO level %u, threshold %u)", level, threshold);
            }
            const uint32_t burst = std::min({kMaxBurst, kFifoDepth - level, words_left});
            rq.burst[n++] = burst;
            s.pushed   += burst;
            level      += burst;
            words_left -= burst;
        }
        s.last  = rq;
        s.start = at;
        if (words_left == 0u) return true;
    }
    return false;
}

bool Sa1111SacTxStream::Fill(uint64_t now, uint32_t threshold, uint32_t& words_left) {
    ResolveGap(now);
    if (grant_ != Sa1111Sbi::BusGrant::Granted) {
        if (words_left != 0u && RequestDue(now, threshold)) stalled_request_ = true;
        return false;
    }
    StepState s;
    s.pushed    = pushed_;
    s.start     = start_;
    s.requests  = requests_;
    s.last_base = last_base_;
    s.last      = last_;
    const uint64_t before = s.requests;
    const bool done = Step(threshold, words_left, Consumed(now), true, s);
    if (s.requests != before && LandedCycle() > s.last.issue) {
        emu_.Get<Fatal>().Die("Sa1111SacTxStream: a DMA request at cycle %llu before the "
                              "previous burst landed at %llu",
                              static_cast<unsigned long long>(s.last.issue),
                              static_cast<unsigned long long>(LandedCycle()));
    }
    if (s.requests != before) resolved_ = false;
    pushed_    = s.pushed;
    start_     = s.start;
    requests_  = s.requests;
    last_base_ = s.last_base;
    last_      = s.last;
    return done;
}

bool Sa1111SacTxStream::DoneCycle(uint64_t now, uint32_t threshold, uint32_t words_left,
                                  uint64_t& cycle) const {
    if (words_left == 0u) {
        cycle = std::max(now, LandedCycle());
        return true;
    }
    if (!running_ || grant_ != Sa1111Sbi::BusGrant::Granted) return false;
    StepState s;
    s.pushed = pushed_;
    s.start  = start_;
    if (!Step(threshold, words_left, 0u, false, s)) return false;
    cycle = WordLandCycle(s.last, Words(s.last));
    return true;
}

void Sa1111SacTxStream::Save(StateWriter& w, uint64_t now) const {
    const uint32_t unlanded = Unlanded(now);
    w.Write<uint32_t>("tx_serializer_running", running_ ? 1u : 0u);
    w.Write<uint32_t>("tx_fifo_level", Level(now));
    w.Write<uint32_t>("tx_underrun", Underrun(now) ? 1u : 0u);
    w.Write<uint64_t>("tx_frame_phase", frames_.PhaseAt(now));
    w.Write<uint64_t>("tx_frame_phase_den", frames_.PhaseDenominator());
    w.Write<uint32_t>("tx_burst0", unlanded != 0u ? last_.burst[0] : 0u);
    w.Write<uint32_t>("tx_burst1", unlanded != 0u ? last_.burst[1] : 0u);
    w.Write<uint32_t>("tx_unlanded", unlanded);
    w.Write<uint64_t>("tx_request_age", unlanded != 0u ? now - last_.issue : 0u);
    w.Write<uint64_t>("tx_request_hz", unlanded != 0u ? last_.hz : 0u);
    w.Write<uint32_t>("tx_request_cas", unlanded != 0u ? last_.cas : 0u);
}

void Sa1111SacTxStream::Restore(StateReader& r, uint64_t now) {
    uint32_t running = 0u, level = 0u, underrun = 0u, burst0 = 0u, burst1 = 0u, unlanded = 0u;
    uint32_t cas = 0u;
    uint64_t phase = 0u, phase_den = 0u, age = 0u, hz = 0u;
    r.Read("tx_serializer_running", running);
    r.Read("tx_fifo_level", level);
    r.Read("tx_underrun", underrun);
    r.Read("tx_frame_phase", phase);
    r.Read("tx_frame_phase_den", phase_den);
    r.Read("tx_burst0", burst0);
    r.Read("tx_burst1", burst1);
    r.Read("tx_unlanded", unlanded);
    r.Read("tx_request_age", age);
    r.Read("tx_request_hz", hz);
    r.Read("tx_request_cas", cas);
    frames_.AnchorAtPhase(now, 0u, phase, phase_den);
    base_           = 0u - frames_.TicksSince(now);
    held_           = 0u;
    skip_           = 0u;
    running_        = running != 0u;
    pushed_         = static_cast<uint64_t>(level) + unlanded;
    start_          = 0u;
    start_cycle_    = now;
    last_.issue     = now - age;
    last_.hz        = hz;
    last_.cas       = cas;
    last_.burst[0]  = burst0;
    last_.burst[1]  = burst1;
    last_base_      = pushed_ - Words(last_);
    resolved_       = Words(last_) == 0u || WordLandCycle(last_, 1u) <= now;
    underrun_       = underrun != 0u;
    stalled_request_ = false;
}

REGISTER_SERVICE(Sa1111SacTxStream);
