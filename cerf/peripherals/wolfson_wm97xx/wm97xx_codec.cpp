#include "wm97xx_codec.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../jit/host_request_channel.h"
#include "../../state/state_stream.h"

namespace {

/* Wolfson WM9705 Table 27 (page 47) and Cirrus Logic WM9713L Rev 4.0 Table 53 (page 75): DEL 0000 to
   1110 delay the sample by 1, 2, 4, 8, 16, 32, 48, 64, 96, 128, 160, 192, 224, 256 and 288 frames. */
constexpr uint32_t kDelayFrames[15] = {1u, 2u, 4u, 8u, 16u, 32u, 48u, 64u, 96u, 128u, 160u, 192u, 224u,
                                       256u, 288u};
constexpr uint32_t kDelSpecial = 15u;
constexpr uint16_t kPndn       = 0x8000u;
constexpr uint16_t kPrpOnBits  = 0xC000u;
constexpr uint32_t kPrpShift   = 14u;
constexpr uint32_t kPrpOn      = 3u;
constexpr uint32_t kPrpWake    = 1u;

}  // namespace

void Wm97xxCodec::OnReady() {
    host_requests_ = &emu_.Get<HostRequestChannel>();
    host_requests_->RegisterListener([this] { DrainPenEdges(); });
}

void Wm97xxCodec::SetPenPosition(uint16_t raw_x, uint16_t raw_y) {
    raw_x_.store(raw_x, std::memory_order_relaxed);
    raw_y_.store(raw_y, std::memory_order_relaxed);
}

void Wm97xxCodec::QueuePenEdge(bool down) {
    {
        std::lock_guard<std::mutex> lk(edge_mtx_);
        edges_.push_back(down);
    }
    host_requests_->Request();
}

void Wm97xxCodec::DrainPenEdges() {
    std::vector<bool> edges;
    {
        std::lock_guard<std::mutex> lk(edge_mtx_);
        edges.swap(edges_);
    }
    for (bool down : edges) {
        if (down != pen_down_) LOG(Periph, "[WM97xx] pen %s\n", down ? "DOWN" : "UP");
        SetPenDown(down);
    }
}

uint32_t Wm97xxCodec::DelayFrames(uint32_t del, uint16_t reg_value) {
    if (del == kDelSpecial) {
        emu_.Get<Fatal>().Die("Wm97xxCodec: digitiser register 0x%04X selects DEL 1111; not modelled",
                              reg_value);
    }
    return kDelayFrames[del];
}

void Wm97xxCodec::SetPenDown(bool down) {
    if (down == pen_down_) return;
    pen_down_ = down;
    pen_line_(down);
    uint64_t frame = 0;
    if (!frames_->FrameAt(emu_.Get<GuestCycleClock>().Cycles(), frame)) {
        digitiser_.ClearHistory(down);
        WakeOnPen(false, 0u);
        return;
    }
    digitiser_.SetPen(frame + 1u, down);
    WakeOnPen(true, frame);
    frames_->OnCodecStreamChange();
}

/* Wolfson WM9705 page 50: in standby with PRP 01 a pen down sets "PRP[1] ... to active (1) and the pen
   digitiser wakes up"; Cirrus Logic WM9713L Rev 4.0 Table 47 (page 70): PRP 01 "touchpanel digitiser
   wakes up (changes to state 11) on pen-down", 11 "Pen digitiser and pen detect enabled". */
bool Wm97xxCodec::DigitiserPowered() {
    const uint16_t d2  = Peek(kRegDigitiserPower);
    uint32_t       prp = d2 >> kPrpShift;
    if (prp == kPrpWake && pen_down_) {
        Poke(kRegDigitiserPower, static_cast<uint16_t>(d2 | kPrpOnBits));
        prp = kPrpOn;
    }
    return prp == kPrpOn;
}

void Wm97xxCodec::WakeOnPen(bool linked, uint64_t frame) {
    if (!pen_down_ || (Peek(kRegDigitiserPower) >> kPrpShift) != kPrpWake) return;
    if (!linked) {
        emu_.Get<Fatal>().Die("Wm97xxCodec: pen-down wake-up with the AC-link stopped; not modelled");
    }
    Reconfigure(frame, false);
}

void Wm97xxCodec::LinkStopped(uint64_t frame) {
    if (digitiser_.Pending(frame)) {
        emu_.Get<Fatal>().Die("Wm97xxCodec: touch-panel conversions in progress when the AC-link stops at "
                              "frame %llu; not modelled", static_cast<unsigned long long>(frame));
    }
    digitiser_.ClearHistory(pen_down_);
}

/* Wolfson WM9705 page 42 (index 7Ah): PNDN 15 "Indicates whether Pen is Down", ADR[2:0] 14:12
   "Conversion Address", D[11:0] "ADC output result". */
uint16_t Wm97xxCodec::ResultWord(const Wm97xxDigitiser::Result& r) {
    const uint16_t data = static_cast<uint16_t>(ConversionData(r.tag) & kAdcMax);
    return static_cast<uint16_t>((r.pen_down ? kPndn : 0u) | ((r.tag & 7u) << 12) | data);
}

uint16_t Wm97xxCodec::LastResultWord(uint64_t frame, uint16_t held) {
    RequireNoTrip(frame + 1u);
    Wm97xxDigitiser::Result r;
    return digitiser_.LastResult(frame, r) ? ResultWord(r) : held;
}

void Wm97xxCodec::RequireNoTrip(uint64_t frames) {
    if (!digitiser_.TripReached(frames)) return;
    emu_.Get<Fatal>().Die("Wm97xxCodec: a polled touch-panel request with more than one channel selected "
                          "completed a conversion; not modelled");
}

uint64_t Wm97xxCodec::SlotWordsBefore(uint64_t frames) {
    RequireNoTrip(frames);
    return digitiser_.SlotWordsBefore(frames);
}

bool Wm97xxCodec::FrameOfSlotWord(uint64_t n, uint64_t& frame) {
    return digitiser_.FrameOfSlotWord(n, frame);
}

uint16_t Wm97xxCodec::SlotWord(uint64_t n) {
    Wm97xxDigitiser::Result r;
    if (!digitiser_.SlotWord(n, r)) {
        emu_.Get<Fatal>().Die("Wm97xxCodec: slot-5 word %llu is in no conversion burst",
                              static_cast<unsigned long long>(n));
    }
    return ResultWord(r);
}

void Wm97xxCodec::PruneSlotWords(uint64_t frames) { digitiser_.Prune(frames); }

void Wm97xxCodec::PostRestore() {
    if (!pen_down_) return;
    SetPenDown(false);
}

void Wm97xxCodec::SavePen(StateWriter& w) const {
    w.Write<uint8_t>("pen_down", pen_down_ ? 1u : 0u);
    digitiser_.Save(w);
}

void Wm97xxCodec::RestorePen(StateReader& r) {
    uint8_t down = 0;
    r.Read("pen_down", down);
    pen_down_ = down != 0u;
    digitiser_.Restore(r);
}
