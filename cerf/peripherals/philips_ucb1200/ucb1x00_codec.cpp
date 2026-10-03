#include "ucb1x00_codec.h"

#include "ucb1x00_board.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../host/guest_deep_sleep.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint8_t kRegIoData   = 0x00;
constexpr uint8_t kRegIoDir    = 0x01;

/* UCB1300 datasheet p.49: IO_DATA / IO_DIR bits 0-9; a read of IO_DATA returns "the
   actual state of the associated I/O pin", an output pin carrying its written bit. */
constexpr uint16_t kIoPins = 0x03FFu;
constexpr uint8_t kRegIeRis    = 0x02;
constexpr uint8_t kRegIeFal    = 0x03;
constexpr uint8_t kRegIeStatus = 0x04;
constexpr uint8_t kRegTsCr     = 0x09;
constexpr uint8_t kRegAdcCr    = 0x0A;
constexpr uint8_t kRegAdcData  = 0x0B;
constexpr uint8_t kRegId       = 0x0C;
constexpr uint8_t kRegNull     = 0x0F;

/* NetBSD hpcmips ucb1200reg.h UCB1200_NULL_REG - "always returns 0xffff". */
constexpr uint16_t kNullValue = 0xFFFFu;

/* UCB1300 datasheet p.49-52, UCB1200 p.48-51, UCB1100 PDF index 29-32: the W and
   R/W bits of each register, the same on the three parts. */
constexpr std::array<uint16_t, 16> kDefinedWriteBits = {
    0x03FFu, 0x83FFu, 0xFBFFu, 0xFBFFu, 0xFBFFu, 0x00FFu, 0xE858u, 0x0FFFu,
    0xE15Fu, 0x0BFFu, 0x80BFu, 0x0000u, 0x0000u, 0xF03Fu, 0x0000u, 0x0000u,
};

/* UCB1300 datasheet, control register overview (p.49): IE bit 12 TSPX, bit 13 TSMX. */
constexpr uint16_t kIeTouch = (1u << 12) | (1u << 13);

/* Linux ucb1x00.h UCB_IO_0..9 and UCB_IE_ADC..UCB_IE_ACLIP (bits 11-15) list every
   interrupt source; ucb1x00-core.c ucb1x00_detect_irq writes 0xffff to UCB_IE_CLEAR. */
constexpr uint16_t kIeClearNoSource = 1u << 10;

constexpr uint16_t kTsCrModeMask = 3u << 8;
constexpr uint16_t kTsCrModePres = 1u << 8;
constexpr uint16_t kTsCrTspxLow  = 1u << 12;
constexpr uint16_t kTsCrTsmxLow  = 1u << 13;
constexpr uint16_t kTsCrBiasEna  = 1u << 11;

/* UCB1300 datasheet p.50-51, TS_CR: TSMX/TSPX/TSMY/TSPY_POW <3:0>, _GND <7:4>. */
enum class PlatePin { Floating, Powered, Grounded };

/* UCB1200 datasheet p.16: a pin programmed to power and ground at once is grounded. */
PlatePin TsPin(uint16_t ts_cr, unsigned index) {
    if ((ts_cr & (1u << (index + 4u))) != 0u) return PlatePin::Grounded;
    if ((ts_cr & (1u << index)) != 0u) return PlatePin::Powered;
    return PlatePin::Floating;
}

constexpr unsigned kPinTsmx = 0;
constexpr unsigned kPinTspx = 1;
constexpr unsigned kPinTsmy = 2;
constexpr unsigned kPinTspy = 3;

struct Plate {
    unsigned powered  = 0;
    unsigned grounded = 0;
};

Plate PlateOf(uint16_t ts_cr, unsigned minus_pin, unsigned plus_pin) {
    Plate p;
    for (const unsigned pin : {minus_pin, plus_pin}) {
        const PlatePin level = TsPin(ts_cr, pin);
        if (level == PlatePin::Powered)  ++p.powered;
        if (level == PlatePin::Grounded) ++p.grounded;
    }
    return p;
}

bool Biased(Plate p)   { return p.powered == 1u && p.grounded == 1u; }
bool Undriven(Plate p) { return p.powered == 0u && p.grounded == 0u; }

bool DrivesAcross(Plate from, Plate to) {
    return from.powered != 0u && from.grounded == 0u &&
           to.grounded == from.powered && to.powered == 0u;
}

constexpr uint16_t kAdcStart      = 1u << 7;
constexpr uint16_t kAdcVrefbypCon = 1u << 1;
constexpr uint16_t kAdcExtRefEna  = 1u << 5;
constexpr uint16_t kAdcEna        = 1u << 15;
constexpr uint16_t kAdcDatVal  = 1u << 15;
constexpr uint16_t kAdcInpMask = 7u << 2;
constexpr uint16_t kAdcInpTspx = 0u << 2;
constexpr uint16_t kAdcInpTsmx = 1u << 2;
constexpr uint16_t kAdcInpTspy = 2u << 2;
constexpr uint16_t kAdcInpTsmy = 3u << 2;
constexpr uint16_t kAdcInpAd0  = 4u << 2;

constexpr uint16_t kAdcDataShift = 5;
constexpr uint16_t kAdcDataMask  = 0x3FFu;

constexpr uint8_t kRegTelCtlB = 0x06;
constexpr uint8_t kRegAudCtlB = 0x08;
constexpr uint8_t kRegMode    = 0x0D;

/* UCB1300 datasheet p.50: TEL_CLIP_STAT reg 6 bit 4, AUD_CLIP_STAT reg 8 bit 6, set by
   the clip detector on the codec input path. */
constexpr uint16_t kTelClipStat = 1u << 4;
constexpr uint16_t kAudClipStat = 1u << 6;

/* UCB1300 datasheet p.52: MODE AUD_TEST<0> TEL_TEST<1> PROD_TEST_MODE<5:2>, note 1
   "Activating one or more test modes changes the functionality of the UCB1300";
   DYN_VFLAG_ENA<12>, A_BIG_ENDIAN<14>, T_BIG_ENDIAN<15>. */
constexpr uint16_t kModeUnmodelled = 0x003Fu | (1u << 12) | (1u << 14) | (1u << 15);

/* UCB1300 datasheet p.50: TEL_IN_ENA<14> and TEL_OUT_ENA<15> activate the telecom
   paths, AUD_LOOP<8> the audio codec loopback. */
constexpr uint16_t kTelCtlBUnmodelled = (1u << 14) | (1u << 15);
constexpr uint16_t kAudCtlBUnmodelled = 1u << 8;

constexpr size_t kMaxStates = 8;

}

Ucb1x00Codec::State Ucb1x00Codec::PowerOn(bool held) const {
    State s;
    s.regs = PowerOnRegs();
    s.held = held;
    return s;
}

void Ucb1x00Codec::OnReady() {
    states_.assign(1, PowerOn(false));
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        auto& reset = emu_.Get<GuestCpuReset>();
        std::lock_guard<std::mutex> lk(mutex_);
        if (kind == ResetLineKind::Rtc) {
            states_.assign(1, PowerOn(pin_ == ResetPin::Low));
            if (pin_ == ResetPin::Floating) ForkLocked("a power-on with the RESET pin floating");
        } else if (emu_.Get<Ucb1x00Board>().CodecSocResetReach() ==
                   Ucb1x00Board::SocResetReach::Unknown) {
            ForkLocked(reset.DeliveredResetWasResume() ? "a sleep-exit reset"
                       : kind == ResetLineKind::Watchdog ? "a watchdog reset"
                                                         : "a warm reset");
        }
        PublishIrqLocked();
    });
    emu_.Get<GuestDeepSleep>().RegisterPowerUpListener([this] {
        std::lock_guard<std::mutex> lk(mutex_);
        if (emu_.Get<Ucb1x00Board>().CodecSocResetReach() ==
            Ucb1x00Board::SocResetReach::Unknown) {
            ForkLocked("a Suspend State power-up");
        }
        PublishIrqLocked();
    });
}

void Ucb1x00Codec::ForkLocked(const char* event) {
    std::vector<State> next;
    for (const State& s : states_) {
        next.push_back(PowerOn(s.held));
        next.push_back(s);
    }
    states_     = std::move(next);
    fork_event_ = event;
    DedupeLocked();
}

void Ucb1x00Codec::DedupeLocked() {
    std::vector<State> unique;
    for (const State& s : states_) {
        bool seen = false;
        for (const State& u : unique) seen = seen || u == s;
        if (!seen) unique.push_back(s);
    }
    states_ = std::move(unique);
    if (states_.size() > kMaxStates) {
        emu_.Get<Fatal>().Die("ucb1x00: %zu codec states remain possible after %s",
                              states_.size(), fork_event_);
    }
}

/* UCB1300 datasheet p.32: RESET holds the internal reset asserted. */
void Ucb1x00Codec::DriveResetPin(ResetPin level) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (level == pin_) return;
    pin_ = level;
    if (level == ResetPin::Low) {
        states_.assign(1, PowerOn(true));
    } else if (level == ResetPin::High) {
        for (State& s : states_) s.held = false;
        DedupeLocked();
    } else {
        std::vector<State> next;
        for (State s : states_) {
            next.push_back(PowerOn(true));
            s.held = false;
            next.push_back(s);
        }
        states_     = std::move(next);
        fork_event_ = "the RESET pin floating";
        DedupeLocked();
    }
    PublishIrqLocked();
}

/* UCB1300 datasheet p.5, pin table note 6: "SIBDOUT reset state is 1 until the SIB bus
   is running." */
uint16_t Ucb1x00Codec::ReadStateLocked(const State& s, uint8_t reg) const {
    if (s.held) return 0xFFFFu;
    auto& board = emu_.Get<Ucb1x00Board>();
    switch (reg) {
        case kRegIoData: {
            const uint16_t out = s.regs[kRegIoDir] & kIoPins;
            const uint16_t in  = static_cast<uint16_t>(kIoPins & ~out);
            const uint16_t levels = in != 0u ? static_cast<uint16_t>(board.IoInputs(in) & in) : 0u;
            return static_cast<uint16_t>((s.regs[kRegIoData] & out) | levels);
        }
        case kRegIeStatus: return IrqStatus(s);
        case kRegTsCr:     return PenDetectTsCr(s);
        case kRegAdcCr:    return AdcCrReadBack(s.regs[kRegAdcCr]);
        case kRegAdcData:  return s.adc_data;
        case kRegTelCtlB:  return static_cast<uint16_t>(s.regs[reg] & ~kTelClipStat);
        case kRegAudCtlB:  return static_cast<uint16_t>(s.regs[reg] & ~kAudClipStat);
        case kRegId:       return DeviceId();
        case kRegNull:     return kNullValue;
        default:           return s.regs[reg];
    }
}

uint16_t Ucb1x00Codec::ReadReg(uint8_t reg) {
    const uint8_t r = reg & 0xFu;
    std::lock_guard<std::mutex> lk(mutex_);
    const uint16_t first = ReadStateLocked(states_[0], r);
    for (size_t i = 1; i < states_.size(); ++i) {
        const uint16_t v = ReadStateLocked(states_[i], r);
        if (v != first) {
            emu_.Get<Fatal>().Die("ucb1x00: register %u reads 0x%04X or 0x%04X depending on "
                                  "whether %s reached the codec; the board's codec RESET "
                                  "wiring does not settle it", r, first, v, fork_event_);
        }
    }
    return first;
}

bool Ucb1x00Codec::IrqAsserted() {
    std::lock_guard<std::mutex> lk(mutex_);
    return irq_out_;
}

bool Ucb1x00Codec::PenDown() { return pen_down_.load(std::memory_order_acquire); }

void Ucb1x00Codec::WriteStateLocked(State& s, uint8_t r, uint16_t value) {
    if (s.held) return;
    if (r == kRegIeStatus) {
        const uint16_t cleared = value & static_cast<uint16_t>(~s.regs[kRegIeStatus]);
        s.rise_ff &= static_cast<uint16_t>(~cleared);
        s.fall_ff &= static_cast<uint16_t>(~cleared);
    }
    /* UCB1300 datasheet p.51, ADC_START: a '0' to '1' transition starts the conversion. */
    const uint16_t prev_cr = s.regs[kRegAdcCr];
    const bool start = r == kRegAdcCr && (value & kAdcStart) != 0u &&
                       (prev_cr & kAdcStart) == 0u;
    s.regs[r] = value;
    if (start) Convert(s, prev_cr, value);
}

void Ucb1x00Codec::WriteReg(uint8_t reg, uint16_t value) {
    const uint8_t  r       = reg & 0xFu;
    const uint16_t defined = static_cast<uint16_t>(
        kDefinedWriteBits[r] | StubWriteBits(r) |
        (r == kRegTsCr ? (kTsCrTspxLow | kTsCrTsmxLow) : 0u) |
        (r == kRegIeStatus ? kIeClearNoSource : 0u));
    if (defined == 0u) {
        emu_.Get<Fatal>().Die("ucb1x00: write 0x%04X to register %u, which has no "
                              "writable bit", value, r);
    }
    if ((value & ~defined) != 0u) {
        emu_.Get<Fatal>().Die("ucb1x00: write 0x%04X to register %u sets bits 0x%04X "
                              "that the register map does not define", value, r,
                              static_cast<uint16_t>(value & ~defined));
    }
    if ((r == kRegIeRis || r == kRegIeFal) && (value & ~kIeTouch) != 0u) {
        emu_.Get<Fatal>().Die(
            "ucb1x00: %s-edge interrupt enable write 0x%04X enables a source other "
            "than TSPX/TSMX; only the touch sources are modelled",
            r == kRegIeRis ? "rising" : "falling", value);
    }
    const uint16_t unmodelled = r == kRegMode    ? kModeUnmodelled
                              : r == kRegTelCtlB ? kTelCtlBUnmodelled
                              : r == kRegAudCtlB ? kAudCtlBUnmodelled
                                                 : 0u;
    if ((value & unmodelled) != 0u) {
        emu_.Get<Fatal>().Die("ucb1x00: write 0x%04X to register %u sets bits 0x%04X, whose "
                              "effect on the codec is not modelled", value, r,
                              static_cast<uint16_t>(value & unmodelled));
    }
    std::lock_guard<std::mutex> lk(mutex_);
    for (State& s : states_) WriteStateLocked(s, r, value);
    DedupeLocked();
    PublishIrqLocked();
}

void Ucb1x00Codec::SetTouchPressed(bool pressed) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (pressed == pen_down_.load(std::memory_order_relaxed)) return;
    pen_down_.store(pressed, std::memory_order_release);
    for (State& s : states_) {
        if (s.held) continue;
        if (pressed) s.fall_ff |= kIeTouch;
        else         s.rise_ff |= kIeTouch;
    }
    DedupeLocked();
    PublishIrqLocked();
}

uint16_t Ucb1x00Codec::IrqStatus(const State& s) {
    return static_cast<uint16_t>((s.fall_ff & s.regs[kRegIeFal]) |
                                 (s.rise_ff & s.regs[kRegIeRis]));
}

bool Ucb1x00Codec::IrqLevelLocked() {
    const bool first = !states_[0].held && IrqStatus(states_[0]) != 0u;
    for (size_t i = 1; i < states_.size(); ++i) {
        const bool level = !states_[i].held && IrqStatus(states_[i]) != 0u;
        if (level != first) {
            emu_.Get<Fatal>().Die("ucb1x00: IRQOUT is %d or %d depending on whether %s "
                                  "reached the codec; the board's codec RESET wiring does "
                                  "not settle it", first ? 1 : 0, level ? 1 : 0, fork_event_);
        }
    }
    return first;
}

void Ucb1x00Codec::PublishIrqLocked() {
    const bool level = IrqLevelLocked();
    if (level == irq_out_) return;
    irq_out_ = level;
    emu_.Get<Ucb1x00Board>().OnIrqOutChanged(level);
}

/* UCB1300 datasheet p.51: TSPX_LOW / TSMX_LOW return the inverted pin state. */
uint16_t Ucb1x00Codec::PenDetectTsCr(const State& s) const {
    uint16_t v = static_cast<uint16_t>(s.regs[kRegTsCr] & ~(kTsCrTspxLow | kTsCrTsmxLow));
    if (pen_down_.load(std::memory_order_acquire) ==
        emu_.Get<Ucb1x00Board>().TsCrLowBitsSetOnTouch()) {
        v |= kTsCrTspxLow | kTsCrTsmxLow;
    }
    return v;
}

/* UCB1300 datasheet p.20-21: the ADC is enabled in a SIB frame before the start frame,
   and a result is readable in the next frame when the start frame keeps the mux. */
void Ucb1x00Codec::Convert(State& s, uint16_t prev_cr, uint16_t adc_cr) {
    auto& board = emu_.Get<Ucb1x00Board>();
    auto& fatal = emu_.Get<Fatal>();
    if ((prev_cr & adc_cr & kAdcEna) == 0u) {
        fatal.Die("ucb1x00: ADC_CR 0x%04X -> 0x%04X starts a conversion without ADC_ENA "
                  "set in an earlier SIB frame", prev_cr, adc_cr);
    }
    if (((prev_cr ^ adc_cr) & kAdcInpMask) != 0u) {
        fatal.Die("ucb1x00: ADC_CR 0x%04X -> 0x%04X changes the input multiplexer in the "
                  "start frame", prev_cr, adc_cr);
    }
    const bool ext_ref = (adc_cr & kAdcExtRefEna) != 0u;
    if (ext_ref != board.AdcExternalReference()) {
        fatal.Die("ucb1x00: ADC_CR 0x%04X converts with EXT_REF_ENA=%d on a board whose "
                  "VREFBYP pin carries %s reference", adc_cr, ext_ref ? 1 : 0,
                  board.AdcExternalReference() ? "an external" : "no external");
    }
    if (ext_ref && (adc_cr & kAdcVrefbypCon) != 0u) {
        fatal.Die("ucb1x00: ADC_CR 0x%04X connects the internal reference to VREFBYP while "
                  "EXT_REF_ENA selects an external one", adc_cr);
    }

    const uint16_t ts   = s.regs[kRegTsCr];
    const uint16_t mode = ts & kTsCrModeMask;
    const uint16_t chan = adc_cr & kAdcInpMask;

    const Plate x = PlateOf(ts, kPinTsmx, kPinTspx);
    const Plate y = PlateOf(ts, kPinTsmy, kPinTspy);
    uint16_t v = 0;
    if (mode == kTsCrModePres) {
        /* UCB1200 datasheet p.18: TSC_MODE 01 sets the ADC multiplexer to the touch
           screen current monitor, whatever ADC_INPUT selects. */
        if ((ts & kTsCrBiasEna) == 0u || (!DrivesAcross(x, y) && !DrivesAcross(y, x))) {
            fatal.Die("ucb1x00: pressure-mode conversion with TS_CR 0x%04X, which does not "
                      "bias the screen with one plate powered and the other grounded", ts);
        }
        v = board.TouchAdcPressure();
    } else if (chan >= kAdcInpAd0) {
        /* Linux ucb1x00-core.c ucb1x00_detect_irq converts with TS_CR at its reset
           value, TSC_MODE 00. */
        v = board.AuxAdc(static_cast<uint8_t>((chan >> 2) - 4u));
    } else {
        if (mode == 0u || (ts & kTsCrBiasEna) == 0u) {
            fatal.Die("ucb1x00: touch channel %u conversion with TS_CR 0x%04X, in interrupt "
                      "mode or with the touch screen bias off", chan >> 2, ts);
        }
        if (Biased(x) && Undriven(y) && (chan == kAdcInpTspy || chan == kAdcInpTsmy)) {
            v = board.TouchAdcX();
        } else if (Biased(y) && Undriven(x) && (chan == kAdcInpTspx || chan == kAdcInpTsmx)) {
            v = board.TouchAdcY();
        } else {
            fatal.Die("ucb1x00: position conversion of touch channel %u with TS_CR 0x%04X, "
                      "which does not bias one plate and read the other", chan >> 2, ts);
        }
    }

    s.adc_data = static_cast<uint16_t>(kAdcDatVal | ((v & kAdcDataMask) << kAdcDataShift));
}

void Ucb1x00Codec::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mutex_);
    w.Write<uint32_t>("reset_pin", static_cast<uint32_t>(pin_));
    w.Write<uint32_t>("irq_out", irq_out_ ? 1u : 0u);
    w.Write<uint32_t>("state_count", static_cast<uint32_t>(states_.size()));
    for (const State& s : states_) {
        w.WriteBytes("regs", s.regs.data(), sizeof(uint16_t) * s.regs.size());
        w.Write("adc_data", s.adc_data);
        w.Write<uint16_t>("rise_ff", s.rise_ff);
        w.Write<uint16_t>("fall_ff", s.fall_ff);
        w.Write<uint32_t>("held", s.held ? 1u : 0u);
    }
}

void Ucb1x00Codec::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mutex_);
    uint32_t pin = 0, out = 0, count = 0;
    r.Read("reset_pin", pin);
    r.Read("irq_out", out);
    r.Read("state_count", count);
    std::vector<State> states(count);
    for (State& s : states) {
        uint32_t held = 0;
        r.ReadBytes("regs", s.regs.data(), sizeof(uint16_t) * s.regs.size());
        r.Read("adc_data", s.adc_data);
        r.Read("rise_ff", s.rise_ff);
        r.Read("fall_ff", s.fall_ff);
        r.Read("held", held);
        s.held = held != 0u;
    }
    pin_        = static_cast<ResetPin>(pin);
    irq_out_    = out != 0u;
    states_     = std::move(states);
    fork_event_ = "a reset before the state was saved";
    pen_down_.store(false, std::memory_order_release);
}
