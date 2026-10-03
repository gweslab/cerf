#include "sa11xx_ssp_stream.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "sa11xx_dma.h"
#include "sa11xx_gpio.h"
#include "sa11xx_intc.h"
#include "sa11xx_mcp.h"
#include "sa11xx_ppc.h"
#include "sa11xx_ssp_bit_clock.h"
#include "sa11xx_ssp_device.h"

#include <algorithm>

namespace {

/* SA-1110 Developer's Manual §11.12.9 SSCR0 (printed 11-158): DSS 3:0, FRF 5:4 (00 = Motorola SPI,
   01 = Texas Instruments), SSE 7; §11.12.10 SSCR1 (printed 11-162): RIE 0, TIE 1, LBM 2, ECS 5. */
constexpr uint32_t kDssMask    = 0xFu;
constexpr uint32_t kFrfShift   = 4;
constexpr uint32_t kFrfMotorola = 0u;
constexpr uint32_t kFrfTi      = 1u;
constexpr uint32_t kSse        = 1u << 7;
constexpr uint32_t kRie        = 1u << 0;
constexpr uint32_t kTie        = 1u << 1;
constexpr uint32_t kLbm        = 1u << 2;
constexpr uint32_t kEcs        = 1u << 5;

/* §11.12.12 SSSR (printed 11-165/166): TNF 1, RNE 2, BSY 3, TFS 4, RFS 5, ROR 6; §9.2.1.1
   (printed 9-12): IP19 "Serial port 4b", "SSP service request". */
constexpr uint32_t kTnf        = 1u << 1;
constexpr uint32_t kRne        = 1u << 2;
constexpr uint32_t kBsy        = 1u << 3;
constexpr uint32_t kTfs        = 1u << 4;
constexpr uint32_t kRfs        = 1u << 5;
constexpr uint32_t kRor        = 1u << 6;
constexpr uint32_t kIntcBitSsp = 1u << 19;

/* §11.12.7.3: "the transmit FIFO is 8 entries deep and the receive FIFO is 12 entries deep";
   TFS at four or fewer entries, RFS at "four or more entries" (§11.12.12.4-5); four half-word
   DMA bursts. */
constexpr uint32_t kTxDepth = 8u;
constexpr uint32_t kRxDepth = 12u;
constexpr uint32_t kBurst   = 4u;

/* §11.12.3 MCCR0 MCE bit 16; §11.13.5 PPAR (printed 11-173): SPR bit 18, with SPR 0 the SSP
   holds the serial port 4 pins "if MCE=0 and SSE=1". */
constexpr uint32_t kMccr0Mce = 1u << 16;
constexpr uint32_t kPparSpr  = 1u << 18;

/* §9.1.2 (printed 9-9): GP 10 SSP_TXD output, GP 11 SSP_RXD input, GP 12 SSP_SCLK output,
   GP 13 SSP_SFRM output. */
constexpr uint32_t kSspPinFirst = 10u;
constexpr uint32_t kSspRxdPin   = 11u;
constexpr uint32_t kSspPinLast  = 13u;

/* SA-1110 Developer's Manual Table 11-6: SSP transmit DS 1110, receive DS 1111. */
constexpr uint32_t kDsSspTransmit = 0xEu;
constexpr uint32_t kDsSspReceive  = 0xFu;

}

bool Sa11xxSspStream::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxSspStream::OnReady() {
    clock_   = &emu_.Get<GuestCycleClock>();
    intc_    = &emu_.Get<Sa11xxIntc>();
    dma_     = &emu_.Get<Sa11xxDma>();
    mcp_     = &emu_.Get<Sa11xxMcp>();
    ppc_     = &emu_.Get<Sa11xxPpc>();
    gpio_    = &emu_.Get<Sa11xxGpio>();
    bit_     = &emu_.Get<Sa11xxSspBitClock>();
    device_  = emu_.TryGet<Sa11xxSspDevice>();
    line_ev_ = clock_->Add([this] {
        const uint64_t now = clock_->Cycles();
        Settle(now);
        RefreshLine(now);
    });
    tx_.Configure(kTxDepth, kBurst, kBurst);
    rx_.Configure(kRxDepth, kRxDepth - kBurst, kBurst);
    rx_.Restore(kRxDepth, 0u);
    dma_->RegisterPort(kDsSspTransmit, &tx_port_);
    dma_->RegisterPort(kDsSspReceive, &rx_port_);
    bit_->SetListener([this](uint64_t now, bool stops) { BeforeClockChange(now, stops); },
                      [this](uint64_t now) { AfterClockChange(now); });
    mcp_->RegisterControlListener([this] { CheckPins(); });
    ppc_->RegisterPparListener([this] { CheckPins(); });
    gpio_->RegisterPinConfigListener([this] { CheckPins(); });
    /* §11.12.9.4 (printed 11-158): SSE resets to 0; §11.12.9.3: "Clearing SSE resets the SSP's
       FIFOs."; SSSR reset row (printed 11-165): ROR "?". */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        Disable();
        bit_->Stop();
        sscr0_    &= ~kSse;
        ror_       = false;
        tx_supply_ = 0u;
        rx_supply_ = 0u;
        tx_.SetSupply(0u);
        rx_.SetSupply(0u);
        RefreshLine(clock_->Cycles());
    });
}

void Sa11xxSspStream::BeforeClockChange(uint64_t now, bool stops) {
    Settle(now);
    if (stops && (tx_run_.Running() || data_busy_)) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: the GPIO 19 clock stops while frames run; not modelled");
    }
}

void Sa11xxSspStream::AfterClockChange(uint64_t now) {
    if (data_busy_ && !data_frame_.Rescale(now, clock_->ClockRate(), HalfBitRate())) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: bit rate overflows the cycle clock ratio");
    }
    RefreshLine(now);
    dma_->OnPortChange();
}

uint64_t Sa11xxSspStream::Frame() const {
    return (sscr0_ & kDssMask) + 1u;
}

/* §11.12.10 SSCR1 SPH (printed 11-162): "0 - SCLK is in its inactive state one full cycle at the
   start of the frame and one-half cycle at the end of the frame. 1 - ... one-half cycle at the
   start of the frame and one full cycle at the end." */
uint64_t Sa11xxSspStream::DataFrameTicks() const {
    return 2u * Frame() + 3u;
}

GuestCycleClock::Rate Sa11xxSspStream::HalfBitRate() const {
    const GuestCycleClock::Rate bit = bit_->BitRate();
    return GuestCycleClock::Rate{bit.num * 2u, bit.den};
}

GuestCycleClock::Rate Sa11xxSspStream::WordRate() const {
    const GuestCycleClock::Rate bit = bit_->BitRate();
    if (bit.num == 0u) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: DMA transfer before any SSP bit clock was selected; not "
                              "modelled");
    }
    return GuestCycleClock::Rate{bit.num, bit.den * Frame()};
}

/* §11.12.9.3: with the MCP enabled "the MCP has precedence and the SSP remains disabled" unless
   the PPAR SSP pin reassignment bit is set; PPAR SPR 1: SSP on GPIO 10-13, "GAFR and GPDR must be
   configured in GPIO unit". */
void Sa11xxSspStream::CheckPins() const {
    if (!enabled_) return;
    if ((ppc_->Ppar() & kPparSpr) == 0u) {
        if ((mcp_->Mccr0() & kMccr0Mce) != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxSsp: SSE set while the MCP holds the serial port 4 pins "
                                  "(MCCR0 0x%08X); not modelled", mcp_->Mccr0());
        }
        return;
    }
    for (uint32_t pin = kSspPinFirst; pin <= kSspPinLast; ++pin) {
        const Sa11xxGpio::PinConfig cfg = gpio_->Pin(pin);
        if (!cfg.alternate || cfg.output == (pin == kSspRxdPin)) {
            emu_.Get<Fatal>().Die("Sa11xxSsp: SSE set with PPAR SPR set and GPIO %u not routed to "
                                  "the SSP (GAFR %u, GPDR %u); not modelled", pin,
                                  cfg.alternate ? 1u : 0u, cfg.output ? 1u : 0u);
        }
    }
}

/* §11.12.9.3: "Clearing SSE resets the SSP's FIFOs." */
void Sa11xxSspStream::Disable() {
    enabled_   = false;
    data_busy_ = false;
    rx_pushed_ = 0u;
    rx_words_.clear();
    tx_run_.Reset();
    tx_.Clear();
    rx_.Restore(kRxDepth, rx_.Moved());
}

void Sa11xxSspStream::WriteControl(uint64_t now, uint32_t sscr0, uint32_t sscr1) {
    Settle(now);
    const bool sse = (sscr0 & kSse) != 0u;
    if (enabled_ && !sse) {
        Disable();
        bit_->Stop();
    } else if (enabled_ && (((sscr0 ^ sscr0_) & ~kSse) != 0u || ((sscr1 ^ sscr1_) & (kEcs | kLbm)) != 0u)) {
        if (tx_run_.Running() || data_busy_) {
            emu_.Get<Fatal>().Die("Sa11xxSsp: SSCR0 0x%08X -> 0x%08X / SSCR1 0x%08X -> 0x%08X while "
                                  "frames run; not modelled", sscr0_, sscr0, sscr1_, sscr1);
        }
        bit_->Change(now, sscr0, sscr1);
    } else if (!enabled_ && sse) {
        enabled_ = true;
        bit_->Start(now, sscr0, sscr1);
    }
    sscr0_ = sscr0;
    sscr1_ = sscr1;
    CheckPins();
    RefreshLine(now);
}

/* §11.12.7.1 (printed 11-153): "Once the bottom entry of the transmit FIFO contains data, SFRM is
   pulled low and remains low for the duration of the frame's transmission"; "For continuous
   transfers ... the SFRM line is continuously asserted (held low)". */
void Sa11xxSspStream::WriteData(uint64_t now, uint16_t value) {
    Settle(now);
    const uint32_t frf = (sscr0_ >> kFrfShift) & 0x3u;
    if (!enabled_ || frf != kFrfMotorola || (sscr0_ & kDssMask) < 3u || (sscr1_ & kLbm) != 0u ||
        !bit_->Clocked() || device_ == nullptr) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: SSDR write 0x%04X with SSCR0 0x%08X SSCR1 0x%08X; only "
                              "Motorola SPI frames of 4-16 bits on a known clock without loopback, "
                              "to an attached serial device, are modelled for programmed I/O",
                              value, sscr0_, sscr1_);
    }
    if (data_busy_ || tx_.Level() != 0u || tx_supply_ != 0u) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: SSDR write 0x%04X while a frame runs or the transmit FIFO "
                              "holds data; continuous transfers are not modelled", value);
    }
    if (!data_frame_.SetRate(clock_->ClockRate(), HalfBitRate())) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: bit rate overflows the cycle clock ratio");
    }
    data_frame_.Start(now);
    data_busy_ = true;
    data_word_ = value;
    RefreshLine(now);
}

/* §11.12.7.1 (printed 11-153): "the SFRM pin is pulled high one SCLK period after the last bit has
   been latched in the receive serial shifter, which causes the data to be transferred to the
   receive FIFO"; §11.12.12.6: on a full receive FIFO the word is lost and ROR set. */
void Sa11xxSspStream::SettleData(uint64_t now) {
    if (!data_busy_ || data_frame_.TicksAt(now) < DataFrameTicks()) return;
    data_busy_ = false;
    const uint16_t received = device_->Exchange(data_word_);
    if (rx_supply_ != 0u) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: a programmed-I/O frame ends with the receive DMA running; "
                              "not modelled");
    }
    if (rx_.Take(1u) != 0u) {
        ror_ = true;
        return;
    }
    rx_words_.push_back(received);
}

/* §11.12.11 (printed 11-162): "When SSDR is read, the bottom entry of receive FIFO is accessed." */
uint16_t Sa11xxSspStream::ReadData(uint64_t now) {
    Settle(now);
    if (rx_words_.empty()) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: SSDR read with no programmed-I/O word in the receive FIFO; "
                              "not modelled");
    }
    const uint16_t value = rx_words_.front();
    rx_words_.pop_front();
    rx_.Put();
    RefreshLine(now);
    return value;
}

/* §11.12.7.1 Figure 11-33: one SFRM clock, then "Bit N" to "Bit 0"; "Continuous Transfers" put
   the next SFRM over bit 0. "The received data is transferred from the serial shifter to the
   receive FIFO on the first rising edge of SCLK after the LSB has been latched." */
void Sa11xxSspStream::Settle(uint64_t now) {
    SettleData(now);
    if (!enabled_ || !bit_->Clocked()) return;
    const uint64_t s = bit_->TicksAt(now);
    const uint64_t f = Frame();
    tx_run_.Settle(s, f, tx_);
    if (s >= f + 1u) {
        const uint64_t pushed = tx_run_.LoadsBy(s - f - 1u, f);
        if (pushed > rx_pushed_) {
            if (rx_.Take(pushed - rx_pushed_) != 0u) ror_ = true;
            rx_pushed_ = pushed;
        }
    }
}

/* §11.12.7.1: "Once the bottom entry of the transmit FIFO contains data, SFRM is pulsed high
   for one SCLK period". */
void Sa11xxSspStream::StartRun(uint64_t now) {
    if (tx_run_.Running() || tx_.Level() == 0u) return;
    const uint32_t frf = (sscr0_ >> kFrfShift) & 0x3u;
    if (frf != kFrfTi || (sscr0_ & kDssMask) < 3u || (sscr1_ & kLbm) != 0u || !bit_->Clocked()) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: transmit data with SSCR0 0x%08X SSCR1 0x%08X; only Texas "
                              "Instruments frames of 4-16 bits on a known clock without loopback "
                              "are modelled", sscr0_, sscr1_);
    }
    const uint64_t t = bit_->TicksAt(now);
    tx_run_.Start(bit_->CycleOfTick(t) == now ? t : t + 1u);
}

/* §11.12.12 SSSR: TFS and RFS read 0 when the "SSP disabled"; §11.12.12.4: "The state of TFS is
   also sent to the DMA controller". */
void Sa11xxSspStream::SetSupply(uint64_t now, bool receive, uint64_t words) {
    Settle(now);
    const uint64_t supply = enabled_ ? words : 0u;
    if (supply != 0u && data_busy_) {
        emu_.Get<Fatal>().Die("Sa11xxSsp: DMA service during a programmed-I/O frame; not modelled");
    }
    (receive ? rx_supply_ : tx_supply_) = supply;
    DmaBurstFifo& fifo = receive ? rx_ : tx_;
    fifo.SetSupply(supply);
    fifo.Refill();
    if (!receive) StartRun(now);
    RefreshLine(now);
}

bool Sa11xxSspStream::TxCycleOfMoved(uint64_t words, uint64_t& cycle) {
    bool     immediate = false;
    uint64_t tick      = 0;
    if (!tx_run_.TickOfMoved(tx_, words, Frame(), immediate, tick)) return false;
    cycle = immediate ? clock_->Cycles() : bit_->CycleOfTick(tick);
    return true;
}

bool Sa11xxSspStream::RxCycleOfMoved(uint64_t words, uint64_t& cycle) {
    uint64_t m = 0;
    if (!rx_.TakesToMove(words, m)) return false;
    if (m == 0u) {
        cycle = clock_->Cycles();
        return true;
    }
    uint64_t tick = 0;
    if (!PushTick(m, tick)) return false;
    cycle = bit_->CycleOfTick(tick);
    return true;
}

bool Sa11xxSspStream::PopTick(uint64_t pop, uint64_t& tick) const {
    return enabled_ && bit_->Clocked() && tx_run_.NextLoadTick(pop, Frame(), tick);
}

bool Sa11xxSspStream::PushTick(uint64_t push, uint64_t& tick) const {
    uint64_t slot = 0;
    if (!enabled_ || !bit_->Clocked() || push == 0u ||
        !tx_run_.LoadTick(rx_pushed_ + push, Frame(), tx_.TakesBeforeEmpty(), slot)) {
        return false;
    }
    tick = slot + Frame() + 1u;
    return true;
}

/* §11.12.12 SSSR (printed 11-165/166): TFS and RFS need "SSP operation is enabled"; BSY while
   the SSP "is currently transmitting and/or receiving a frame"; ROR is the only read/write bit. */
uint32_t Sa11xxSspStream::Status(uint64_t now) {
    Settle(now);
    const uint32_t tx_level = tx_.Level();
    const uint32_t rx_level = kRxDepth - rx_.Level();
    uint32_t s = 0u;
    if (tx_level < kTxDepth) s |= kTnf;
    if (rx_level != 0u) s |= kRne;
    if (data_busy_ ||
        (enabled_ && bit_->Clocked() && tx_run_.Busy(bit_->TicksAt(now), Frame(), 1u))) {
        s |= kBsy;
    }
    if (enabled_ && tx_level <= kBurst) s |= kTfs;
    if (enabled_ && rx_level >= kBurst) s |= kRfs;
    if (ror_) s |= kRor;
    return s;
}

void Sa11xxSspStream::ClearOverrun(uint64_t now) {
    Settle(now);
    ror_ = false;
    RefreshLine(now);
}

/* §11.12.12.4-6: TFS and RFS request an interrupt "unless" TIE / RIE is cleared; "When the ROR
   bit is set, an interrupt request is made." */
bool Sa11xxSspStream::LineLevel() const {
    if (ror_) return true;
    if (!enabled_) return false;
    const bool tfs = tx_.Level() <= kBurst;
    const bool rfs = kRxDepth - rx_.Level() >= kBurst;
    return (tfs && (sscr1_ & kTie) != 0u) || (rfs && (sscr1_ & kRie) != 0u);
}

bool Sa11xxSspStream::NextRise(uint64_t& cycle) const {
    cycle = kNever;
    uint64_t at = 0;
    const uint64_t tx_left = tx_.TakesBeforeEmpty();
    if ((sscr1_ & kTie) != 0u && tx_left != DmaBurstFifo::kUnlimited && tx_left > kBurst &&
        PopTick(tx_left - kBurst, at)) {
        cycle = std::min(cycle, bit_->CycleOfTick(at));
    }
    const uint64_t rx_left = rx_.TakesBeforeEmpty();
    const uint64_t rx_lead = kRxDepth - kBurst;
    if (rx_left != DmaBurstFifo::kUnlimited) {
        if ((sscr1_ & kRie) != 0u && rx_left > rx_lead && PushTick(rx_left - rx_lead, at)) {
            cycle = std::min(cycle, bit_->CycleOfTick(at));
        }
        if (!ror_ && PushTick(rx_left + 1u, at)) cycle = std::min(cycle, bit_->CycleOfTick(at));
    }
    const uint32_t filled = kRxDepth - rx_.Level();
    if (data_busy_ && (((sscr1_ & kRie) != 0u && filled + 1u == kBurst) ||
                       (!ror_ && filled == kRxDepth))) {
        cycle = std::min(cycle, data_frame_.CycleOfTick(DataFrameTicks()));
    }
    return cycle != kNever;
}

void Sa11xxSspStream::RefreshLine(uint64_t now) {
    const bool level = LineLevel();
    intc_->SetSourceLevel(kIntcBitSsp, level ? kIntcBitSsp : 0u);
    uint64_t cycle = 0;
    if (!level && enabled_ && NextRise(cycle)) {
        clock_->Arm(line_ev_, std::max(cycle, now));
    } else {
        clock_->Disarm(line_ev_);
    }
}

void Sa11xxSspStream::Save(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    Settle(now);
    const RatedTickCount::Position frame =
        data_busy_ ? data_frame_.PositionAt(now) : RatedTickCount::Position{};
    w.Write<uint32_t>("stream_sscr0", sscr0_);
    w.Write<uint32_t>("stream_sscr1", sscr1_);
    w.Write<uint8_t>("stream_enabled", enabled_ ? 1u : 0u);
    w.Write<uint8_t>("stream_ror", ror_ ? 1u : 0u);
    bit_->Save(w);
    tx_run_.Save(w);
    w.Write<uint64_t>("stream_rx_pushed", rx_pushed_);
    w.Write<uint32_t>("stream_tx_level", tx_.Level());
    w.Write<uint64_t>("stream_tx_moved", tx_.Moved());
    w.Write<uint32_t>("stream_rx_free", rx_.Level());
    w.Write<uint64_t>("stream_rx_moved", rx_.Moved());
    w.Write<uint8_t>("stream_data_busy", data_busy_ ? 1u : 0u);
    w.Write<uint16_t>("stream_data_word", data_word_);
    w.Write<uint64_t>("stream_data_ticks", frame.ticks);
    w.Write<uint64_t>("stream_data_phase", frame.phase);
    w.Write<uint64_t>("stream_data_phase_den", frame.phase_den);
    w.Write<uint32_t>("stream_rx_word_count", static_cast<uint32_t>(rx_words_.size()));
    for (uint16_t v : rx_words_) w.Write("stream_rx_word", v);
}

void Sa11xxSspStream::Restore(StateReader& r) {
    uint8_t  enabled = 0, ror = 0, busy = 0;
    uint32_t tx_level = 0, rx_free = 0, n = 0;
    uint64_t tx_moved = 0, rx_moved = 0;
    RatedTickCount::Position frame;
    r.Read("stream_sscr0", sscr0_);
    r.Read("stream_sscr1", sscr1_);
    r.Read("stream_enabled", enabled);
    r.Read("stream_ror", ror);
    bit_->Restore(r);
    tx_run_.Restore(r);
    r.Read("stream_rx_pushed", rx_pushed_);
    r.Read("stream_tx_level", tx_level);
    r.Read("stream_tx_moved", tx_moved);
    r.Read("stream_rx_free", rx_free);
    r.Read("stream_rx_moved", rx_moved);
    r.Read("stream_data_busy", busy);
    r.Read("stream_data_word", data_word_);
    r.Read("stream_data_ticks", frame.ticks);
    r.Read("stream_data_phase", frame.phase);
    r.Read("stream_data_phase_den", frame.phase_den);
    rx_words_.clear();
    r.Read("stream_rx_word_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint16_t v = 0;
        r.Read("stream_rx_word", v);
        rx_words_.push_back(v);
    }
    enabled_   = enabled != 0u;
    ror_       = ror != 0u;
    data_busy_ = busy != 0u;
    tx_.Restore(tx_level, tx_moved);
    rx_.Restore(rx_free, rx_moved);
    tx_supply_ = 0u;
    rx_supply_ = 0u;
    tx_.SetSupply(0u);
    rx_.SetSupply(0u);
    if (!data_busy_) return;
    if (!data_frame_.SetRate(clock_->ClockRate(), HalfBitRate()) ||
        !data_frame_.PlaceAt(clock_->Cycles(), frame)) {
        r.Reject("Sa11xxSsp: the restored programmed-I/O frame at half-bit %llu does not fit the "
                 "current core ratio", static_cast<unsigned long long>(frame.ticks));
    }
}

REGISTER_SERVICE(Sa11xxSspStream);
