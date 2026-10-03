#include "sa11xx_mcp_audio_stream.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "sa11xx_dma.h"
#include "sa11xx_intc.h"

#include <algorithm>

namespace {

/* SA-1110 Developer's Manual §11.12.3 MCCR0 (printed 11-137/138): ASD 6:0, MCE 16, ECS 17,
   ADM 18, TTE 19, TRE 20, ATE 21, ARE 22, LBM 23; §11.12.4 MCCR1: CFS 20. */
constexpr uint32_t kAsdMask = 0x7Fu;
constexpr uint32_t kMce     = 1u << 16;
constexpr uint32_t kEcs     = 1u << 17;
constexpr uint32_t kAdm     = 1u << 18;
constexpr uint32_t kTte     = 1u << 19;
constexpr uint32_t kAte     = 1u << 21;
constexpr uint32_t kAre     = 1u << 22;
constexpr uint32_t kLbm     = 1u << 23;
constexpr uint32_t kCfs     = 1u << 20;

/* §11.12.1.2 Figure 11-31: the counter decrements once per 32 SCLK, "32*12=384" SCLK for a
   divisor of 12. */
constexpr uint64_t kTicksPerStep = 32u;

/* §11.12.1.3 (printed 11-131): "the audio and telecom transmit FIFOs are 8-entries deep and the
   audio and telecom receive FIFOs are 12-entries deep"; MCSR (printed 11-149): ATS at "four or
   fewer entries filled", ARS at "four or more entries filled"; Table 11-1: an 8-byte burst. */
constexpr uint32_t kTxDepth   = 8u;
constexpr uint32_t kRxDepth   = 12u;
constexpr uint32_t kRequestAt = 4u;
constexpr uint32_t kBurst     = 4u;

/* §11.12.6 MCSR (printed 11-149/150): ATS 0, ARS 1, TTS 2, ATU 4, ARO 5, ANF 8, ANE 9, TNF 10,
   ACE 14. */
constexpr uint32_t kAts = 1u << 0;
constexpr uint32_t kArs = 1u << 1;
constexpr uint32_t kTts = 1u << 2;
constexpr uint32_t kAtu = 1u << 4;
constexpr uint32_t kAro = 1u << 5;
constexpr uint32_t kAnf = 1u << 8;
constexpr uint32_t kAne = 1u << 9;
constexpr uint32_t kTnf = 1u << 10;
constexpr uint32_t kAce = 1u << 14;

/* Linux ucb1x00 UCB_TC_B 0x06, UCB_AC_B 0x08, *_IN_ENA (1 << 14); SA-1110 §11.12.6.15 and
   §11.12.6.16: register 8 or register 6 with bit 14 or 15 set. */
constexpr uint32_t kCodecTelecomB = 6u;
constexpr uint32_t kCodecAudioB   = 8u;
constexpr uint16_t kCodecInEna    = 0x4000u;
constexpr uint16_t kCodecEnables  = 0xC000u;

/* Linux mach-sa1100 DDAR_Ser4MCP0Tr DS 0xA, DDAR_Ser4MCP0Rc DS 0xB; SA-1110 §9.2.1.1 (printed
   9-12): IP18 "Serial port 4a", "MCP service request". */
constexpr uint32_t kDsMcpAudioTransmit = 0xAu;
constexpr uint32_t kDsMcpAudioReceive  = 0xBu;
constexpr uint32_t kIntcBitMcp         = 1u << 18;

}

bool Sa11xxMcpAudioStream::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxMcpAudioStream::OnReady() {
    clock_   = &emu_.Get<GuestCycleClock>();
    dma_     = &emu_.Get<Sa11xxDma>();
    intc_    = &emu_.Get<Sa11xxIntc>();
    line_ev_ = clock_->Add([this] {
        const uint64_t now = clock_->Cycles();
        Settle(now);
        RefreshLine(now);
    });
    tx_.Configure(kTxDepth, kRequestAt, kBurst);
    rx_.Configure(kRxDepth, kRxDepth - kRequestAt, kBurst);
    rx_.Restore(kRxDepth, 0u);
    dma_->RegisterPort(kDsMcpAudioTransmit, &tx_port_);
    dma_->RegisterPort(kDsMcpAudioReceive, &rx_port_);
    clock_->RegisterRateListener([this] {
        OnCpuRate(clock_->Cycles());
        dma_->OnPortChange();
    });
    /* §11.12.3.11: MCE resets to 0; MCSR reset row (printed 11-149): ATU and ARO "?", ACE 0;
       §11.12.5.1: the audio FIFOs are cleared "when the SA-1110 is reset". */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        Disable();
        mccr0_ &= ~kMce;
        atu_ = false;
        aro_ = false;
        RefreshLine(clock_->Cycles());
    });
}

/* §11.12.1: "dividing either by 5 (9.58464 MHz) or by 4 (11.9808 MHz)" the 3.6864 MHz oscillator
   multiplied by 13; MCCR1 CFS 1 = 9.585 MHz. */
uint64_t Sa11xxMcpAudioStream::SclkHz(uint32_t mccr1) const {
    return (mccr1 & kCfs) != 0u ? 9584640u : 11980800u;
}

uint64_t Sa11xxMcpAudioStream::Period() const {
    return kTicksPerStep * (mccr0_ & kAsdMask);
}

bool Sa11xxMcpAudioStream::SclkTick(uint64_t now, uint64_t& tick) const {
    if (!enabled_) return false;
    tick = sclk_.TicksAt(now);
    return true;
}

uint64_t Sa11xxMcpAudioStream::NextFrameEdge(uint64_t now) const {
    return (sclk_.TicksAt(now) / kFrameTicks + 1u) * kFrameTicks;
}

GuestCycleClock::Rate Sa11xxMcpAudioStream::WordRate() const {
    const uint32_t asd = mccr0_ & kAsdMask;
    if (asd < 6u) {
        emu_.Get<Fatal>().Die("Sa11xxMcp: audio DMA transfer with MCCR0 0x%08X ASD %u; §11.12.3.1 "
                              "makes ASD below 6 unpredictable", mccr0_, asd);
    }
    return GuestCycleClock::Rate{SclkHz(mccr1_), Period()};
}

/* §11.12.5.1: "the transmit and receive audio FIFOs are cleared when the SA-1110 is reset or by
   writing a zero to MCE". */
void Sa11xxMcpAudioStream::Disable() {
    enabled_   = false;
    rx_armed_  = false;
    counter_.Reset();
    codec_b_   = 0u;
    rx_pushed_ = 0u;
    rx_schedule_.Close();
    tx_.Clear();
    tx_.SetSupply(0u);
    rx_.Restore(kRxDepth, rx_.Moved());
    rx_.SetSupply(0u);
}

/* §11.12.1.1: "After the MCP is enabled, SCLK begins to transition at the programmed clock rate
   and the start of the first frame is signalled by pulsing the SFRM". */
void Sa11xxMcpAudioStream::WriteControl(uint64_t now, uint32_t mccr0, uint32_t mccr1) {
    Settle(now);
    const bool mce = (mccr0 & kMce) != 0u;
    if (enabled_ && !mce) {
        /* §11.12.3.3 (printed 11-135): "Clearing MCE resets the MCP's FIFOs. However, MCP data
           register 3, the control, and the status registers are not reset." */
        if (counter_.Counting()) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCCR0 0x%08X clears MCE while the audio sample counter "
                                  "runs (ACE 1); the counter and ACE across a disabled MCP are not "
                                  "modelled", mccr0);
        }
        Disable();
    } else if (!enabled_ && mce) {
        if ((mccr0 & (kEcs | kLbm)) != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCCR0 0x%08X enables the MCP with the GPIO 21 clock "
                                  "or loopback; not modelled", mccr0);
        }
        if (!sclk_.SetRate(clock_->ClockRate(), GuestCycleClock::Rate{SclkHz(mccr1), 1u})) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: SCLK rate overflows the cycle clock ratio");
        }
        sclk_.Start(now);
        enabled_ = true;
        ++run_;
    } else if (enabled_) {
        if (((mccr0 ^ mccr0_) & (kEcs | kLbm)) != 0u || ((mccr1 ^ mccr1_) & kCfs) != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCCR0 0x%08X -> 0x%08X / MCCR1 0x%08X -> 0x%08X change "
                                  "the clock or loopback of an enabled MCP; not modelled",
                                  mccr0_, mccr0, mccr1_, mccr1);
        }
        if (counter_.Counting() && ((mccr0 ^ mccr0_) & (kAsdMask | kAdm)) != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCCR0 0x%08X -> 0x%08X changes ASD or ADM while the "
                                  "audio sample counter runs; not modelled", mccr0_, mccr0);
        }
        if (rx_armed_ && ((mccr0 ^ mccr0_) & kAdm) != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCCR0 0x%08X -> 0x%08X changes ADM after the first "
                                  "stored sample of this MCP enable; not modelled", mccr0_, mccr0);
        }
    }
    mccr0_ = mccr0;
    mccr1_ = mccr1;
    RefreshLine(now);
}

/* §11.12.3 MCCR0 ADM (printed 11-138): "1- Audio and telecom receive data is stored when the
   receive data valid bit is set the first time, and from that point on whenever the MCP's audio
   and telecom sample rate counters time out." */
void Sa11xxMcpAudioStream::OpenReceive(uint64_t origin, uint64_t first_valid) {
    if ((mccr0_ & kAdm) == 0u) {
        emu_.Get<Fatal>().Die("Sa11xxMcp: audio input enabled with MCCR0 0x%08X ADM 0; storing on "
                              "the codec data valid bit is not modelled", mccr0_);
    }
    rx_schedule_.Open(origin, Period(), first_valid);
    rx_pushed_ = 0u;
}

/* §11.12.3.1: the sample clock starts at "the rising edge of the next SFRM pulse after the write
   has been made"; Figure 11-31: "The register is updated with the write at the end of subframe".
   §11.12.6.16: TCE follows a write to Telecom Control Register B with bit 14 or 15 set. */
bool Sa11xxMcpAudioStream::CodecWrite(uint64_t now, uint32_t reg, uint16_t value) {
    if (reg == kCodecTelecomB && (value & kCodecEnables) != 0u) {
        emu_.Get<Fatal>().Die("Sa11xxMcp: telecom control B write 0x%04X enables the telecom codec; "
                              "the telecom path is not modelled", value);
    }
    if (reg != kCodecAudioB) return false;
    const uint16_t before = codec_b_;
    codec_b_ = value;
    const bool on     = (value & kCodecEnables) != 0u;
    const bool was_on = (before & kCodecEnables) != 0u;
    const bool in     = (value & kCodecInEna) != 0u;
    const bool was_in = (before & kCodecInEna) != 0u;
    if (!on && !was_on) return false;
    if (!enabled_) {
        emu_.Get<Fatal>().Die("Sa11xxMcp: audio control B write 0x%04X with MCE clear; the frame "
                              "that carries it is not modelled", value);
    }
    Settle(now);
    const uint64_t latch = NextFrameEdge(now) + Sa11xxMcpAudioStream::kFrameTicks / 2u;
    const uint64_t edge  = NextFrameEdge(now) + kFrameTicks;
    if (counter_.ReloadPending()) {
        emu_.Get<Fatal>().Die("Sa11xxMcp: audio control B write 0x%04X before the counter reload at "
                              "SCLK %llu took effect; not modelled", value,
                              static_cast<unsigned long long>(counter_.StopTick()));
    }
    /* Figure 11-31 (printed 11-129): the counters run through the frame that carries the write. */
    if (on) {
        if (counter_.DisablePending()) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: audio codec enabled again before its disable at SCLK "
                                  "%llu took effect", static_cast<unsigned long long>(counter_.StopTick()));
        }
        const uint32_t asd = mccr0_ & kAsdMask;
        if (asd < 6u) {
            emu_.Get<Fatal>().Die("Sa11xxMcp: audio sample counter enabled with ASD %u; §11.12.3.1 "
                                  "makes ASD below 6 unpredictable", asd);
        }
        if (counter_.Counting()) counter_.Reload(edge);
        else                     counter_.Enable(edge);
    } else {
        counter_.Disable(edge);
    }
    /* §11.12.1.3 (printed 11-130): "Audio data is transferred from the incoming data frames to
       the receive FIFO only if the audio enable bit is set within the MCP's status register";
       §11.12.6.15: ACE clears at the SFRM after the frame that carries the disable. */
    /* §11.12.3.5 (printed 11-135): "When ADM=1, after the MCP is enabled, data is taken from the
       incoming frame when the data valid bit is set for the first time. After this point, the data
       valid bit is ignored". */
    if (!rx_schedule_.IsOpen() && ((in && !was_in) || (on && rx_armed_))) {
        OpenReceive(edge, latch);
    } else if (on && rx_schedule_.IsOpen()) {
        rx_schedule_.Reload(edge);
    }
    if (!on && rx_schedule_.IsOpen()) rx_schedule_.Limit(NextFrameEdge(now));
    RefreshLine(now);
    return true;
}

/* §11.12.1.3: each reload "triggers the audio transmit FIFO to transfer the next" entry;
   §11.12.6.5 ATU: a fetch "after it has been completely emptied"; §11.12.6.6 ARO: a place
   "into the audio receive FIFO after it has been completely filled". */
void Sa11xxMcpAudioStream::Settle(uint64_t now) {
    if (!enabled_) return;
    const uint64_t t     = sclk_.TicksAt(now);
    const uint64_t takes = counter_.Settle(t, Period());
    if (takes != 0u && tx_.Take(takes) != 0u) atu_ = true;
    const uint64_t pushed = rx_schedule_.PushesBy(t);
    if (pushed > rx_pushed_) {
        if (rx_.Take(pushed - rx_pushed_) != 0u) aro_ = true;
        rx_pushed_ = pushed;
        rx_armed_  = true;
    }
    rx_schedule_.Advance(rx_pushed_);
    if (rx_schedule_.IsOpen() && !rx_schedule_.Pending(rx_pushed_) && !counter_.Counting()) {
        rx_schedule_.Close();
    }
}

/* §11.12.6.1: ATS is 0 when the "MCP is disabled"; "The state of ATS is also sent to the DMA
   controller"; §11.12.6.2: likewise ARS. */
void Sa11xxMcpAudioStream::SetSupply(uint64_t now, bool receive, uint64_t words) {
    Settle(now);
    DmaBurstFifo& fifo = receive ? rx_ : tx_;
    fifo.SetSupply(enabled_ ? words : 0u);
    fifo.Refill();
    RefreshLine(now);
}

bool Sa11xxMcpAudioStream::TakeTick(uint64_t take, uint64_t& tick) const {
    return enabled_ && counter_.TakeTick(take, Period(), tick);
}

bool Sa11xxMcpAudioStream::TxCycleOfMoved(uint64_t words, uint64_t& cycle) {
    uint64_t n = 0, tick = 0;
    if (!tx_.TakesToMove(words, n)) return false;
    if (n == 0u) {
        cycle = clock_->Cycles();
        return true;
    }
    if (!TakeTick(n, tick)) return false;
    cycle = sclk_.CycleOfTick(tick);
    return true;
}

bool Sa11xxMcpAudioStream::RxCycleOfMoved(uint64_t words, uint64_t& cycle) {
    uint64_t m = 0, tick = 0;
    if (!rx_.TakesToMove(words, m)) return false;
    if (m == 0u) {
        cycle = clock_->Cycles();
        return true;
    }
    if (!enabled_ || !rx_schedule_.TickOfPush(rx_pushed_ + m, tick)) return false;
    cycle = sclk_.CycleOfTick(tick);
    return true;
}

/* §11.12.6 MCSR (printed 11-149/150): ATS, ARS and TTS need "MCP operation is enabled";
   §11.12.6.15: ACE from the SFRM after the register 8 write. */
uint32_t Sa11xxMcpAudioStream::Status(uint64_t now) {
    Settle(now);
    const uint32_t tx_level = tx_.Level();
    const uint32_t rx_level = kRxDepth - rx_.Level();
    uint32_t s = kTnf;
    if (enabled_ && tx_level <= kRequestAt) s |= kAts;
    if (enabled_ && rx_level >= kRequestAt) s |= kArs;
    if (enabled_) s |= kTts;
    if (atu_) s |= kAtu;
    if (aro_) s |= kAro;
    if (tx_level < kTxDepth) s |= kAnf;
    if (rx_level != 0u) s |= kAne;
    if (enabled_ && counter_.Active(sclk_.TicksAt(now))) s |= kAce;
    return s;
}

/* §11.12.6: "Writing a one to a sticky status bit clears it; writing a zero has no effect." */
void Sa11xxMcpAudioStream::ClearStatus(uint64_t now, uint32_t mask) {
    Settle(now);
    if ((mask & kAtu) != 0u) atu_ = false;
    if ((mask & kAro) != 0u) aro_ = false;
    RefreshLine(now);
}

/* §11.12.6: "A bit that can cause an interrupt signals the interrupt request as long as the bit
   is set"; ATS / ARS / TTS request "if not masked (if ATE=1)" and the like; ATU and ARO request
   unconditionally. */
bool Sa11xxMcpAudioStream::LineLevel() const {
    if (atu_ || aro_) return true;
    if (!enabled_) return false;
    const bool ats = tx_.Level() <= kRequestAt;
    const bool ars = kRxDepth - rx_.Level() >= kRequestAt;
    return (ats && (mccr0_ & kAte) != 0u) || (ars && (mccr0_ & kAre) != 0u) ||
           (mccr0_ & kTte) != 0u;
}

bool Sa11xxMcpAudioStream::NextRise(uint64_t& tick) const {
    if (!enabled_) return false;
    tick = kNever;
    uint64_t at = 0;
    const uint64_t tx_left = tx_.TakesBeforeEmpty();
    if (tx_left != DmaBurstFifo::kUnlimited) {
        if ((mccr0_ & kAte) != 0u && tx_left > kRequestAt &&
            TakeTick(tx_left - kRequestAt, at)) {
            tick = std::min(tick, at);
        }
        if (!atu_ && TakeTick(tx_left + 1u, at)) tick = std::min(tick, at);
    }
    const uint64_t rx_left = rx_.TakesBeforeEmpty();
    const uint32_t rx_lead = kRxDepth - kRequestAt;
    if (rx_left != DmaBurstFifo::kUnlimited) {
        if ((mccr0_ & kAre) != 0u && rx_left > rx_lead &&
            rx_schedule_.TickOfPush(rx_pushed_ + rx_left - rx_lead, at)) {
            tick = std::min(tick, at);
        }
        if (!aro_ && rx_schedule_.TickOfPush(rx_pushed_ + rx_left + 1u, at)) {
            tick = std::min(tick, at);
        }
    }
    return tick != kNever;
}

void Sa11xxMcpAudioStream::RefreshLine(uint64_t now) {
    const bool level = LineLevel();
    intc_->SetSourceLevel(kIntcBitMcp, level ? kIntcBitMcp : 0u);
    uint64_t tick = 0;
    if (!level && NextRise(tick)) {
        clock_->Arm(line_ev_, std::max(sclk_.CycleOfTick(tick), now));
    } else {
        clock_->Disarm(line_ev_);
    }
}

void Sa11xxMcpAudioStream::OnCpuRate(uint64_t now) {
    if (!enabled_) return;
    Settle(now);
    if (!sclk_.Rescale(now, clock_->ClockRate(), GuestCycleClock::Rate{SclkHz(mccr1_), 1u})) {
        emu_.Get<Fatal>().Die("Sa11xxMcp: SCLK rate overflows the cycle clock ratio");
    }
    RefreshLine(now);
}

void Sa11xxMcpAudioStream::Save(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    Settle(now);
    const RatedTickCount::Position pos = enabled_ ? sclk_.PositionAt(now) : RatedTickCount::Position{};
    w.Write<uint8_t>("audio_enabled", enabled_ ? 1u : 0u);
    w.Write<uint8_t>("audio_atu", atu_ ? 1u : 0u);
    w.Write<uint8_t>("audio_aro", aro_ ? 1u : 0u);
    w.Write<uint8_t>("audio_rx_armed", rx_armed_ ? 1u : 0u);
    w.Write<uint32_t>("audio_mccr0", mccr0_);
    w.Write<uint32_t>("audio_mccr1", mccr1_);
    w.Write<uint16_t>("audio_codec_b", codec_b_);
    counter_.Save(w);
    w.Write<uint32_t>("audio_run", run_);
    w.Write<uint32_t>("audio_fifo_level", tx_.Level());
    w.Write<uint64_t>("audio_fifo_moved", tx_.Moved());
    w.Write<uint32_t>("audio_rx_free", rx_.Level());
    w.Write<uint64_t>("audio_rx_moved", rx_.Moved());
    w.Write<uint64_t>("audio_rx_pushed", rx_pushed_);
    rx_schedule_.Save(w);
    w.Write<uint64_t>("audio_sclk_ticks", pos.ticks);
    w.Write<uint64_t>("audio_sclk_phase", pos.phase);
    w.Write<uint64_t>("audio_sclk_phase_den", pos.phase_den);
}

void Sa11xxMcpAudioStream::Restore(StateReader& r) {
    uint8_t enabled = 0, atu = 0, aro = 0, armed = 0;
    uint32_t tx_level = 0, rx_free = 0;
    uint64_t tx_moved = 0, rx_moved = 0;
    RatedTickCount::Position pos;
    r.Read("audio_enabled", enabled);
    r.Read("audio_atu", atu);
    r.Read("audio_aro", aro);
    r.Read("audio_rx_armed", armed);
    r.Read("audio_mccr0", mccr0_);
    r.Read("audio_mccr1", mccr1_);
    r.Read("audio_codec_b", codec_b_);
    counter_.Restore(r);
    r.Read("audio_run", run_);
    r.Read("audio_fifo_level", tx_level);
    r.Read("audio_fifo_moved", tx_moved);
    r.Read("audio_rx_free", rx_free);
    r.Read("audio_rx_moved", rx_moved);
    r.Read("audio_rx_pushed", rx_pushed_);
    rx_schedule_.Restore(r);
    r.Read("audio_sclk_ticks", pos.ticks);
    r.Read("audio_sclk_phase", pos.phase);
    r.Read("audio_sclk_phase_den", pos.phase_den);
    enabled_  = enabled != 0u;
    atu_      = atu != 0u;
    aro_      = aro != 0u;
    rx_armed_ = armed != 0u;
    tx_.Restore(tx_level, tx_moved);
    rx_.Restore(rx_free, rx_moved);
    tx_.SetSupply(0u);
    rx_.SetSupply(0u);
    if (!enabled_) return;
    if (!sclk_.SetRate(clock_->ClockRate(), GuestCycleClock::Rate{SclkHz(mccr1_), 1u}) ||
        !sclk_.PlaceAt(clock_->Cycles(), pos)) {
        r.Reject("Sa11xxMcp: the restored SCLK at %llu phase %llu/%llu does not fit the current "
                 "core ratio", static_cast<unsigned long long>(pos.ticks),
                 static_cast<unsigned long long>(pos.phase),
                 static_cast<unsigned long long>(pos.phase_den));
    }
}

REGISTER_SERVICE(Sa11xxMcpAudioStream);
