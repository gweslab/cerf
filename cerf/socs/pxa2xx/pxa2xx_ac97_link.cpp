#include "pxa2xx_ac97_link.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../peripherals/ac97_codec.h"
#include "../../state/state_stream.h"
#include "../pxa255/pxa255_id.h"
#include "../pxa27x/pxa270_id.h"

namespace {

/* AC '97 Component Specification Revision 2.1 section 5.1.2 (page 31): slot 0 "containing
   16-bits", then "20-bit time slots"; sections 5.1.1.2-5.1.1.3 (page 30): slot 1 the command
   address port, slot 2 the command data port. */
constexpr uint64_t kSlot2End = 16u + 20u + 20u;
constexpr uint32_t kRegPowerdown  = 0x26u;
constexpr uint32_t kRegGpioStatus = 0x54u;
/* AC '97 Component Specification Revision 2.1 Appendix D.6.2.1 Table 54 and D.6.2.2 Table 55 (page 102):
   Trst2clk "RESET# inactive to BIT_CLK startup delay" min 162.8 ns; Tsync_high min 1.0 us, Tsync2clk min
   162.8 ns; no typical or maximum value is given. */
constexpr uint64_t kColdStartPs  = 162800u;
constexpr uint64_t kWarmStartPs  = 1000000u + 162800u;
constexpr uint64_t kPsPerSecond  = 1000000000000u;
/* Intel PXA255 Developer's Manual section 13.5.2.2 (page 13-14): "the AC-link must wait for a minimum of four
   audio frame times after the frame in which the power down occurred before it can be reactivated". */
constexpr uint64_t kPowerDownWaitPs = (Pxa2xxAc97Link::kBitsPerFrame - kSlot2End + 4u * Pxa2xxAc97Link::kBitsPerFrame) *
                                      kPsPerSecond / Pxa2xxAc97Link::kBitClockHz;

}  // namespace

bool Pxa2xxAc97Link::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Pxa255 || bd->GetSocId() == SocId::Pxa270);
}

void Pxa2xxAc97Link::OnReady() {
    clock_     = &emu_.Get<GuestCycleClock>();
    codec_     = emu_.TryGet<Ac97Codec>();
    cmd_ev_    = clock_->Add([this] { Settle(clock_->Cycles()); });
    notify_ev_ = clock_->Add([this] { NotifyEvent(); });
    start_ev_  = clock_->Add([this] { OnStartEvent(); });
    clock_->RegisterRateListener([this] { OnCpuRate(); });
    if (codec_ != nullptr) codec_->AttachFrameSource(this);
}

bool Pxa2xxAc97Link::FrameAt(uint64_t cycle, uint64_t& frame) const {
    if (!running_) return false;
    frame = FrameIndexAt(cycle);
    return true;
}

void Pxa2xxAc97Link::OnCodecStreamChange() { NotifyEvent(); }

void Pxa2xxAc97Link::NotifyEvent() {
    for (Pxa2xxAc97LinkListener* l : listeners_) l->OnLinkEvent();
}

void Pxa2xxAc97Link::Settle(uint64_t now) {
    if (cmd_ == Cmd::None || !cmd_framed_) return;
    const uint64_t at = bits_.CycleOfTick(cmd_done_bit_);
    if (at <= now) CompleteCommand(at);
}

/* AC '97 Component Specification Revision 2.1 section 5.1.1.2 (page 30): "Audio output frame
   slot 1 communicates control register address, and write/read command information". */
void Pxa2xxAc97Link::FrameCommand(uint64_t now) {
    const uint64_t frame = FrameIndexAt(now) + 1u;
    const uint64_t reply = cmd_ == Cmd::Read ? frame + 1u : frame;
    cmd_done_bit_ = reply * kBitsPerFrame + kSlot2End;
    cmd_framed_   = true;
    ArmCommand();
}

void Pxa2xxAc97Link::ArmCommand() {
    if (cmd_framed_ && cmd_ == Cmd::Write) {
        clock_->Arm(cmd_ev_, bits_.CycleOfTick(cmd_done_bit_));
    } else {
        clock_->Disarm(cmd_ev_);
    }
}

/* Intel PXA255 Developer's Manual Table 13-8 (page 13-22): CDONE "ACUNIT has sent command
   address and data to the CODEC", SDONE "ACUNIT has received status address and data from the
   CODEC"; Table 13-13 (page 13-26) CAIP: "Once the cycle is complete, this bit is automatically cleared". */
void Pxa2xxAc97Link::CompleteCommand(uint64_t at) {
    const Cmd cmd = cmd_;
    cmd_        = Cmd::None;
    cmd_framed_ = false;
    caip_       = false;
    clock_->Disarm(cmd_ev_);
    const uint64_t frame = cmd_done_bit_ / kBitsPerFrame;
    if (cmd == Cmd::Read) {
        latch_ = codec_->ReadReg(cmd_reg_, frame);
        sdone_ = true;
        return;
    }
    codec_->WriteReg(cmd_reg_, cmd_value_, frame);
    LOG(SocIis, "AC-link codec write 0x%02X <= 0x%04X at cycle %llu\n", cmd_reg_, cmd_value_,
        static_cast<unsigned long long>(at));
    cdone_ = true;
    for (Pxa2xxAc97LinkListener* l : listeners_) l->OnCodecWrite(at);
    clock_->Arm(notify_ev_, at);
    /* Cirrus Logic WM9713L Rev 4.0 Figure 4 (page 13): with PR4 set, BITCLK goes low at most
       1.0 us after the end of slot 2. */
    if (cmd_reg_ == kRegPowerdown && codec_->LinkPoweredDown()) {
        bitclk_          = false;
        pd_wait_         = true;
        pd_wait_at_      = at + PsToCycles(kPowerDownWaitPs);
        pd_wait_rate_    = clock_->ClockRate();
        UpdateRun(at);
    }
}

void Pxa2xxAc97Link::UpdateRun(uint64_t now) {
    const bool run = codec_ != nullptr && cold_released_ && bitclk_ && !off_;
    if (run == running_) return;
    LOG(SocIis, "AC-link %s at cycle %llu (cold released %d, BITCLK %d, link off %d)\n",
        run ? "runs" : "stops", static_cast<unsigned long long>(now), cold_released_ ? 1 : 0,
        bitclk_ ? 1 : 0, off_ ? 1 : 0);
    if (!run) {
        for (Pxa2xxAc97LinkListener* l : listeners_) l->OnLinkStop(now);
        running_    = false;
        cmd_framed_ = false;
        clock_->Disarm(cmd_ev_);
        if (cold_released_) codec_->LinkStopped(FrameIndexAt(now));
        return;
    }
    running_ = true;
    pd_wait_ = false;
    if (!bits_.SetRate(clock_->ClockRate(), GuestCycleClock::Rate{kBitClockHz, 1u})) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: the AC-link bit clock does not fit the core clock ratio");
    }
    bits_.Start(now);
    ready_ = true;
    if (cmd_ != Cmd::None) FrameCommand(now);
    for (Pxa2xxAc97LinkListener* l : listeners_) l->OnLinkRun(now);
}

uint64_t Pxa2xxAc97Link::PsToCycles(uint64_t ps) const {
    const GuestCycleClock::Rate r = clock_->ClockRate();
    if (ps != 0u && r.num > UINT64_MAX / ps) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: a %llu ps delay overflows the core clock ratio %llu/%llu",
                              static_cast<unsigned long long>(ps), static_cast<unsigned long long>(r.num),
                              static_cast<unsigned long long>(r.den));
    }
    const uint64_t per_den = (ps * r.num + r.den - 1u) / r.den;
    return (per_den + kPsPerSecond - 1u) / kPsPerSecond;
}

uint64_t Pxa2xxAc97Link::CyclesToPs(uint64_t cycles) const {
    const GuestCycleClock::Rate r = clock_->ClockRate();
    return (cycles * r.den * kPsPerSecond + r.num - 1u) / r.num;
}

void Pxa2xxAc97Link::ArmStart(uint64_t now, uint64_t delay_ps, bool warm) {
    start_pending_ = true;
    warm_start_    = warm;
    start_at_      = now + PsToCycles(delay_ps);
    start_rate_    = clock_->ClockRate();
    clock_->Arm(start_ev_, start_at_);
}

uint64_t Pxa2xxAc97Link::Rescaled(uint64_t at, GuestCycleClock::Rate from, uint64_t now) const {
    const GuestCycleClock::Rate n   = clock_->ClockRate();
    const uint64_t              rem = at > now ? at - now : 0u;
    const uint64_t              num = rem * n.num * from.den;
    const uint64_t              den = n.den * from.num;
    return now + (num + den - 1u) / den;
}

void Pxa2xxAc97Link::OnStartEvent() {
    if (!start_pending_) return;
    start_pending_ = false;
    if (warm_start_) codec_->WarmReset();
    warm_start_ = false;
    bitclk_     = true;
    UpdateRun(start_at_);
    NotifyEvent();
}

void Pxa2xxAc97Link::OnCpuRate() {
    const uint64_t now = clock_->Cycles();
    if (start_pending_) {
        start_at_   = Rescaled(start_at_, start_rate_, now);
        start_rate_ = clock_->ClockRate();
        clock_->Arm(start_ev_, start_at_);
    }
    if (pd_wait_) {
        pd_wait_at_   = Rescaled(pd_wait_at_, pd_wait_rate_, now);
        pd_wait_rate_ = clock_->ClockRate();
    }
    if (!running_) return;
    Settle(now);
    if (!bits_.Rescale(now, clock_->ClockRate(), GuestCycleClock::Rate{kBitClockHz, 1u})) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: the AC-link bit clock does not fit the core clock ratio");
    }
    ArmCommand();
    NotifyEvent();
}

void Pxa2xxAc97Link::SetColdReset(uint64_t now, bool asserted) {
    Settle(now);
    if (asserted != cold_released_) return;
    if (asserted) {
        AssertColdReset(now);
        return;
    }
    cold_released_ = true;
    if (codec_ != nullptr) ArmStart(now, kColdStartPs, false);
}

/* Intel PXA255 Developer's Manual Table 13-7 (page 13-21) COLD_RST: "Causes a cold reset to
   occur throughout the AC'97 circuitry. All data in the ACUNIT and the CODEC will be lost";
   section 13.5.2.2.1 (page 13-14): "All AC'97 control registers are initialized to their default". */
void Pxa2xxAc97Link::AssertColdReset(uint64_t now) {
    start_pending_ = false;
    warm_start_    = false;
    pd_wait_       = false;
    clock_->Disarm(start_ev_);
    cold_released_ = false;
    bitclk_        = false;
    off_           = false;
    requests_off_  = false;
    UpdateRun(now);
    cmd_        = Cmd::None;
    cmd_framed_ = false;
    clock_->Disarm(cmd_ev_);
    latch_ = 0u;
    cdone_ = sdone_ = caip_ = ready_ = false;
    for (Pxa2xxAc97LinkListener* l : listeners_) l->OnFifoReset(now, true);
    if (codec_) codec_->ColdReset();
}

void Pxa2xxAc97Link::SetLinkOff(uint64_t now, bool off, bool discard_fifos) {
    Settle(now);
    if (off == off_) return;
    off_          = off;
    requests_off_ = off && discard_fifos;
    UpdateRun(now);
    if (!requests_off_) return;
    for (Pxa2xxAc97LinkListener* l : listeners_) l->OnFifoReset(now, false);
}

/* AC '97 Component Specification Revision 2.1 section 7 (page 47): a warm reset will "restart
   AC '97's digital interface (resetting PR4 to zero)"; Intel PXA27x Developer's Manual Table 13-8
   (page 13-22) WRST: "If software attempts to perform a warm reset while AC97_BITCLK is running, the write is ignored". */
bool Pxa2xxAc97Link::WarmReset(uint64_t now) {
    Settle(now);
    if (codec_ == nullptr || !cold_released_ || bitclk_) return false;
    if (start_pending_) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: warm reset while a BITCLK start is pending; not modelled");
    }
    if (pd_wait_ && now < pd_wait_at_) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: warm reset within four AC-link frames of the power down; not modelled");
    }
    ArmStart(now, kWarmStartPs, true);
    return true;
}

void Pxa2xxAc97Link::RequireIdle(const char* op, uint32_t reg) {
    if (cmd_ == Cmd::None) return;
    emu_.Get<Fatal>().Die("Pxa2xxAc97Link: codec %s of register 0x%02X while the previous AC-link "
                          "command is in flight; not modelled", op, reg);
}

/* Intel PXA27x Developer's Manual section 13.6.3 (page 13-17): "Software issues a dummy read
   to the Codec register. The AC '97 controller responds to this read operation with invalid
   data. The AC '97 controller then initiates the read access across the AC-link." */
uint32_t Pxa2xxAc97Link::CodecRead(uint64_t now, uint32_t reg) {
    Settle(now);
    RequireIdle("read", reg);
    cmd_     = Cmd::Read;
    cmd_reg_ = reg;
    if (running_) FrameCommand(now);
    return latch_;
}

void Pxa2xxAc97Link::CodecWrite(uint64_t now, uint32_t reg, uint16_t value) {
    Settle(now);
    RequireIdle("write", reg);
    cmd_       = Cmd::Write;
    cmd_reg_   = reg;
    cmd_value_ = value;
    if (running_) FrameCommand(now);
}

/* Intel PXA255 Developer's Manual section 13.8.3.17 (page 13-32): Primary Audio CODEC at 0x4050_0200,
   Secondary Audio at 0x4050_0300, Primary Modem at 0x4050_0400, Secondary Modem at 0x4050_0500, each
   "+ Shift_Left_Once(Internal 7-bit CODEC Register Address)". */
uint32_t Pxa2xxAc97Link::PrimaryCodecReg(uint32_t off) {
    if ((((off - kCodecBase) >> 8) & 1u) != 0u) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: secondary codec window access at offset 0x%03X; "
                              "not modelled", off);
    }
    return (off & 0xFFu) >> 1;
}

/* Intel PXA255 Developer's Manual section 13.6 (page 13-14): the modem CODEC GPIO register at 0x0054
   "write operation goes across the AC-link, but a read does not"; its contents "are continuously updated
   into a shadow register in the ACUNIT when a frame is received from the CODEC". */
uint32_t Pxa2xxAc97Link::CodecWindowRead(uint64_t now, uint32_t off) {
    const uint32_t reg = PrimaryCodecReg(off);
    if (reg != kRegGpioStatus || off - kCodecBase < kModemWindow) return CodecRead(now, reg);
    if (!running_) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: modem codec GPIO shadow read at offset 0x%03X with the AC-link "
                              "stopped; not modelled", off);
    }
    Settle(now);
    const uint64_t frame = FrameIndexAt(now);
    if (frame == 0u) {
        emu_.Get<Fatal>().Die("Pxa2xxAc97Link: modem codec GPIO shadow read at offset 0x%03X before the first frame "
                              "since the AC-link started; not modelled", off);
    }
    return codec_->GpioSlotStatus(frame - 1u);
}

void Pxa2xxAc97Link::CodecWindowWrite(uint64_t now, uint32_t off, uint16_t value) {
    CodecWrite(now, PrimaryCodecReg(off), value);
}

/* Intel PXA255 Developer's Manual Table 13-13 (page 13-26) CAIP: "No cycle is in progress and
   the act of reading the register sets this bit to '1'". */
bool Pxa2xxAc97Link::ReadCar(uint64_t now) {
    Settle(now);
    const bool was = caip_;
    caip_ = true;
    return was;
}

void Pxa2xxAc97Link::ClearCar(uint64_t now) {
    Settle(now);
    caip_ = false;
}

bool Pxa2xxAc97Link::CommandDone(uint64_t now) {
    Settle(now);
    return cdone_;
}

bool Pxa2xxAc97Link::StatusDone(uint64_t now) {
    Settle(now);
    return sdone_;
}

/* Intel PXA255 Developer's Manual Table 13-8 (page 13-22) PCR: "Reflects the state of the
   CODEC ready bit in SDATA_IN_0". */
bool Pxa2xxAc97Link::CodecReady(uint64_t now) {
    Settle(now);
    return ready_;
}

void Pxa2xxAc97Link::ClearDone(uint64_t now, bool command, bool status) {
    Settle(now);
    if (command) cdone_ = false;
    if (status) sdone_ = false;
}

void Pxa2xxAc97Link::ResetLine() {
    const uint64_t now = clock_->Cycles();
    Settle(now);
    AssertColdReset(now);
}

void Pxa2xxAc97Link::Save(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    Settle(now);
    const RatedTickCount::Position pos = running_ ? bits_.PositionAt(now) : RatedTickCount::Position{};
    w.Write<uint8_t>("link_cold_released", cold_released_ ? 1u : 0u);
    w.Write<uint8_t>("link_bitclk", bitclk_ ? 1u : 0u);
    w.Write<uint8_t>("link_off", off_ ? 1u : 0u);
    w.Write<uint8_t>("link_requests_off", requests_off_ ? 1u : 0u);
    w.Write<uint8_t>("link_running", running_ ? 1u : 0u);
    w.Write<uint8_t>("link_ready", ready_ ? 1u : 0u);
    w.Write<uint8_t>("link_cmd", static_cast<uint8_t>(cmd_));
    w.Write<uint8_t>("link_cmd_framed", cmd_framed_ ? 1u : 0u);
    w.Write<uint32_t>("link_cmd_reg", cmd_reg_);
    w.Write<uint16_t>("link_cmd_value", cmd_value_);
    w.Write<uint64_t>("link_cmd_done_bit", cmd_done_bit_);
    w.Write<uint16_t>("link_latch", latch_);
    w.Write<uint8_t>("link_cdone", cdone_ ? 1u : 0u);
    w.Write<uint8_t>("link_sdone", sdone_ ? 1u : 0u);
    w.Write<uint8_t>("link_caip", caip_ ? 1u : 0u);
    w.Write<uint64_t>("link_bits_ticks", pos.ticks);
    w.Write<uint64_t>("link_bits_phase", pos.phase);
    w.Write<uint64_t>("link_bits_phase_den", pos.phase_den);
    w.Write<uint8_t>("link_start_pending", start_pending_ ? 1u : 0u);
    w.Write<uint8_t>("link_warm_start", warm_start_ ? 1u : 0u);
    w.Write<uint64_t>("link_start_left_ps", start_pending_ && start_at_ > now ? CyclesToPs(start_at_ - now) : 0u);
    w.Write<uint8_t>("link_pd_wait", pd_wait_ ? 1u : 0u);
    w.Write<uint64_t>("link_pd_wait_left_ps", pd_wait_ && pd_wait_at_ > now ? CyclesToPs(pd_wait_at_ - now) : 0u);
}

void Pxa2xxAc97Link::Restore(StateReader& r) {
    uint8_t released = 0, bitclk = 0, off = 0, requests_off = 0, running = 0, ready = 0, cmd = 0;
    uint8_t framed = 0;
    uint8_t cdone = 0, sdone = 0, caip = 0;
    RatedTickCount::Position pos;
    r.Read("link_cold_released", released);
    r.Read("link_bitclk", bitclk);
    r.Read("link_off", off);
    r.Read("link_requests_off", requests_off);
    r.Read("link_running", running);
    r.Read("link_ready", ready);
    r.Read("link_cmd", cmd);
    r.Read("link_cmd_framed", framed);
    r.Read("link_cmd_reg", cmd_reg_);
    r.Read("link_cmd_value", cmd_value_);
    r.Read("link_cmd_done_bit", cmd_done_bit_);
    r.Read("link_latch", latch_);
    r.Read("link_cdone", cdone);
    r.Read("link_sdone", sdone);
    r.Read("link_caip", caip);
    r.Read("link_bits_ticks", pos.ticks);
    r.Read("link_bits_phase", pos.phase);
    r.Read("link_bits_phase_den", pos.phase_den);
    uint8_t  start_pending = 0, warm_start = 0, pd_wait = 0;
    uint64_t pd_wait_left_ps = 0;
    r.Read("link_start_pending", start_pending);
    r.Read("link_warm_start", warm_start);
    r.Read("link_start_left_ps", start_left_ps_);
    r.Read("link_pd_wait", pd_wait);
    r.Read("link_pd_wait_left_ps", pd_wait_left_ps);
    start_pending_ = start_pending != 0u;
    warm_start_    = warm_start != 0u;
    pd_wait_       = pd_wait != 0u;
    pd_wait_at_    = clock_->Cycles() + PsToCycles(pd_wait_left_ps);
    pd_wait_rate_  = clock_->ClockRate();
    cold_released_ = released != 0u;
    bitclk_        = bitclk != 0u;
    off_           = off != 0u;
    requests_off_  = requests_off != 0u;
    running_       = running != 0u;
    ready_         = ready != 0u;
    cmd_           = static_cast<Cmd>(cmd);
    cmd_framed_    = framed != 0u;
    cdone_         = cdone != 0u;
    sdone_         = sdone != 0u;
    caip_          = caip != 0u;
    if (!running_) return;
    if (!bits_.SetRate(clock_->ClockRate(), GuestCycleClock::Rate{kBitClockHz, 1u}) ||
        !bits_.PlaceAt(clock_->Cycles(), pos)) {
        r.Reject("Pxa2xxAc97Link: the restored AC-link bit clock at %llu phase %llu/%llu does not "
                 "fit the current core ratio", static_cast<unsigned long long>(pos.ticks),
                 static_cast<unsigned long long>(pos.phase),
                 static_cast<unsigned long long>(pos.phase_den));
    }
}

void Pxa2xxAc97Link::PostRestore() {
    ArmCommand();
    clock_->Disarm(start_ev_);
    if (start_pending_) ArmStart(clock_->Cycles(), start_left_ps_, warm_start_);
}

REGISTER_SERVICE(Pxa2xxAc97Link);
