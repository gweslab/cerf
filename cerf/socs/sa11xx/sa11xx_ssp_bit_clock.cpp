#include "sa11xx_ssp_bit_clock.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "sa11xx_gpio.h"
#include "sa11xx_ssp_clock_input.h"

namespace {

/* SA-1110 Developer's Manual §11.12.9 SSCR0 (printed 11-158): SCR 15:8; §11.12.10 SSCR1 (printed
   11-162): ECS 5. */
constexpr uint32_t kScrShift = 8;
constexpr uint32_t kEcs      = 1u << 5;

/* §11.12.7.2: the 3.6864 MHz clock "is first divided by a fixed value of 2 and then by a
   programmable number between 1 and 256". */
constexpr uint64_t kInternalClockHz = 3686400u;

/* §11.12.10.6 (printed 11-161): "the user must also set bit 19 of the GPIO alternate function
   register (GAFR), and clear bit 19 of the GPIO pin direction register (GPDR)". */
constexpr uint32_t kSspClockPin = 19u;

}

bool Sa11xxSspBitClock::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxSspBitClock::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    gpio_  = &emu_.Get<Sa11xxGpio>();
    input_ = emu_.TryGet<Sa11xxSspClockInput>();
    reset_ = &emu_.Get<GuestCpuReset>();
    clock_->RegisterRateListener([this] { OnCpuRate(); });
    if (input_ != nullptr) input_->RegisterChangeListener([this] { Reevaluate(); });
    gpio_->RegisterPinConfigListener([this] { Reevaluate(); });
}

void Sa11xxSspBitClock::SetListener(BeforeChange before, AfterChange after) {
    before_ = std::move(before);
    after_  = std::move(after);
}

void Sa11xxSspBitClock::RequireRatio(bool fits) const {
    if (!fits) emu_.Get<Fatal>().Die("Sa11xxSsp: bit rate overflows the cycle clock ratio");
}

/* §11.12.9.4: "BitRate = 3.6864x10^6 / (2x(SCR+1))"; Linux sa11xx_uda1341_set_samplerate pairs
   SSCR1 ExtClk with SSCR0_SerClkDiv, the GPIO 19 clock divided by 2(SCR+1). */
bool Sa11xxSspBitClock::Select(uint32_t sscr0, uint32_t sscr1, GuestCycleClock::Rate& rate) const {
    const uint64_t div = 2u * (((sscr0 >> kScrShift) & 0xFFu) + 1u);
    if ((sscr1 & kEcs) == 0u) {
        rate = GuestCycleClock::Rate{kInternalClockHz, div};
        return true;
    }
    const Sa11xxGpio::PinConfig pin = gpio_->Pin(kSspClockPin);
    GuestCycleClock::Rate in{};
    if (!pin.alternate || pin.output || input_ == nullptr || !input_->Frequency(in)) return false;
    rate = GuestCycleClock::Rate{in.num, in.den * div};
    return true;
}

void Sa11xxSspBitClock::Start(uint64_t now, uint32_t sscr0, uint32_t sscr1) {
    sscr0_   = sscr0;
    sscr1_   = sscr1;
    started_ = true;
    held_    = RatedTickCount::Position{};
    clocked_ = Select(sscr0, sscr1, rate_);
    if (!clocked_) return;
    RequireRatio(bits_.SetRate(clock_->ClockRate(), rate_));
    bits_.Start(now);
}

void Sa11xxSspBitClock::Change(uint64_t now, uint32_t sscr0, uint32_t sscr1) {
    sscr0_ = sscr0;
    sscr1_ = sscr1;
    GuestCycleClock::Rate rate{};
    if (!Select(sscr0, sscr1, rate)) {
        if (clocked_) held_ = bits_.PositionAt(now);
        clocked_ = false;
        return;
    }
    if (clocked_) {
        RequireRatio(bits_.Rescale(now, clock_->ClockRate(), rate));
    } else {
        RequireRatio(bits_.SetRate(clock_->ClockRate(), rate) && bits_.PlaceAt(now, held_));
    }
    rate_    = rate;
    clocked_ = true;
}

void Sa11xxSspBitClock::Reevaluate() {
    if (!started_ || reset_->LineHeld()) return;
    GuestCycleClock::Rate rate{};
    const bool known = Select(sscr0_, sscr1_, rate);
    if (known == clocked_ && (!known || (rate.num == rate_.num && rate.den == rate_.den))) return;
    const uint64_t now = clock_->Cycles();
    before_(now, !known);
    Change(now, sscr0_, sscr1_);
    after_(now);
}

void Sa11xxSspBitClock::OnCpuRate() {
    if (!started_ || !clocked_) return;
    const uint64_t now = clock_->Cycles();
    before_(now, false);
    RequireRatio(bits_.Rescale(now, clock_->ClockRate(), rate_));
    after_(now);
}

void Sa11xxSspBitClock::Save(StateWriter& w) {
    const RatedTickCount::Position pos = clocked_ ? bits_.PositionAt(clock_->Cycles()) : held_;
    w.Write<uint32_t>("bit_clock_sscr0", sscr0_);
    w.Write<uint32_t>("bit_clock_sscr1", sscr1_);
    w.Write<uint8_t>("bit_clock_started", started_ ? 1u : 0u);
    w.Write<uint8_t>("bit_clock_clocked", clocked_ ? 1u : 0u);
    w.Write<uint64_t>("bit_clock_rate_num", rate_.num);
    w.Write<uint64_t>("bit_clock_rate_den", rate_.den);
    w.Write<uint64_t>("bit_clock_ticks", pos.ticks);
    w.Write<uint64_t>("bit_clock_phase", pos.phase);
    w.Write<uint64_t>("bit_clock_phase_den", pos.phase_den);
}

void Sa11xxSspBitClock::Restore(StateReader& r) {
    uint8_t started = 0, clocked = 0;
    RatedTickCount::Position pos;
    r.Read("bit_clock_sscr0", sscr0_);
    r.Read("bit_clock_sscr1", sscr1_);
    r.Read("bit_clock_started", started);
    r.Read("bit_clock_clocked", clocked);
    r.Read("bit_clock_rate_num", rate_.num);
    r.Read("bit_clock_rate_den", rate_.den);
    r.Read("bit_clock_ticks", pos.ticks);
    r.Read("bit_clock_phase", pos.phase);
    r.Read("bit_clock_phase_den", pos.phase_den);
    started_ = started != 0u;
    clocked_ = clocked != 0u;
    held_    = clocked_ ? RatedTickCount::Position{} : pos;
    if (!clocked_) return;
    if (!bits_.SetRate(clock_->ClockRate(), rate_) || !bits_.PlaceAt(clock_->Cycles(), pos)) {
        r.Reject("Sa11xxSsp: the restored bit clock %llu/%llu Hz at bit %llu does not fit the "
                 "current core ratio", static_cast<unsigned long long>(rate_.num),
                 static_cast<unsigned long long>(rate_.den),
                 static_cast<unsigned long long>(pos.ticks));
    }
}

REGISTER_SERVICE(Sa11xxSspBitClock);
