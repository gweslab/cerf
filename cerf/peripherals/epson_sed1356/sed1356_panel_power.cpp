#include "sed1356_panel_power.h"

#include "sed1356_config.h"
#include "sed1356_power_sequence.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"

#include <algorithm>

bool Sed1356PanelPower::ShouldRegister() {
    return emu_.TryGet<Sed1356Config>() != nullptr;
}

void Sed1356PanelPower::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    seq_   = &emu_.Get<Sed1356PowerSequence>();
    clock_->RegisterRateListener([this] {
        std::lock_guard<std::mutex> lk(mtx_);
        if (PendingLocked(clock_->Cycles())) RescaleLocked(pixel_);
    });
}

void Sed1356PanelPower::PowerUp() {
    std::lock_guard<std::mutex> lk(mtx_);
    state_           = State::Up;
    signals_unknown_ = false;
}

void Sed1356PanelPower::PowerDown(bool lcd_disable, const Timing& t) {
    std::lock_guard<std::mutex> lk(mtx_);
    const Sed1356PowerSequence::PanelDown d = lcd_disable
        ? seq_->LcdDisableToPanelDown(t.panel_divisor, t.power_save_reg)
        : seq_->PowerSaveToPanelDown();
    const uint64_t status  = d.status.frames * t.frame_ticks + d.status.lines * t.line_ticks;
    const uint64_t signals = d.signals.frames * t.frame_ticks + d.signals.lines * t.line_ticks;
    signals_unknown_ = false;
    if (std::max(status, signals) == 0u) {
        state_ = State::Down;
        return;
    }
    if (!ticks_.SetRate(clock_->ClockRate(), t.pixel)) {
        emu_.Get<Fatal>().Die("Sed1356: panel power-down of %llu pixel clocks cannot be scheduled",
                              static_cast<unsigned long long>(std::max(status, signals)));
    }
    ticks_.Start(clock_->Cycles());
    pixel_         = t.pixel;
    status_after_  = status;
    signals_after_ = signals;
    state_         = State::PoweringDown;
}

void Sed1356PanelPower::Disturb() {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now = clock_->Cycles();
    if (StatusPendingLocked(now)) {
        state_ = State::Unknown;
    } else if (SignalsActiveLocked(now)) {
        signals_unknown_ = true;
    }
}

bool Sed1356PanelPower::Pending() {
    std::lock_guard<std::mutex> lk(mtx_);
    return PendingLocked(clock_->Cycles());
}

bool Sed1356PanelPower::PowerDownInProgress() {
    std::lock_guard<std::mutex> lk(mtx_);
    return state_ == State::Unknown || signals_unknown_ || SignalsActiveLocked(clock_->Cycles());
}

/* SED1356 Table 7-20 p.78 t4 max 65 / 130 T_FPFRAME, Table 7-21 p.80 t3 max 129 T_FPFRAME +
   T_FPLINE; S1D13806 Table 6-15 p.62 t1 max 1 T_FPLINE: panel line signals inactive. */
uint8_t Sed1356PanelPower::VndWhileScanStopped() {
    if (PowerDownInProgress()) {
        emu_.Get<Fatal>().Die("Sed1356: REG[03Ah] VND status read during the panel power-down "
                              "sequence is not modelled");
    }
    return 0x00u;
}

bool Sed1356PanelPower::PendingLocked(uint64_t now) const {
    return state_ == State::PoweringDown &&
           ticks_.TicksAt(now) < std::max(status_after_, signals_after_);
}

bool Sed1356PanelPower::StatusPendingLocked(uint64_t now) const {
    return state_ == State::PoweringDown && ticks_.TicksAt(now) < status_after_;
}

bool Sed1356PanelPower::SignalsActiveLocked(uint64_t now) const {
    return state_ == State::PoweringDown && ticks_.TicksAt(now) < signals_after_;
}

void Sed1356PanelPower::SetPixelRate(GuestCycleClock::Rate pixel) {
    std::lock_guard<std::mutex> lk(mtx_);
    RescaleLocked(pixel);
}

void Sed1356PanelPower::RescaleLocked(GuestCycleClock::Rate pixel) {
    if (!ticks_.Rescale(clock_->Cycles(), clock_->ClockRate(), pixel)) {
        emu_.Get<Fatal>().Die("Sed1356: panel power-down rescale to %llu/%llu Hz failed",
                              static_cast<unsigned long long>(pixel.num),
                              static_cast<unsigned long long>(pixel.den));
    }
    pixel_ = pixel;
}

/* SED1356 REG[1F1h] p.170-171, S1D13806 REG[1F1h] p.145: bit 1 LCD Power Save Status, 1 =
   panel powered down; bit 0 Memory Controller Power Save Status. */
uint8_t Sed1356PanelPower::StatusBits(uint8_t mode_reg, uint8_t power_save_reg,
                                      uint8_t refresh_reg) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint8_t memory =
        (power_save_reg & 0x1u) != 0u && seq_->MemoryControllerPowersDown(refresh_reg) ? 0x01u
                                                                                       : 0x00u;
    if ((mode_reg & 0x1u) == 0u && seq_->LcdDisabledReadsPanelDown()) {
        return static_cast<uint8_t>(0x02u | memory);
    }
    const bool elapsed =
        state_ == State::PoweringDown && !StatusPendingLocked(clock_->Cycles());
    switch (elapsed ? State::Down : state_) {
        case State::Down:         return static_cast<uint8_t>(0x02u | memory);
        case State::Up:           return memory;
        case State::PoweringDown: return memory;
        case State::Unknown:      break;
    }
    emu_.Get<Fatal>().Die("Sed1356: REG[1F1h] read after an LCD timing, enable or power-save "
                          "change inside the panel power-down sequence is not modelled");
}

void Sed1356PanelPower::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    RatedTickCount::Position at;
    if (state_ == State::PoweringDown) at = ticks_.PositionAt(clock_->Cycles());
    w.Write<uint8_t>("panel_state", static_cast<uint8_t>(state_));
    w.Write<uint64_t>("panel_status_after", status_after_);
    w.Write<uint64_t>("panel_signals_after", signals_after_);
    w.Write<uint8_t>("panel_signals_unknown", signals_unknown_ ? 1u : 0u);
    w.Write<uint64_t>("panel_pixel_num", pixel_.num);
    w.Write<uint64_t>("panel_pixel_den", pixel_.den);
    w.Write<uint64_t>("panel_down_ticks", at.ticks);
    w.Write<uint64_t>("panel_down_phase", at.phase);
    w.Write<uint64_t>("panel_down_phase_den", at.phase_den);
}

void Sed1356PanelPower::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t state = 0;
    uint8_t signals_unknown = 0;
    r.Read("panel_state", state);
    r.Read("panel_status_after", status_after_);
    r.Read("panel_signals_after", signals_after_);
    r.Read("panel_signals_unknown", signals_unknown);
    r.Read("panel_pixel_num", pixel_.num);
    r.Read("panel_pixel_den", pixel_.den);
    r.Read("panel_down_ticks", held_.ticks);
    r.Read("panel_down_phase", held_.phase);
    r.Read("panel_down_phase_den", held_.phase_den);
    state_           = static_cast<State>(state);
    signals_unknown_ = signals_unknown != 0u;
}

void Sed1356PanelPower::ResumeAfterRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (state_ != State::PoweringDown) return;
    if (!ticks_.SetRate(clock_->ClockRate(), pixel_) ||
        !ticks_.PlaceAt(clock_->Cycles(), held_)) {
        emu_.Get<Fatal>().Die("Sed1356: panel power-down cannot resume after a restore");
    }
}

REGISTER_SERVICE(Sed1356PanelPower);
