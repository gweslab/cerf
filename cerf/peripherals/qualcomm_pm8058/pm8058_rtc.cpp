#include "pm8058_rtc.h"

#include "pm8058_irq.h"

#include "../../boards/board_context.h"
#include "../../boards/nokia_lumia_800/nokia_lumia_800_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <iterator>

namespace {

/* Linux drivers/rtc/rtc-pm8xxx.c: PM8xxx_RTC_ENABLE BIT(7),
   PM8xxx_RTC_ALARM_CLEAR BIT(0), and pm8058_regs.alarm_en BIT(1). */
constexpr uint8_t kEnable      = 1u << 7;
constexpr uint8_t kAlarmEnable = 1u << 1;
constexpr uint8_t kAlarmClear  = 1u << 0;
constexpr uint8_t kCtrlBits    = kEnable | kAlarmEnable;

constexpr uint64_t kCountHz = 1u;

constexpr uint32_t kAlarmIrq = 39u;
constexpr uint32_t kRtcIrq   = 53u;

}  // namespace

bool Pm8058Rtc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
}

void Pm8058Rtc::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    irq_   = &emu_.Get<Pm8058Irq>();
    irq_->GuardLineShape(kAlarmIrq);
    irq_->GuardUnmodeledSource(kRtcIrq);
    RequireRatio(counter_.SetRatio(clock_->CpuHz(), kCountHz));
    alarm_event_ = clock_->Add([this] { OnAlarmMatch(); });
    PowerOn();
    clock_->RegisterRateListener([this] { OnRateChange(); });
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind kind) {
        if (kind == ResetLineKind::Rtc) PowerOn();
    });
    reset.RegisterResetReleaseListener([this] { RedriveAlarmLine(); });
}

void Pm8058Rtc::PowerOn() {
    std::lock_guard<std::mutex> lk(mtx_);
    ctrl_          = kEnable;
    stopped_count_ = 0u;
    alarm_status_  = false;
    std::fill(std::begin(alarm_), std::end(alarm_), uint8_t{0});
    counter_.Anchor(clock_->Cycles(), 0u);
    clock_->Disarm(alarm_event_);
}

bool Pm8058Rtc::RunningLocked() const { return (ctrl_ & kEnable) != 0u; }

bool Pm8058Rtc::AlarmArmedLocked() const {
    return RunningLocked() && (ctrl_ & kAlarmEnable) != 0u;
}

uint32_t Pm8058Rtc::CountLocked(uint64_t now) const {
    return RunningLocked() ? counter_.CountAt(now) : stopped_count_;
}

uint32_t Pm8058Rtc::AlarmLocked() const { return cerf::le::U32(alarm_); }

void Pm8058Rtc::SetCountLocked(uint64_t now, uint32_t count) {
    if (RunningLocked()) counter_.SetCountAt(now, count);
    else                 stopped_count_ = count;
}

void Pm8058Rtc::SetAlarmStatusLocked(bool high) {
    alarm_status_ = high;
    irq_->SetSourceLevel(kAlarmIrq, high);
}

void Pm8058Rtc::ArmAlarmLocked(uint64_t now) {
    if (!AlarmArmedLocked()) {
        clock_->Disarm(alarm_event_);
        return;
    }
    clock_->Arm(alarm_event_, counter_.NextMatchCycle(AlarmLocked(), now));
}

void Pm8058Rtc::RequireComparatorUnequalLocked(uint64_t now, const char* write) const {
    if ((ctrl_ & kAlarmEnable) != 0u && CountLocked(now) == AlarmLocked()) {
        emu_.Get<Fatal>().Die(
            "pm8058 rtc: %s leaves count 0x%08X equal to alarm 0x%08X under "
            "control 0x%02X", write, CountLocked(now), AlarmLocked(), ctrl_);
    }
}

void Pm8058Rtc::OnAlarmMatch() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (alarm_status_) {
        emu_.Get<Fatal>().Die(
            "pm8058 rtc: alarm 0x%08X matched with the alarm status still set",
            AlarmLocked());
    }
    SetAlarmStatusLocked(true);
    ArmAlarmLocked(clock_->Cycles());
}

void Pm8058Rtc::RedriveAlarmLine() {
    std::lock_guard<std::mutex> lk(mtx_);
    irq_->SetSourceLevel(kAlarmIrq, alarm_status_);
}

void Pm8058Rtc::RequireRatio(bool ok) const {
    if (!ok) {
        emu_.Get<Fatal>().Die(
            "pm8058 rtc: 1 Hz against the %llu Hz core overflows the 64-bit "
            "scale", static_cast<unsigned long long>(clock_->CpuHz()));
    }
}

void Pm8058Rtc::OnRateChange() {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now = clock_->Cycles();
    if (RunningLocked()) {
        RequireRatio(counter_.Rescale(now, clock_->CpuHz(), kCountHz));
    } else {
        RequireRatio(counter_.SetRatio(clock_->CpuHz(), kCountHz));
    }
    ArmAlarmLocked(now);
}

uint8_t Pm8058Rtc::ReadReg(uint16_t reg) {
    std::lock_guard<std::mutex> lk(mtx_);

    if (reg == kRegCtrl)      return ctrl_;
    if (reg == kRegAlarmCtl2) return alarm_status_ ? kAlarmClear : 0u;

    if (reg >= kRegWrite && reg < kRegWrite + kBytes) return 0u;
    if (reg >= kRegRead && reg < kRegRead + kBytes) {
        const uint32_t count = CountLocked(clock_->Cycles());
        return (uint8_t)(count >> (8u * (uint32_t)(reg - kRegRead)));
    }
    if (reg >= kRegAlarmRw && reg < kRegAlarmRw + kBytes) {
        return alarm_[reg - kRegAlarmRw];
    }

    emu_.Get<Fatal>().Die(
        "pm8058 rtc: register 0x%03X is not one of the block's fourteen", reg);
}

void Pm8058Rtc::WriteReg(uint16_t reg, uint8_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now = clock_->Cycles();

    if (reg == kRegCtrl) {
        if ((value & (uint8_t)~kCtrlBits) != 0u) {
            emu_.Get<Fatal>().Die(
                "pm8058 rtc: control write 0x%02X sets bits 0x%02X", value,
                (unsigned)(value & (uint8_t)~kCtrlBits));
        }
        const bool want = (value & kEnable) != 0u;
        if (RunningLocked() && !want) {
            stopped_count_ = counter_.CountAt(now);
        } else if (!RunningLocked() && want) {
            counter_.Anchor(now, stopped_count_);
        }
        ctrl_ = value;
        RequireComparatorUnequalLocked(now, "control write");
        ArmAlarmLocked(now);
        return;
    }

    if (reg >= kRegWrite && reg < kRegWrite + kBytes) {
        const uint32_t shift = 8u * (uint32_t)(reg - kRegWrite);
        const uint32_t count = CountLocked(now);
        SetCountLocked(now, (count & ~(0xFFu << shift)) | ((uint32_t)value << shift));
        RequireComparatorUnequalLocked(now, "counter write");
        ArmAlarmLocked(now);
        return;
    }

    if (reg == kRegAlarmCtl2) {
        if (value != 0u) {
            emu_.Get<Fatal>().Die(
                "pm8058 rtc: alarm control 2 write 0x%02X", value);
        }
        RequireComparatorUnequalLocked(now, "alarm status clear");
        SetAlarmStatusLocked(false);
        return;
    }

    if (reg >= kRegAlarmRw && reg < kRegAlarmRw + kBytes) {
        alarm_[reg - kRegAlarmRw] = value;
        RequireComparatorUnequalLocked(now, "alarm write");
        ArmAlarmLocked(now);
        return;
    }

    emu_.Get<Fatal>().Die(
        "pm8058 rtc: write of 0x%02X to register 0x%03X", value, reg);
}

void Pm8058Rtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now     = clock_->Cycles();
    const bool     running = RunningLocked();
    w.Write<uint32_t>("counter", CountLocked(now));
    w.Write<uint64_t>("counter_phase", running ? counter_.PhaseAt(now) : 0u);
    w.Write<uint64_t>("counter_phase_den",
                      running ? counter_.PhaseDenominator() : 1u);
    w.Write<uint8_t>("ctrl", ctrl_);
    w.Write<uint8_t>("alarm_status", alarm_status_ ? 1u : 0u);
    for (uint32_t i = 0; i < kBytes; ++i) {
        w.Write<uint8_t>("alarm", alarm_[i]);
    }
}

void Pm8058Rtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint32_t count = 0;
    uint64_t phase = 0, den = 0;
    uint8_t  ctrl = 0, status = 0;
    r.Read("counter", count);
    r.Read("counter_phase", phase);
    r.Read("counter_phase_den", den);
    r.Read("ctrl", ctrl);
    r.Read("alarm_status", status);
    for (uint32_t i = 0; i < kBytes; ++i) {
        r.Read("alarm", alarm_[i]);
    }
    if ((ctrl & (uint8_t)~kCtrlBits) != 0u) {
        r.Reject("pm8058 rtc: restored control 0x%02X sets bits 0x%02X", ctrl,
                 (unsigned)(ctrl & (uint8_t)~kCtrlBits));
    }
    if (status > 1u) {
        r.Reject("pm8058 rtc: restored alarm status %u is not 0 or 1",
                 (unsigned)status);
    }
    if ((ctrl & kAlarmEnable) != 0u && count == AlarmLocked() &&
        ((ctrl & kEnable) == 0u || status == 0u)) {
        r.Reject("pm8058 rtc: restored count 0x%08X equals alarm 0x%08X under "
                 "control 0x%02X with alarm status %u", count, AlarmLocked(),
                 ctrl, (unsigned)status);
    }
    if (!counter_.SetRatio(clock_->CpuHz(), kCountHz)) {
        r.Reject("pm8058 rtc: 1 Hz against the %llu Hz core overflows the "
                 "64-bit scale", static_cast<unsigned long long>(clock_->CpuHz()));
    }
    const uint64_t now = clock_->Cycles();
    ctrl_         = ctrl;
    alarm_status_ = status != 0u;
    if (RunningLocked()) {
        if (!counter_.AnchorAtPhase(now, count, phase, den)) {
            r.Reject("pm8058 rtc: restored phase %llu/%llu is not a fraction of "
                     "one second this build can place",
                     static_cast<unsigned long long>(phase),
                     static_cast<unsigned long long>(den));
        }
    } else {
        if (phase != 0u || den != 1u) {
            r.Reject("pm8058 rtc: restored stopped counter carries a phase "
                     "%llu/%llu", static_cast<unsigned long long>(phase),
                     static_cast<unsigned long long>(den));
        }
        stopped_count_ = count;
    }
    ArmAlarmLocked(now);
}

REGISTER_SERVICE(Pm8058Rtc);
