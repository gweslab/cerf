#include "pm8058_rtc.h"

#include "../../boards/board_context.h"
#include "../../boards/nokia_lumia_800/nokia_lumia_800_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/steady_time.h"
#include "../../state/state_stream.h"

namespace {

/* Linux drivers/rtc/rtc-pm8xxx.c: PM8xxx_RTC_ENABLE BIT(7),
   PM8xxx_RTC_ALARM_CLEAR BIT(0), and pm8058_regs.alarm_en BIT(1). */
constexpr uint8_t kEnable      = 1u << 7;
constexpr uint8_t kAlarmEnable = 1u << 1;
constexpr uint8_t kAlarmClear  = 1u << 0;

constexpr uint64_t kMicrosPerSecond = 1000000u;

}  // namespace

bool Pm8058Rtc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
}

uint32_t Pm8058Rtc::CounterLocked() const {
    if (!running_) return base_;
    const uint64_t now = HostSteadyMicros();
    const uint64_t elapsed = now > anchor_us_ ? now - anchor_us_ : 0u;
    return (uint32_t)(base_ + (uint32_t)(elapsed / kMicrosPerSecond));
}

void Pm8058Rtc::LatchLocked() {
    base_      = CounterLocked();
    anchor_us_ = HostSteadyMicros();
}

uint8_t Pm8058Rtc::ReadReg(uint16_t reg) {
    std::lock_guard<std::mutex> lk(mtx_);

    if (reg == kRegCtrl)      return ctrl_;
    if (reg == kRegAlarmCtl2) return alarm_ctl2_;

    if (reg >= kRegWrite && reg < kRegWrite + kBytes) {
        return load_[reg - kRegWrite];
    }
    if (reg >= kRegRead && reg < kRegRead + kBytes) {
        const uint32_t secs = CounterLocked();
        return (uint8_t)(secs >> (8u * (uint32_t)(reg - kRegRead)));
    }
    if (reg >= kRegAlarmRw && reg < kRegAlarmRw + kBytes) {
        return alarm_[reg - kRegAlarmRw];
    }

    emu_.Get<Fatal>().Die(
        "pm8058 rtc: register 0x%03X is not one of the block's fourteen", reg);
}

void Pm8058Rtc::WriteReg(uint16_t reg, uint8_t value) {
    std::lock_guard<std::mutex> lk(mtx_);

    if (reg == kRegCtrl) {
        if ((value & (uint8_t)~(kEnable | kAlarmEnable)) != 0u) {
            emu_.Get<Fatal>().Die(
                "pm8058 rtc: the 0x%02X written to control sets bits outside "
                "the 0x%02X the enable and alarm-enable fields occupy",
                value, (unsigned)(kEnable | kAlarmEnable));
        }
        if ((value & kAlarmEnable) != 0u) {
            emu_.Get<Fatal>().Die(
                "pm8058 rtc: the 0x%02X written to control arms the alarm, and "
                "no source names the interrupt that would deliver it", value);
        }
        const bool want = (value & kEnable) != 0u;
        if (want != running_) {
            if (running_) {
                LatchLocked();
            } else {
                anchor_us_ = HostSteadyMicros();
            }
            running_ = want;
        }
        ctrl_ = value;
        return;
    }

    /* Linux drivers/rtc/rtc-pm8xxx.c __pm8xxx_rtc_set_time writes byte 0 as
       zero, then bytes 1 through 3, then byte 0 again carrying its real value,
       so the counter takes the load registers when byte 0 is written. */
    if (reg >= kRegWrite && reg < kRegWrite + kBytes) {
        load_[reg - kRegWrite] = value;
        if (reg == kRegWrite) {
            base_ = cerf::le::U32(load_);
            anchor_us_ = HostSteadyMicros();
        }
        return;
    }

    if (reg == kRegAlarmCtl2) {
        emu_.Get<Fatal>().Die(
            "pm8058 rtc: the 0x%02X written to alarm control 2 clears an alarm "
            "status this model cannot raise (clear bit 0x%02X)",
            value, (unsigned)kAlarmClear);
    }
    if (reg >= kRegAlarmRw && reg < kRegAlarmRw + kBytes) {
        emu_.Get<Fatal>().Die(
            "pm8058 rtc: nothing models a write of 0x%02X to alarm register "
            "0x%03X while the alarm cannot be armed", value, reg);
    }

    emu_.Get<Fatal>().Die(
        "pm8058 rtc: nothing models a write of 0x%02X to register 0x%03X",
        value, reg);
}

void Pm8058Rtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write<uint32_t>("counter", CounterLocked());
    w.Write<uint8_t>("running", running_ ? 1u : 0u);
    w.Write<uint8_t>("ctrl", ctrl_);
    w.Write<uint8_t>("alarm_ctl2", alarm_ctl2_);
    for (uint32_t i = 0; i < kBytes; ++i) {
        w.Write<uint8_t>("load", load_[i]);
        w.Write<uint8_t>("alarm", alarm_[i]);
    }
}

void Pm8058Rtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t running = 0;
    r.Read("counter", base_);
    r.Read("running", running);
    r.Read("ctrl", ctrl_);
    r.Read("alarm_ctl2", alarm_ctl2_);
    for (uint32_t i = 0; i < kBytes; ++i) {
        r.Read("load", load_[i]);
        r.Read("alarm", alarm_[i]);
    }
    running_   = running != 0u;
    anchor_us_ = HostSteadyMicros();
    if (((ctrl_ & kEnable) != 0u) != running_) {
        r.Reject(
            "pm8058 rtc: restored control 0x%02X disagrees with the restored "
            "running flag %u", ctrl_, (unsigned)running_);
    }
}

REGISTER_SERVICE(Pm8058Rtc);
