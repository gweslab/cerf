#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../socs/cycle_anchored_counter.h"

#include <cstdint>
#include <mutex>

class Pm8058Irq;
class StateWriter;
class StateReader;

class Pm8058Rtc : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    /* Linux drivers/rtc/rtc-pm8xxx.c pm8058_regs: ctrl 0x1e8, write 0x1ea,
       read 0x1ee, alarm_ctrl 0x1e8, alarm_ctrl2 0x1e9, alarm_rw 0x1f2, with
       NUM_8_BIT_RTC_REGS 4 bytes in each of the three register groups. */
    static constexpr uint16_t kRegCtrl      = 0x01E8u;
    static constexpr uint16_t kRegAlarmCtl2 = 0x01E9u;
    static constexpr uint16_t kRegWrite     = 0x01EAu;
    static constexpr uint16_t kRegRead      = 0x01EEu;
    static constexpr uint16_t kRegAlarmRw   = 0x01F2u;
    static constexpr uint32_t kBytes        = 4u;

    static bool Owns(uint16_t reg) {
        return reg >= kRegCtrl && reg < kRegAlarmRw + kBytes;
    }

    uint8_t ReadReg(uint16_t reg);
    void    WriteReg(uint16_t reg, uint8_t value);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    bool     RunningLocked() const;
    bool     AlarmArmedLocked() const;
    uint32_t CountLocked(uint64_t now) const;
    uint32_t AlarmLocked() const;
    void     SetCountLocked(uint64_t now, uint32_t count);
    void     SetAlarmStatusLocked(bool high);
    void     ArmAlarmLocked(uint64_t now);
    void     RequireComparatorUnequalLocked(uint64_t now, const char* write) const;
    void     PowerOn();
    void     OnAlarmMatch();
    void     OnRateChange();
    void     RedriveAlarmLine();
    void     RequireRatio(bool ok) const;

    std::mutex mtx_;

    GuestCycleClock*        clock_       = nullptr;
    GuestCycleClock::Event* alarm_event_ = nullptr;
    Pm8058Irq*              irq_         = nullptr;
    CycleAnchoredCounter    counter_;
    uint32_t                stopped_count_ = 0;
    uint8_t                 ctrl_          = 0;
    bool                    alarm_status_  = false;
    uint8_t                 alarm_[kBytes] = {};
};
