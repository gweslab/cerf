#pragma once

#include "../../core/service.h"
#include "../../socs/oscillator_ticks.h"

#include <cstdint>

class Mc13783IntLine;
class StateWriter;
class StateReader;

class Mc13783 : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    /* MC13783 datasheet §4.1.1.3.1 SPI Transfer Protocol. */
    uint32_t SpiExchange(uint32_t cmd);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    /* MC13783 datasheet Table 5: 64 control fields of 24 bits each. */
    static constexpr uint32_t kRegisterCount = 64;
    uint32_t regs_[kRegisterCount] = {};

    /* §4.1.2.2.1: 17-bit TOD (0..86399), 15-bit DAY (0..32767). */
    static constexpr uint32_t kRtcDayMask = 0x7FFFu;

    uint64_t RtcSeconds();
    uint64_t TickSeconds();
    void     WriteRtc(uint32_t addr, uint32_t data);
    uint32_t ReadReg(uint32_t addr);
    void     WriteReg(uint32_t addr, uint32_t data);
    bool     AlarmMatches(uint64_t secs) const;
    void     RearmAlarm(uint64_t now);
    void     OnAlarm();
    bool     IntLevel() const;
    void     UpdateInt();

    OscillatorTicks         clk32k_{emu_, true};
    int64_t                 rtc_offset_secs_  = 0;
    uint64_t                hz_clear_second_  = 0;
    GuestCycleClock*        clock_            = nullptr;
    GuestCycleClock::Event* alarm_event_      = nullptr;
    Mc13783IntLine*         int_line_         = nullptr;
    bool                    int_asserted_     = false;
    bool                    pending_todai_    = false;
};
