#include "pxa255_rtc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "pxa255_clock_manager.h"
#include "pxa255_power_manager.h"
#include "../../host/guest_deep_sleep.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"
#include "../pxa2xx/pxa2xx_intc.h"

REGISTER_SERVICE(Pxa255Rtc);

namespace {

/* PXA255 Dev Man Table 4-36: "IS<31> Real-time clock ... RTC equals alarm
   register", "IS<30> One Hz clock TIC occurred". */
constexpr uint32_t kIntcAlarmBit = 1u << 31;
constexpr uint32_t kIntcHzBit    = 1u << 30;

/* §4.3.2.1 Table 4-37: "<31> LCK", "<25:16> DEL", "<15:0> CK_DIV";
   §4.3.3: "The RTTR is reset to its default value of 0x0000_7FFF". */
constexpr uint32_t kRttrLck   = 0x80000000u;
constexpr uint32_t kRttrReset = 0x00007FFFu;

/* §3.6.3 Table 3-22 OON: "0 - 32.768 KHz oscillator is disabled. The 3.6864
   MHz oscillator (divided by 112) clocks the RTC and PM." */
constexpr uint64_t kOscCrystalHz = 32768u;
constexpr uint64_t kOscDividedNum = 230400u;
constexpr uint64_t kOscDividedDen = 7u;

/* §4.3.2.3: the RCNR write is delayed "by approximately two 32 kHz clock cycles"; §4.3.2.2:
   the RTAR write is delayed "by two 32 kHz clock cycles after the processor store". */
constexpr IntelRtcCounter::Traits kTraits = {
    "pxa255", kRttrLck | 0x03FFFFFFu, kRttrLck, true, true, false, 2u, 2u, 0u, 0u, 0u, false,
};

}

Pxa255Rtc::Pxa255Rtc(CerfEmulator& emu)
    : Peripheral(emu), rtc_{emu, kTraits, [this] { PushLevel(); }} {}

bool Pxa255Rtc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

void Pxa255Rtc::OnReady() {
    rtc_.Attach(kOscDividedNum, kOscDividedDen);
    rtc_.ResetRttr(kRttrReset);
    auto& clocks = emu_.Get<Pxa255ClockManager>();
    clocks.RegisterOscillatorListener([this] { ApplyOscillator(); });
    ApplyOscillator();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        OnResetLine(kind);
    });
    /* PXA255 Dev Man Table 3-9 WERTC: "Wake-up due to RTC alarm enabled."
       §4.3.2.4: "In Sleep mode, only AL events set the status bit". */
    auto& sleep = emu_.Get<GuestDeepSleep>();
    sleep.RegisterSleepEntryListener([this] {
        rtc_.RequireSettled("sleep entered");
        alarm_mark_ = rtc_.AlarmEvents();
        match_mark_ = rtc_.MatchEvents();
    });
    auto alarm_woke = [this] {
        return emu_.Get<Pxa255PowerManager>().RtcAlarmWakeEnabled() &&
               rtc_.AlarmEvents() != alarm_mark_;
    };
    sleep.RegisterParkClock([this, alarm_woke] {
        if (alarm_woke()) {
            emu_.Get<Pxa255PowerManager>().LatchRtcWakeEdge();
        } else if (emu_.Get<Pxa255PowerManager>().RtcAlarmWakeEnabled() &&
                   rtc_.MatchEvents() != match_mark_) {
            emu_.Get<Fatal>().Die("Pxa255Rtc: RCNR reached RTAR %u in sleep with PWER.WERTC set "
                                  "and RTSR.ALE clear (rtsr=0x%X); an RTC wake without ALE is "
                                  "not modelled", rtc_.Rtar(), rtc_.Rtsr());
        }
    });
    sleep.RegisterParkWakeSource(alarm_woke);
    sleep.RegisterParkWakeDue([this] {
        if (!emu_.Get<Pxa255PowerManager>().RtcAlarmWakeEnabled()) {
            return GuestDeepSleep::kNoParkWake;
        }
        return rtc_.SleptNsAtEdge(rtc_.EdgesToMatch());
    });
    emu_.Get<PeripheralDispatcher>().Register(this);
    rtc_.Rearm();
}

void Pxa255Rtc::SaveState(StateWriter& w) { rtc_.Save(w); }
void Pxa255Rtc::RestoreState(StateReader& r) { rtc_.Restore(r); }

void Pxa255Rtc::PostRestore() {
    PushLevel();
    rtc_.Rearm();
}

/* §3.6.3: "When OSCC[OOK] is set, the RTC and PM are clocked
   from the 32.768 KHz oscillator. Otherwise, the 3.6864 MHz oscillator is
   used." */
void Pxa255Rtc::ApplyOscillator() {
    if (emu_.Get<Pxa255ClockManager>().OscillatorOk()) {
        rtc_.SetOscRate(kOscCrystalHz, 1u);
    } else {
        rtc_.SetOscRate(kOscDividedNum, kOscDividedDen);
    }
}

/* §4.3.2.4: "The AL and HZ bits are routed to the interrupt controller
   where they may be enabled to cause a first level interrupt." */
void Pxa255Rtc::PushLevel() {
    const uint32_t rtsr = rtc_.Rtsr();
    uint32_t level = 0;
    if ((rtsr & IntelRtcCounter::kRtsrAl) && (rtsr & IntelRtcCounter::kRtsrAle))
        level |= kIntcAlarmBit;
    if ((rtsr & IntelRtcCounter::kRtsrHz) && (rtsr & IntelRtcCounter::kRtsrHze))
        level |= kIntcHzBit;
    static_cast<Pxa2xxIntc&>(emu_.Get<IrqController>())
        .SetSourceLevel(kIntcAlarmBit | kIntcHzBit, level);
}

/* §4.3.1: "All registers in the RTC, with the exception RTTR, are reset by
   hardware reset and the watchdog reset. The trim register, RTTR is reset
   only by hardware reset." */
void Pxa255Rtc::OnResetLine(ResetLineKind kind) {
    if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
    if (kind == ResetLineKind::Rtc) {
        rtc_.ResetCounter();
        rtc_.ResetRttr(kRttrReset);
        return;
    }
    if (kind == ResetLineKind::Watchdog) rtc_.ResetCounter();
}

void Pxa255Rtc::WriteRttr(uint32_t value) {
    rtc_.WriteRttr(value);
    rtc_.IncrementRcnr();
}

uint32_t Pxa255Rtc::ReadWord(uint32_t addr) {
    rtc_.Rearm();
    switch (addr - MmioBase()) {
        case 0x00: return rtc_.Rcnr();
        case 0x04: return rtc_.Rtar();
        case 0x08: return rtc_.Rtsr();
        case 0x0C: return rtc_.Rttr();
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255Rtc::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: rtc_.WriteRcnr(value); return;
        case 0x04: rtc_.WriteRtar(value); return;
        case 0x08: rtc_.WriteRtsr(value); return;
        case 0x0C: WriteRttr(value);      return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}
