#include "sa11xx_rtc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../host/guest_deep_sleep.h"
#include "../../state/state_stream.h"
#include "sa11xx_intc.h"

REGISTER_SERVICE(Sa11xxRtc);

namespace {

/* §9.2.1.1 Table 9-1 ICPR source bits. */
constexpr uint32_t kIntcAlarmBit = 1u << 31;
constexpr uint32_t kIntcHzBit    = 1u << 30;

/* SA-1110 Dev Man §9.3.5.1: "When the trim circuitry is disabled, the 1-Hz
   clock feeding the RTC is the same frequency as the output of the 32.768-kHz
   oscillator." */
constexpr uint64_t kOscHz = 32768u;

/* SA-1110 Dev Man §9.3.1: RCNR writes are delayed "by up to one 32-kHz-clock (~ 30 us)
   after the processor store is performed". */
constexpr IntelRtcCounter::Traits kTraits = {
    "sa11xx", 0x03FFFFFFu, 0u, false, false, true, 1u, 0u, 0u, 0u, 0u, true,
};

}

Sa11xxRtc::Sa11xxRtc(CerfEmulator& emu)
    : Peripheral(emu), rtc_{emu, kTraits, [this] { PushLevel(); }} {}

bool Sa11xxRtc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxRtc::OnReady() {
    rtc_.Attach(kOscHz, 1u);
    /* §9.5.3, second step of sleep shutdown: "All potential wake-up sources
       are cleared. This involves ... clearing the RTC alarm interrupt bit." */
    emu_.Get<GuestDeepSleep>().RegisterSleepEntryListener([this] {
        rtc_.RequireSettled("sleep entered");
        rtc_.ClearAlarmStatus();
    });
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        OnResetLine(kind);
    });
    emu_.Get<PeripheralDispatcher>().Register(this);
    rtc_.Rearm();
}

void Sa11xxRtc::SaveState(StateWriter& w) { rtc_.Save(w); }
void Sa11xxRtc::RestoreState(StateReader& r) { rtc_.Restore(r); }

void Sa11xxRtc::PostRestore() {
    PushLevel();
    rtc_.Rearm();
}

/* §9.3.2: "Following each rising edge of the 1-Hz clock, this register is
   compared to the RCNR. If the two are equal and the enable bit is set, then
   the alarm bit in the RTC status register is set." */
int64_t Sa11xxRtc::AlarmWakeDueNs() {
    if ((rtc_.Rtsr() & IntelRtcCounter::kRtsrAle) == 0u) return GuestDeepSleep::kNoParkWake;
    return rtc_.SleptNsAtEdge(rtc_.EdgesToMatch());
}

void Sa11xxRtc::CreditCoreStop(uint64_t ns) { rtc_.CreditCoreStop(ns); }

/* SA-1110 Dev Man §9.3.3: "The AL and HZ bits in this register are routed to the
   interrupt controller"; ALE "RTC alarm interrupt enable", HZE "1-Hz interrupt enable". */
void Sa11xxRtc::PushLevel() {
    const uint32_t rtsr = rtc_.Rtsr();
    uint32_t level = 0;
    if ((rtsr & IntelRtcCounter::kRtsrAl) && (rtsr & IntelRtcCounter::kRtsrAle))
        level |= kIntcAlarmBit;
    if ((rtsr & IntelRtcCounter::kRtsrHz) && (rtsr & IntelRtcCounter::kRtsrHze))
        level |= kIntcHzBit;
    emu_.Get<Sa11xxIntc>().SetSourceLevel(kIntcAlarmBit | kIntcHzBit, level);
}

/* §9.3.5.1: "The RTTR is reset to all zeros each time the nRESET signal is
   asserted." */
void Sa11xxRtc::OnResetLine(ResetLineKind kind) {
    if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
    if (kind != ResetLineKind::Rtc) return;
    rtc_.Advance();
    const uint32_t before = rtc_.Rcnr();
    const uint32_t was    = rtc_.Rttr();
    rtc_.ResetRttr(0u);
    LOG(SocTimer, "[RTCRESET] sa11xx reset: rcnr %u -> %u rttr 0x%X -> 0x%X\n",
        before, rtc_.Rcnr(), was, rtc_.Rttr());
}

uint32_t Sa11xxRtc::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x00: return rtc_.Rtar();
        case 0x04: return rtc_.Rcnr();
        case 0x08: return rtc_.Rttr();
        case 0x10: return rtc_.Rtsr();
        default:
            emu_.Get<Fatal>().Die("Sa11xxRtc: read of unmapped offset +0x%02X", off);
    }
}

void Sa11xxRtc::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x00:
            rtc_.WriteRtar(value);
            LOG(SocTimer, "[RTC] sa11xx RTAR <- %u (rcnr %u rtsr=0x%X)\n", rtc_.Rtar(),
                rtc_.Rcnr(), rtc_.Rtsr());
            break;
        case 0x04: rtc_.WriteRcnr(value); break;
        case 0x08: rtc_.WriteRttr(value); break;
        case 0x10: rtc_.WriteRtsr(value); break;
        default:
            emu_.Get<Fatal>().Die("Sa11xxRtc: write 0x%08X to unmapped offset +0x%02X", value, off);
    }
}

uint32_t Sa11xxRtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off != 0x00 && off != 0x04 && off != 0x08 && off != 0x10) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    rtc_.Rearm();
    return ReadReg(off);
}

void Sa11xxRtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off != 0x00 && off != 0x04 && off != 0x08 && off != 0x10) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    WriteReg(off, value);
}
