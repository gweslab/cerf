#include "mc13783.h"

#include "mc13783_int_line.h"
#include "../../boards/board_context.h"
#include "../../boards/zune_keel/zune_30_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../host/guest_deep_sleep.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../state/state_stream.h"

#include <cstring>

REGISTER_SERVICE(Mc13783);

namespace {

constexpr uint32_t kRegStatus0     = 0;
constexpr uint32_t kRegMask0       = 1;
constexpr uint32_t kRegSense0      = 2;
constexpr uint32_t kRegStatus1     = 3;
constexpr uint32_t kRegMask1       = 4;
constexpr uint32_t kRegSense1      = 5;
constexpr uint32_t kRegRtcTime     = 20;
constexpr uint32_t kRegRtcAlarm    = 21;
constexpr uint32_t kRegRtcDay      = 22;
constexpr uint32_t kRegRtcDayAlarm = 23;
constexpr uint32_t kRegAdc1        = 44;
constexpr uint32_t kFieldMask      = 0x00FFFFFFu;
constexpr uint32_t kSecondsPerDay  = 86400u;

/* MC13783 UG Table 13-4 and Table 13-5. */
constexpr uint32_t kStatus1Hzi    = 1u << 0;
constexpr uint32_t kStatus1Todai  = 1u << 1;
constexpr uint32_t kStatus1Rtcrst = 1u << 7;
constexpr uint32_t kMask1Hzm      = 1u << 0;

/* UG Tables 13-2 and 13-5, §3.4.1: reserved mask bits default to 1 and must not be
   programmed to 0. */
constexpr uint32_t kMask0Reserved = 0x160020u;
constexpr uint32_t kMask1Reserved = 0xC10004u;

/* MC13783 UG Table 13-22 and Table 13-24. */
constexpr uint32_t kTodaMask = 0x1FFFFu;
constexpr uint32_t kDayaMask = 0x7FFFu;

/* UG Table 13-3 BPONS, LOBATHS, IDFLOATS; Table 10-8: IDFLOATS with no device. */
constexpr uint32_t kSense0 = (1u << 12) | (1u << 14) | (1u << 19);

/* UG Table 13-6 ONOFD1S, ONOFD2S, ONOFD3S, CLKS; Table 3-8: ONOFDnS is 1 while the pin is
   high. */
constexpr uint32_t kSense1 = (1u << 3) | (1u << 4) | (1u << 5) | (1u << 14);

/* UG Table 13-45: ASC starts a conversion. */
constexpr uint32_t kAdc1Asc = 1u << 20;

/* MC13783 datasheet §4.1.2.1: the part generates a 32.768 kHz clock; §4.1.2.2.1 divides
   it down to the 1 Hz time tick. */
constexpr uint64_t kClk32kHz = 32768u;

}

bool Mc13783::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Zune30;
}

void Mc13783::OnReady() {
    clock_       = &emu_.Get<GuestCycleClock>();
    alarm_event_ = clock_->Add([this] { OnAlarm(); });
    int_line_    = &emu_.Get<Mc13783IntLine>();

    /* UG §3.4.1: the part powers up with all interrupts masked. §4.2.2: TODA and DAYA are
       all 1s at power up. §4.2.3: RTCRSTI defaults to 1 on RTCPORB. */
    regs_[kRegMask0]       = kFieldMask;
    regs_[kRegMask1]       = kFieldMask;
    regs_[kRegRtcAlarm]    = kTodaMask;
    regs_[kRegRtcDayAlarm] = kDayaMask;
    regs_[kRegStatus1]     = kStatus1Rtcrst;

    clk32k_.Attach(kClk32kHz, 1u);
    clock_->RegisterRateListener([this] {
        clk32k_.Rescale();
        RearmAlarm(clock_->Cycles());
    });
    emu_.Get<GuestDeepSleep>().RegisterParkClock([this] { RearmAlarm(clock_->Cycles()); });
}

void Mc13783::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_, sizeof(regs_));
    clk32k_.Save(w);
    w.Write("rtc_offset_secs", rtc_offset_secs_);
    w.Write("hz_clear_second", hz_clear_second_);
}

void Mc13783::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_, sizeof(regs_));
    clk32k_.Restore(r);
    r.Read("rtc_offset_secs", rtc_offset_secs_);
    r.Read("hz_clear_second", hz_clear_second_);
    pending_todai_ = false;
    clock_->Disarm(alarm_event_);
}

void Mc13783::PostRestore() {
    RearmAlarm(clock_->Cycles());
    int_asserted_ = IntLevel();
    int_line_->SetMc13783IntAsserted(int_asserted_);
}

uint64_t Mc13783::TickSeconds() {
    return clk32k_.Now() / kClk32kHz;
}

uint64_t Mc13783::RtcSeconds() {
    return static_cast<uint64_t>(static_cast<int64_t>(TickSeconds()) + rtc_offset_secs_);
}

/* §4.1.2.2.1: the 1 Hz tick drives the TOD counter, which rolls over into DAY at 86,400. */
void Mc13783::WriteRtc(uint32_t addr, uint32_t data) {
    const uint64_t now  = RtcSeconds();
    uint64_t       day  = now / kSecondsPerDay;
    uint64_t       tod  = now % kSecondsPerDay;
    if (addr == kRegRtcTime) {
        if (data >= kSecondsPerDay) {
            emu_.Get<Fatal>().Die("Mc13783: TOD write 0x%06X is past the 0..86399 count",
                                  data);
        }
        tod = data;
    } else {
        day = data & kRtcDayMask;
    }
    rtc_offset_secs_ += static_cast<int64_t>(day * kSecondsPerDay + tod) -
                        static_cast<int64_t>(now);
}

/* UG §4.2.2: TODAI when the TOD counter equals TODA and the DAY counter equals DAYA. */
bool Mc13783::AlarmMatches(uint64_t secs) const {
    return secs % kSecondsPerDay == regs_[kRegRtcAlarm] &&
           ((secs / kSecondsPerDay) & kDayaMask) == regs_[kRegRtcDayAlarm];
}

void Mc13783::RearmAlarm(uint64_t now) {
    if (pending_todai_) {
        clock_->Arm(alarm_event_, now);
        return;
    }
    if (regs_[kRegRtcAlarm] >= kSecondsPerDay) {
        clock_->Disarm(alarm_event_);
        return;
    }
    constexpr uint64_t kPeriod = (uint64_t{kDayaMask} + 1u) * kSecondsPerDay;
    const uint64_t target = uint64_t{regs_[kRegRtcDayAlarm]} * kSecondsPerDay +
                            regs_[kRegRtcAlarm];
    uint64_t ahead = (target + kPeriod - RtcSeconds() % kPeriod) % kPeriod;
    if (ahead == 0u) ahead = kPeriod;
    clk32k_.ArmAt(alarm_event_, (TickSeconds() + ahead) * kClk32kHz);
}

/* UG Table 3-8: TODAI triggers on the low-to-high transition of the match. */
void Mc13783::OnAlarm() {
    pending_todai_ = false;
    regs_[kRegStatus1] |= kStatus1Todai;
    UpdateInt();
    RearmAlarm(clock_->Cycles());
}

/* UG §3.4.1: PRIINT is high while an unmasked status bit is set. */
bool Mc13783::IntLevel() const {
    return (((regs_[kRegStatus0] & ~regs_[kRegMask0]) |
             (regs_[kRegStatus1] & ~regs_[kRegMask1])) & kFieldMask) != 0u;
}

void Mc13783::UpdateInt() {
    const bool level = IntLevel();
    if (level == int_asserted_) return;
    int_asserted_ = level;
    int_line_->SetMc13783IntAsserted(level);
}

uint32_t Mc13783::ReadReg(uint32_t addr) {
    switch (addr) {
        case kRegRtcTime:
            return static_cast<uint32_t>(RtcSeconds() % kSecondsPerDay);
        case kRegRtcDay:
            return static_cast<uint32_t>(RtcSeconds() / kSecondsPerDay) & kRtcDayMask;
        /* UG §3.4.1: a status bit latches whether or not it is masked. */
        case kRegStatus1:
            return regs_[addr] | (TickSeconds() > hz_clear_second_ ? kStatus1Hzi : 0u);
        case kRegSense0:
            return kSense0;
        case kRegSense1:
            return kSense1;
        default:
            return regs_[addr] & kFieldMask;
    }
}

void Mc13783::WriteReg(uint32_t addr, uint32_t data) {
    const uint64_t now = clock_->Cycles();
    if (clock_->IsDue(alarm_event_, now)) pending_todai_ = true;
    const bool matched = AlarmMatches(RtcSeconds());

    switch (addr) {
        /* UG §3.4.1: writing 1 to a status bit clears it. */
        case kRegStatus0:
            regs_[addr] &= ~data;
            break;
        case kRegStatus1:
            if ((data & kStatus1Hzi) != 0u) hz_clear_second_ = TickSeconds();
            if ((data & kStatus1Todai) != 0u) pending_todai_ = false;
            regs_[addr] &= ~data;
            break;
        case kRegMask0:
        case kRegMask1: {
            const uint32_t reserved = addr == kRegMask0 ? kMask0Reserved : kMask1Reserved;
            if ((data & reserved) != reserved) {
                emu_.Get<Fatal>().Die("Mc13783: mask register %u write 0x%06X clears a "
                                      "reserved bit", addr, data);
            }
            if (addr == kRegMask1 && (data & kMask1Hzm) == 0u) {
                emu_.Get<Fatal>().Die("Mc13783: mask register 4 write 0x%06X unmasks 1HZI; "
                                      "the 1 Hz interrupt output is not modeled", data);
            }
            regs_[addr] = data;
            break;
        }
        case kRegSense0:
        case kRegSense1:
            emu_.Get<Fatal>().Die("Mc13783: write 0x%06X to the read-only sense register %u",
                                  data, addr);
        case kRegRtcTime:
        case kRegRtcDay:
            WriteRtc(addr, data);
            break;
        case kRegRtcAlarm:
            regs_[addr] = data & kTodaMask;
            break;
        case kRegRtcDayAlarm:
            regs_[addr] = data & kDayaMask;
            break;
        case kRegAdc1:
            if ((data & kAdc1Asc) != 0u) {
                emu_.Get<Fatal>().Die("Mc13783: ADC1 write 0x%06X starts a conversion; the "
                                      "ADC is not modeled", data);
            }
            regs_[addr] = data;
            break;
        default:
            regs_[addr] = data;
            break;
    }

    if (!matched && AlarmMatches(RtcSeconds())) regs_[kRegStatus1] |= kStatus1Todai;
    UpdateInt();
    RearmAlarm(now);
}

uint32_t Mc13783::SpiExchange(uint32_t cmd) {
    const bool     write = ((cmd >> 31) & 1u) != 0;
    const uint32_t addr  = (cmd >> 25) & 0x3Fu;
    const uint32_t data  = cmd & kFieldMask;
    const uint32_t value = ReadReg(addr);

    if (write) {
        WriteReg(addr, data);
        LOG(Periph, "[MC13783] WRITE reg=%u (0x%02X) data=0x%06X\n",
            addr, addr, data);
        return value;
    }

    LOG(Periph, "[MC13783] READ  reg=%u (0x%02X) value=0x%06X\n",
        addr, addr, value);
    return value;
}
