#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/nec_rockhopper/nec_rockhopper_id.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <mutex>


namespace {

constexpr uint32_t kBase = 0x1A000000u;   /* BSP_REG_PA_NVRAM */
constexpr uint32_t kSize = 0x00010000u;   /* NVRAM decode window: base..BSP_REG_PA_SWITCH */

enum : uint32_t {
    kSECLL = 0x00, kSECTL = 0x01, kMINTL = 0x02, kAL_MIN = 0x03,
    kHOURS = 0x04, kAL_HR = 0x05, kDAYS  = 0x06, kAL_DAY = 0x07,
    kDATE  = 0x08, kMONTH = 0x09, kYEARS = 0x0A, kCMD    = 0x0B,
    kWD0   = 0x0C, kWD1   = 0x0D, kRAM_BASE = 0x0E,
};

constexpr uint8_t kCmdTE  = 0x80;   /* transfer enable */
constexpr uint8_t kCmdWAF = 0x02;   /* watchdog alarm flag (read-only) */
constexpr uint8_t kCmdTDF = 0x01;   /* time-of-day alarm flag (read-only) */
constexpr uint8_t kCmdRwMask = 0xFC; /* TE/IPSW/IBH/PU/WAM/TDM are R/W; WAF/TDF read-only */

constexpr uint8_t kMonthEOSC = 0x80;  /* oscillator stop (1 = stopped) */
constexpr uint8_t kMonthFlags = 0xC0; /* EOSC | ESQW - stored apart from the BCD month */
constexpr uint8_t kHours1224  = 0x40; /* HOURS bit6: 1 = 12-hour, 0 = 24-hour */
constexpr uint8_t kHoursAMPM  = 0x20; /* HOURS bit5: 1 = PM (12-hour mode) */

uint8_t ToBcd(uint32_t v)   { return static_cast<uint8_t>(((v / 10u) << 4) | (v % 10u)); }
uint32_t FromBcd(uint8_t b) { return static_cast<uint32_t>((b >> 4) * 10u + (b & 0x0Fu)); }

class Ds1386Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecRockhopper;
    }
    void OnReady() override {
        std::lock_guard<std::mutex> lk(mtx_);
        /* DS1386 ships with EOSC set (oscillator off); the clock is frozen at
           the host time until the OAL enables it (TE=1, EOSC=0). */
        month_flags_ = kMonthEOSC;
        running_     = false;
        frozen_sec_  = HostSec();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte (uint32_t addr) override;
    void    WriteByte(uint32_t addr, uint8_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Host wall-clock helpers. */
    static int64_t HostMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    }
    static int64_t HostSec() { return HostMs() / 1000; }

    /* The live guest epoch seconds: host+offset while running, else the frozen
       value (TE=0 / EOSC=1 stop the internal->external transfer). */
    int64_t GuestSec() const { return running_ ? HostSec() + offset_sec_ : frozen_sec_; }

    void SetRunning(bool r) {
        if (r == running_) return;
        if (r) { offset_sec_ = frozen_sec_ - HostSec(); }   /* resume from frozen value */
        else   { frozen_sec_ = GuestSec(); }                /* capture current time */
        running_ = r;
    }

    void SetGuestSec(int64_t g) {
        if (running_) offset_sec_ = g - HostSec();
        else          frozen_sec_ = g;
    }

    /* Recompute the clock offset after a guest write replaces one broken-down
       field (TE=1 write-through; converges across the OAL's field-by-field set). */
    void WriteClockField(int field, uint32_t value);

    void RefreshRunState() { SetRunning((cmd_ & kCmdTE) != 0 && (month_flags_ & kMonthEOSC) == 0); }

    mutable std::mutex mtx_;

    /* Clock source. */
    bool    running_     = false;
    int64_t offset_sec_  = 0;   /* guest = host + offset while running (a delta - hibernation-safe) */
    int64_t frozen_sec_  = 0;   /* guest epoch seconds while stopped */

    /* Control / mode / alarm registers (the chip state the host clock can't supply). */
    uint8_t cmd_         = 0;            /* command register (WAF/TDF in bits 1:0) */
    uint8_t month_flags_ = kMonthEOSC;   /* EOSC | ESQW (bits 7:6 of MONTH) */
    uint8_t hours_mode_  = 0;            /* 12/24 (bit6) | AM-PM (bit5) of HOURS */
    uint8_t al_min_ = 0, al_hour_ = 0, al_day_ = 0;   /* TOD alarm (raw, incl. mask bit7) */
    uint8_t wd_[2]  = {0, 0};                          /* watchdog alarm BCD */

    /* User NV-SRAM: registers 0x0E.. over the board's NVRAM decode window. */
    uint8_t nvram_[kSize - kRAM_BASE] = {};
};

uint8_t Ds1386Rtc::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);

    if (off >= kRAM_BASE) return nvram_[off - kRAM_BASE];

    const int64_t g = GuestSec();
    const std::time_t tt = static_cast<std::time_t>(g);
    std::tm lt{};
    localtime_s(&lt, &tt);

    switch (off) {
        case kSECLL: {
            const uint32_t cs = running_ ? static_cast<uint32_t>((HostMs() % 1000) / 10) : 0u;
            return ToBcd(cs);
        }
        case kSECTL: return ToBcd(static_cast<uint32_t>(lt.tm_sec));
        case kMINTL: return ToBcd(static_cast<uint32_t>(lt.tm_min));
        case kHOURS: {
            uint32_t hour = static_cast<uint32_t>(lt.tm_hour);   /* 0..23 */
            if (hours_mode_ & kHours1224) {                      /* 12-hour mode */
                const bool pm = hour >= 12u;
                uint32_t h12 = hour % 12u; if (h12 == 0u) h12 = 12u;
                return static_cast<uint8_t>(ToBcd(h12) | kHours1224 | (pm ? kHoursAMPM : 0u));
            }
            return ToBcd(hour);                                  /* 24-hour: bit6 = 0 */
        }
        case kDAYS:  return static_cast<uint8_t>(lt.tm_wday + 1);   /* 1..7, single BCD digit */
        case kDATE:  return ToBcd(static_cast<uint32_t>(lt.tm_mday));
        case kMONTH: return static_cast<uint8_t>(ToBcd(static_cast<uint32_t>(lt.tm_mon + 1)) | month_flags_);
        case kYEARS: return ToBcd(static_cast<uint32_t>(lt.tm_year % 100));   /* 2000-based, tm_year is 1900-based */

        case kAL_MIN: cmd_ &= ~kCmdTDF; return al_min_;    /* reading a TOD-alarm reg clears TDF (datasheet p.9) */
        case kAL_HR:  cmd_ &= ~kCmdTDF; return al_hour_;
        case kAL_DAY: cmd_ &= ~kCmdTDF; return al_day_;

        case kCMD:    return cmd_;
        case kWD0:    cmd_ &= ~kCmdWAF; return wd_[0];      /* accessing a watchdog reg clears WAF + reinit */
        case kWD1:    cmd_ &= ~kCmdWAF; return wd_[1];
        default:      return 0;
    }
}

void Ds1386Rtc::WriteClockField(int field, uint32_t value) {
    const int64_t g = GuestSec();
    const std::time_t tt = static_cast<std::time_t>(g);
    std::tm lt{};
    localtime_s(&lt, &tt);
    lt.tm_isdst = -1;

    switch (field) {
        case kSECTL: lt.tm_sec  = static_cast<int>(FromBcd(static_cast<uint8_t>(value)));        break;
        case kMINTL: lt.tm_min  = static_cast<int>(FromBcd(static_cast<uint8_t>(value)));        break;
        case kHOURS: {
            if (value & kHours1224) {   /* 12-hour mode write */
                uint32_t h12 = FromBcd(static_cast<uint8_t>(value & 0x1Fu));
                if (h12 == 12u) h12 = 0u;
                lt.tm_hour = static_cast<int>(h12 + ((value & kHoursAMPM) ? 12u : 0u));
            } else {                    /* 24-hour mode write (bits 5:0) */
                lt.tm_hour = static_cast<int>(FromBcd(static_cast<uint8_t>(value & 0x3Fu)));
            }
            break;
        }
        case kDATE:  lt.tm_mday = static_cast<int>(FromBcd(static_cast<uint8_t>(value)));        break;
        case kMONTH: lt.tm_mon  = static_cast<int>(FromBcd(static_cast<uint8_t>(value & 0x1Fu))) - 1; break;
        case kYEARS: lt.tm_year = 100 + static_cast<int>(FromBcd(static_cast<uint8_t>(value)));  break;
        default: return;
    }
    const std::time_t ng = std::mktime(&lt);
    if (ng != static_cast<std::time_t>(-1)) SetGuestSec(static_cast<int64_t>(ng));
}

void Ds1386Rtc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);

    if (off >= kRAM_BASE) { nvram_[off - kRAM_BASE] = value; return; }

    switch (off) {
        case kSECLL: break;   /* sub-second write: offset is whole-second; OAL never writes SECLL */
        case kSECTL: case kMINTL: case kDATE: case kYEARS:
            WriteClockField(static_cast<int>(off), value);
            break;
        case kHOURS:
            hours_mode_ = value & (kHours1224 | kHoursAMPM);
            WriteClockField(kHOURS, value);
            break;
        case kDAYS:  break;   /* day-of-week is derived from the date (set via DATE/MONTH/YEARS) */
        case kMONTH:
            month_flags_ = value & kMonthFlags;       /* EOSC | ESQW */
            WriteClockField(kMONTH, value);
            RefreshRunState();                        /* EOSC change starts/stops the clock */
            break;

        case kAL_MIN: al_min_  = value; break;
        case kAL_HR:  al_hour_ = value; break;
        case kAL_DAY: al_day_  = value; break;

        case kCMD:
            cmd_ = static_cast<uint8_t>((cmd_ & ~kCmdRwMask) | (value & kCmdRwMask));  /* WAF/TDF read-only */
            RefreshRunState();                        /* TE change enables/freezes transfer */
            break;

        /* Watchdog alarm: storage + WAF clear on access (datasheet p.7). The
           countdown's interrupt output connects when the VRC5477 INTC + CP0
           exception delivery exist; the chip-side state is complete here. */
        case kWD0: wd_[0] = value; cmd_ &= ~kCmdWAF; break;
        case kWD1: wd_[1] = value; cmd_ &= ~kCmdWAF; break;
        default: break;
    }
}

void Ds1386Rtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    /* offset_sec_/frozen_sec_ are deltas/relative epochs, not host time_points,
       so they restore correctly against the new host clock (hibernation.md). */
    w.Write("running", static_cast<uint8_t>(running_ ? 1u : 0u));
    w.Write("offset_sec", offset_sec_); w.Write("frozen_sec", frozen_sec_);
    w.Write("cmd", cmd_); w.Write("month_flags", month_flags_); w.Write("hours_mode", hours_mode_);
    w.Write("al_min", al_min_); w.Write("al_hour", al_hour_); w.Write("al_day", al_day_);
    w.Write("wd", wd_[0]); w.Write("wd", wd_[1]);
    w.WriteBytes("nvram", nvram_, sizeof(nvram_));
}

void Ds1386Rtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t run = 0; r.Read("running", run); running_ = run != 0;
    r.Read("offset_sec", offset_sec_); r.Read("frozen_sec", frozen_sec_);
    r.Read("cmd", cmd_); r.Read("month_flags", month_flags_); r.Read("hours_mode", hours_mode_);
    r.Read("al_min", al_min_); r.Read("al_hour", al_hour_); r.Read("al_day", al_day_);
    r.Read("wd", wd_[0]); r.Read("wd", wd_[1]);
    r.ReadBytes("nvram", nvram_, sizeof(nvram_));
}

}  /* namespace */

REGISTER_SERVICE(Ds1386Rtc);
