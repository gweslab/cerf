#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <chrono>
#include <cstdint>
#include <mutex>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 21-18 (page 21-27) "RTC
   Controller Register Summary": "0x4090_0000 RCNR", "0x4090_0004 RTAR",
   "0x4090_0008 RTSR", "0x4090_000C RTTR". */
class Pxa27xRtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40900000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    using Clock = std::chrono::steady_clock;

    /* Table 21-7 (pages 21-17..21-19) R/WC alarm-detect bits: "13 PIAL", "10
       SWAL2", "8 SWAL1", "6 RDAL2", "4 RDAL1", "1 HZ", "0 AL". R/W enable bits:
       "15 PICE", "14 PIALE", "12 SWCE", "11 SWALE2", "9 SWALE1", "7 RDALE2",
       "5 RDALE1", "3 HZE", "2 ALE". "31:16 reserved"; Reset row 0 for 15:0. */
    static constexpr uint32_t kRtsrDetect = 0x00002553u;
    static constexpr uint32_t kRtsrEnable = 0x0000DAACu;
    static constexpr uint32_t kRtsrAL     = 0x00000001u;
    static constexpr uint32_t kRtsrHZ     = 0x00000002u;
    static constexpr uint32_t kRtsrALE    = 0x00000004u;
    static constexpr uint32_t kRtsrHZE    = 0x00000008u;

    /* Table 21-6 (page 21-16): "31 R/W LCK", "30:26 reserved", "25:16 R/W DEL",
       "15:0 R/W CK_DIV". */
    static constexpr uint32_t kRttrMask = 0x83FFFFFFu;
    static constexpr uint32_t kRttrLck  = 0x80000000u;

    /* Table 21-14 (pages 21-24..21-25): "22:20 R/W WOM", "19:17 R/W DOW",
       "16:12 R/W HOURS", "11:6 R/W MINUTES", "5:0 R/W SECONDS", "31:23
       Reserved". */
    static constexpr uint32_t kRdcrMask = 0x007FFFFFu;

    /* Table 21-15 (page 21-25): "20:9 R/W YEAR", "8:5 R/W MONTH", "4:0 R/W DOM",
       "31:21 reserved". */
    static constexpr uint32_t kRycrMask = 0x001FFFFFu;

    /* Section 21.5.8 (page 21-24): "RCNR is incremented at each rising edge of a
       1-Hz clock signal". */
    uint32_t ReadRcnrLocked() const {
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - baseline_).count();
        return rcnr_base_ + static_cast<uint32_t>(secs);
    }

    uint32_t ReadRtsrLocked() const;

    /* Section 21.4.2 (page 21-6): "The counters section of the wristwatch
       consists of two 32-bit, free-running counters (RDCR and RYCR)". */
    std::chrono::sys_seconds WristwatchLocked() const {
        return ww_base_ + std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - ww_baseline_);
    }

    uint32_t ReadRdcrLocked() const;
    uint32_t ReadRycrLocked() const;
    void     CommitWristwatchLocked(uint32_t rdcr);

    mutable std::mutex mtx_;

    /* Table 21-13 (page 21-24) RCNR Reset row: all 0. */
    uint32_t          rcnr_base_ = 0;
    Clock::time_point baseline_  = Clock::now();

    /* Table 21-8 (page 21-19): "31:0 R/W RTMV RTC Target Match Value"; Reset row
       all 0. */
    uint32_t rtar_ = 0;

    uint32_t rtsr_ = 0;

    /* Section 21.5.1 (page 21-16): "The reset value of this register
       (0x0000_7FFF) is such that a perfect 32.768-kHz crystal would result in a
       1-Hz clock." */
    uint32_t rttr_ = 0x00007FFFu;

    /* Section 21.5.3 (page 21-19): "Following each rising edge of the 1-Hz
       clock, this register is compared to the RCNR. If the two are equal and
       RTSR[ALE] is set, then RTSR[AL] is set." */
    uint32_t alarm_armed_at_ = 0;
    uint32_t hz_armed_at_    = 0;

    /* Table 21-15 (page 21-25) Reset row: YEAR 2000, MONTH 1, DOM 1. Table 21-14
       (page 21-24) Reset row: WOM 1, DOW 7, HOURS 0, MINUTES 0, SECONDS 0. */
    std::chrono::sys_seconds ww_base_ =
        std::chrono::sys_days{std::chrono::January / 1 / 2000};
    Clock::time_point ww_baseline_ = Clock::now();

    /* Section 21.4.2.3.1 (page 21-8): "When the write for RYCR is executed, the
       new data for RYCR is first written into an internal register. This new data
       is only written into the RYCR register when a write to the RDCR occurs." */
    uint32_t rycr_shadow_  = 0;
    bool     rycr_pending_ = false;
};

uint32_t Pxa27xRtc::ReadRtsrLocked() const {
    uint32_t s = rtsr_;
    const uint32_t now = ReadRcnrLocked();
    if ((rtsr_ & kRtsrALE) &&
        static_cast<int32_t>(alarm_armed_at_ - rtar_) < 0 &&
        static_cast<int32_t>(now - rtar_) >= 0) {
        s |= kRtsrAL;
    }
    /* Table 21-7 (page 21-19): "1 R/WC HZ HZ Rising Edge Detected ... 1 = A
       1-Hz rising edge has been detected and HZE is set." */
    if ((rtsr_ & kRtsrHZE) && now != hz_armed_at_) s |= kRtsrHZ;
    return s;
}

uint32_t Pxa27xRtc::ReadRdcrLocked() const {
    const auto now  = WristwatchLocked();
    const auto days = std::chrono::floor<std::chrono::days>(now);
    const std::chrono::hh_mm_ss hms{now - days};
    /* Table 21-14 (page 21-24): "19:17 R/W DOW Day of Week-1 (Sunday) through 7
       (Saturday)". */
    const uint32_t dow = std::chrono::weekday{days}.c_encoding() + 1u;
    /* Table 21-3 (page 21-7): "Week of month (WOM) 3 1 to 5". */
    const uint32_t dom = unsigned{std::chrono::year_month_day{days}.day()};
    const uint32_t wom = (dom - 1u) / 7u + 1u;
    return (wom << 20) | (dow << 17) |
           (static_cast<uint32_t>(hms.hours().count())   << 12) |
           (static_cast<uint32_t>(hms.minutes().count()) <<  6) |
            static_cast<uint32_t>(hms.seconds().count());
}

uint32_t Pxa27xRtc::ReadRycrLocked() const {
    const std::chrono::year_month_day ymd{
        std::chrono::floor<std::chrono::days>(WristwatchLocked())};
    return (static_cast<uint32_t>(int{ymd.year()}) << 9) |
           (static_cast<uint32_t>(unsigned{ymd.month()}) << 5) |
            static_cast<uint32_t>(unsigned{ymd.day()});
}

void Pxa27xRtc::CommitWristwatchLocked(uint32_t rdcr) {
    /* Section 21.4.2.3.1 (page 21-8): "Update the RDCR only and not the RYCR:
       Write the RDCR with new data-the RYCR (with current data) and the RDCR
       (with new data) is written." */
    const uint32_t rycr = rycr_pending_ ? rycr_shadow_ : ReadRycrLocked();
    rycr_pending_ = false;

    const std::chrono::year_month_day ymd{
        std::chrono::year {static_cast<int>((rycr >> 9) & 0xFFFu)},
        std::chrono::month{(rycr >> 5) & 0xFu},
        std::chrono::day  {rycr & 0x1Fu}};
    /* Section 21.4.2.3.2 (page 21-8): "Any attempt to write invalid or incorrect
       data to the counter registers results in unpredictable behavior." */
    if (!ymd.ok()) return;

    ww_base_ = std::chrono::sys_seconds{std::chrono::sys_days{ymd}} +
               std::chrono::hours  {static_cast<int>((rdcr >> 12) & 0x1Fu)} +
               std::chrono::minutes{static_cast<int>((rdcr >>  6) & 0x3Fu)} +
               std::chrono::seconds{static_cast<int>( rdcr        & 0x3Fu)};
    ww_baseline_ = Clock::now();
}

uint32_t Pxa27xRtc::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> g(mtx_);
    switch (addr - MmioBase()) {
        case 0x00: return ReadRcnrLocked();
        case 0x04: return rtar_;
        case 0x08: return ReadRtsrLocked();
        /* Section 21.5.1 (page 21-16): "Ignore reads from reserved bits." */
        case 0x0C: return rttr_ & kRttrMask;
        /* Section 21.5.9 (page 21-24): "RDCR ... reflects the current time in
           seconds, minutes, hours, day-of-the-week, and week-of-the-month."
           Section 21.5.10 (page 21-25): "RYCR ... contains the current time in
           the day-of-the-month, month, and year." */
        case 0x10: return ReadRdcrLocked() & kRdcrMask;
        case 0x14: return ReadRycrLocked() & kRycrMask;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xRtc::WriteWord(uint32_t addr, uint32_t value) {
    std::lock_guard<std::mutex> g(mtx_);
    switch (addr - MmioBase()) {
        /* Table 21-13 (page 21-24): "31:0 R/W RCV Count Value Current value of
           the RTC counter in seconds". */
        case 0x00:
            rcnr_base_      = value;
            baseline_       = Clock::now();
            alarm_armed_at_ = value;
            hz_armed_at_    = value;
            return;
        case 0x04:
            rtar_           = value;
            alarm_armed_at_ = ReadRcnrLocked();
            return;
        /* Section 21.5.2 (page 21-17): "The alarm-detect bits are reset by
           writing 0b1 to the bits to be cleared." */
        case 0x08: {
            const uint32_t now  = ReadRcnrLocked();
            const uint32_t prev = rtsr_;
            const uint32_t latched = ReadRtsrLocked() & kRtsrDetect;
            rtsr_ = (latched & ~value) | (value & kRtsrEnable);
            if ((value & kRtsrAL) || (~prev & rtsr_ & kRtsrALE)) {
                alarm_armed_at_ = now;
            }
            if ((value & kRtsrHZ) || (~prev & rtsr_ & kRtsrHZE)) {
                hz_armed_at_ = now;
            }
            return;
        }
        /* Section 21.5.1 (page 21-16): "The data in RTTR can be changed only if
           RTTR[LCK] is zero. Once RTTR[LCK] is set, only a hardware reset can
           clear the RTTR." */
        case 0x0C:
            if (!(rttr_ & kRttrLck)) rttr_ = value & kRttrMask;
            return;
        /* Section 21.4.2.3.1 (page 21-8): "The counter registers are updated only
           when there is a write to the RTC Day Counter register (RDCR)." */
        case 0x10:
            CommitWristwatchLocked(value & kRdcrMask);
            return;
        /* Section 21.4.2.3.1 (page 21-8): "When the write for RYCR is executed,
           the new data for RYCR is first written into an internal register." */
        case 0x14:
            rycr_shadow_  = value & kRycrMask;
            rycr_pending_ = true;
            return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xRtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> g(mtx_);
    const uint32_t live = ReadRcnrLocked();
    w.Write(live);
    w.Write(rtar_); w.Write(rtsr_); w.Write(rttr_);
    w.Write(alarm_armed_at_); w.Write(hz_armed_at_);
    const int64_t ww_live = WristwatchLocked().time_since_epoch().count();
    w.Write(ww_live);
    w.Write(rycr_shadow_); w.Write(rycr_pending_);
}

void Pxa27xRtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> g(mtx_);
    r.Read(rcnr_base_);
    baseline_ = Clock::now();
    r.Read(rtar_); r.Read(rtsr_); r.Read(rttr_);
    r.Read(alarm_armed_at_); r.Read(hz_armed_at_);
    int64_t ww_live = 0;
    r.Read(ww_live);
    ww_base_     = std::chrono::sys_seconds{std::chrono::seconds{ww_live}};
    ww_baseline_ = Clock::now();
    r.Read(rycr_shadow_); r.Read(rycr_pending_);
}

}  /* namespace */

REGISTER_SERVICE(Pxa27xRtc);
