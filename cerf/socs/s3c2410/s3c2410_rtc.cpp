#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_detector.h"

#include <cstdint>
#include <ctime>
#include <mutex>

namespace {

/* BCDDATE = day-of-week 1..7, not BCD-encoded day-of-month despite the
   name. BCD* writes are dropped (no host time-set propagation). */

class S3C2410Rtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x57000000u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static uint32_t ToBcd(uint32_t v) {
        return ((v / 10u) << 4) | (v % 10u);
    }

    static uint32_t HostBcdField(uint32_t off);

    mutable std::mutex state_mutex_;
    uint32_t rtccon_ = 0, ticint_ = 0;
    uint32_t rtcalm_ = 0;
    uint32_t almsec_ = 0, almmin_ = 0, almhour_ = 0;
    uint32_t almdate_ = 0, almmon_ = 0, almyear_ = 0;
    uint32_t rtcrst_ = 0;
};

uint32_t S3C2410Rtc::HostBcdField(uint32_t off) {
    std::time_t t = std::time(nullptr);
    std::tm lt{};
    localtime_s(&lt, &t);
    switch (off) {
        case 0x70u: return ToBcd(static_cast<uint32_t>(lt.tm_sec));
        case 0x74u: return ToBcd(static_cast<uint32_t>(lt.tm_min));
        case 0x78u: return ToBcd(static_cast<uint32_t>(lt.tm_hour));
        case 0x7Cu: return ToBcd(static_cast<uint32_t>(lt.tm_mday));
        case 0x80u: return static_cast<uint32_t>(lt.tm_wday) + 1u;
        case 0x84u: return ToBcd(static_cast<uint32_t>(lt.tm_mon + 1));
        case 0x88u: return ToBcd(static_cast<uint32_t>(lt.tm_year - 100));
    }
    return 0;
}

uint32_t S3C2410Rtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t value = 0;

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case 0x40u: value = rtccon_;  break;
            case 0x44u: value = ticint_;  break;
            case 0x50u: value = rtcalm_;  break;
            case 0x54u: value = almsec_;  break;
            case 0x58u: value = almmin_;  break;
            case 0x5Cu: value = almhour_; break;
            case 0x60u: value = almdate_; break;
            case 0x64u: value = almmon_;  break;
            case 0x68u: value = almyear_; break;
            case 0x6Cu: value = rtcrst_;  break;
            case 0x70u: case 0x74u: case 0x78u:
            case 0x7Cu: case 0x80u: case 0x84u: case 0x88u:
                value = HostBcdField(off);
                break;
            default:
                HaltUnsupportedAccess("ReadWord", addr, 0);  /* noreturn */
        }
    }

    return value;
}

void S3C2410Rtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case 0x40u: rtccon_  = value; break;
            case 0x44u: ticint_  = value; break;
            case 0x50u: rtcalm_  = value; break;
            case 0x54u: almsec_  = value; break;
            case 0x58u: almmin_  = value; break;
            case 0x5Cu: almhour_ = value; break;
            case 0x60u: almdate_ = value; break;
            case 0x64u: almmon_  = value; break;
            case 0x68u: almyear_ = value; break;
            case 0x6Cu: rtcrst_  = value; break;
            case 0x70u: case 0x74u: case 0x78u:
            case 0x7Cu: case 0x80u: case 0x84u: case 0x88u:
                break;
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);  /* noreturn */
        }
    }
}

}  /* namespace */

REGISTER_SERVICE(S3C2410Rtc);
