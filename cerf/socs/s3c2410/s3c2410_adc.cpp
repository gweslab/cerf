#include "s3c2410_adc.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"
#include "s3c2410_touch_calibration.h"

namespace {

constexpr uint32_t kBase = 0x58000000u;
constexpr uint32_t kSpan = 0x14u;

constexpr uint32_t kOffCon  = 0x00u;
constexpr uint32_t kOffTsc  = 0x04u;
constexpr uint32_t kOffDly  = 0x08u;
constexpr uint32_t kOffDat0 = 0x0Cu;
constexpr uint32_t kOffDat1 = 0x10u;

/* UM p. 16-7 ADCCON: [15] ECFLG read only, [14] PRSCEN, [13:6] PRSCVL,
   [5:3] SEL_MUX, [2] STDBM, [1] READ_START, [0] ENABLE_START. */
constexpr uint32_t kConEcflg       = 1u << 15;
constexpr uint32_t kConWritable    = 0x7FFFu;
constexpr uint32_t kConStdbm       = 1u << 2;
constexpr uint32_t kConReadStart   = 1u << 1;
constexpr uint32_t kConEnableStart = 1u << 0;

/* UM p. 16-8 ADCTSC: [8] Reserved, [7] YM_SEN, [6] YP_SEN, [5] XM_SEN,
   [4] XP_SEN, [3] PULL_UP, [2] AUTO_PST, [1:0] XY_PST. */
constexpr uint32_t kTscWritable  = 0x1FFu;
/* Linux drivers/input/touchscreen/s3c2410_ts.c INT_DOWN 0 / INT_UP (1 << 8),
   written as WAIT4INT|INT_DOWN 0xD3 and WAIT4INT|INT_UP 0x1D3. */
constexpr uint32_t kTscUdSen     = 1u << 8;
constexpr uint32_t kTscAutoPst   = 1u << 2;
constexpr uint32_t kTscXyPstMask = 0x3u;
constexpr uint32_t kXyPstNoOperation = 0u;
constexpr uint32_t kXyPstWaitForInt  = 3u;

/* UM p. 16-9 ADCDLY: DELAY [15:0]. */
constexpr uint32_t kDlyWritable = 0xFFFFu;

/* UM p. 16-10 ADCDAT0 / p. 16-11 ADCDAT1: [15] UPDOWN, [14] AUTO_PST,
   [13:12] XY_PST, [11:10] Reserved, [9:0] XPDATA / YPDATA 0 ~ 3FF. */
constexpr uint32_t kDatUpDown     = 1u << 15;
constexpr uint32_t kDatAutoPst    = 1u << 14;
constexpr uint32_t kDatXyPstShift = 12;
constexpr uint32_t kDatValueMask  = 0x3FFu;

/* UM p. 14-7 SRCPND INT_ADC [31]; p. 14-18 INTSUBMSK INT_ADC [10],
   INT_TC [9]. */
constexpr int kMainSourceAdc = 31;
constexpr int kSubSourceTc   = 9;
constexpr int kSubSourceAdc  = 10;

}  /* namespace */

bool S3C2410Adc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::S3c2410;
}

void S3C2410Adc::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    emu_.Get<S3C2410SubSourceLevels>().Register(kMainSourceAdc, kSubSourceTc,
                                                this);
}

bool S3C2410Adc::SubSourceAsserted(int sub_source_bit) {
    if (sub_source_bit != kSubSourceTc) return false;
    std::lock_guard<std::mutex> lk(state_mutex_);
    return PenInterruptAssertedLocked();
}

uint32_t S3C2410Adc::MmioBase() const { return kBase; }
uint32_t S3C2410Adc::MmioSize() const { return kSpan; }

uint32_t S3C2410Adc::ComposeDataLocked(uint32_t data) const {
    uint32_t v = data & kDatValueMask;
    if (!pen_down_) v |= kDatUpDown;
    if (tsc_ & kTscAutoPst) v |= kDatAutoPst;
    v |= (tsc_ & kTscXyPstMask) << kDatXyPstShift;
    return v;
}

/* UM p. 16-5 "Auto (Sequential) X/Y Position Conversion Mode (AUTO_PST = 1
   and XY_PST = 0) ... writes X-measurement data to XPDATA of ADCDAT0, and
   then writes Y-measurement data to YPDATA of ADCDAT1". */
void S3C2410Adc::ConvertLocked() {
    const uint32_t xy_pst = tsc_ & kTscXyPstMask;
    if (!(tsc_ & kTscAutoPst) || xy_pst != kXyPstNoOperation) {
        emu_.Get<Fatal>().Die(
            "S3C2410 ADC: conversion started with ADCTSC 0x%03X - only Auto "
            "(Sequential) X/Y Position Conversion Mode is implemented",
            tsc_);
    }

    auto* calibration = emu_.TryGet<S3C2410TouchCalibration>();
    if (!calibration) {
        emu_.Get<Fatal>().Die(
            "S3C2410 ADC: Auto (Sequential) X/Y Position Conversion started on "
            "a board that registers no S3C2410TouchCalibration");
    }

    uint16_t x = pen_x_;
    uint16_t y = pen_y_;
    if (calibration->AxisSwap()) {
        const uint16_t t = x;
        x = y;
        y = t;
    }
    x_data_ = x & kDatValueMask;
    y_data_ = y & kDatValueMask;
    ecflg_  = true;
}

/* UM p. 16-5 "When Touch Screen Controller is in Waiting for Interrupt Mode,
   it waits for Stylus down. The controller generates Interrupt (INT_TC)
   signals when the Stylus is down on Touch Screen Panel." UM p. 16-8 ADCTSC
   XY_PST 11 = "Waiting for Interrupt Mode". */
bool S3C2410Adc::PenInterruptAssertedLocked() const {
    if ((tsc_ & kTscXyPstMask) != kXyPstWaitForInt) return false;
    const bool reports_stylus_down = (tsc_ & kTscUdSen) == 0;
    return pen_down_ == reports_stylus_down;
}

uint32_t S3C2410Adc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
        case kOffCon:  return con_ | (ecflg_ ? kConEcflg : 0u);
        case kOffTsc:  return tsc_;
        case kOffDly:  return dly_;
        case kOffDat0: return ComposeDataLocked(x_data_);
        case kOffDat1: return ComposeDataLocked(y_data_);
        default:
            HaltUnsupportedAccess("ReadWord", addr, 0);
    }
}

void S3C2410Adc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    bool converted   = false;
    bool raise_touch = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case kOffCon: {
                const uint32_t v = value & kConWritable;
                if (v & kConReadStart) {
                    emu_.Get<Fatal>().Die(
                        "S3C2410 ADC: ADCCON 0x%04X sets READ_START - A/D "
                        "conversion start by read is unimplemented", v);
                }
                /* UM p. 16-7 ENABLE_START: "A/D conversion starts and this
                   bit is cleared after the start-up". */
                con_ = v & ~kConEnableStart;
                if (v & kConEnableStart) {
                    /* UM p. 16-5 Standby Mode: "A/D conversion operation is
                       halted" while STDBM is 1. */
                    if (con_ & kConStdbm) {
                        emu_.Get<Fatal>().Die(
                            "S3C2410 ADC: conversion started with ADCCON "
                            "0x%04X STDBM set", con_);
                    }
                    ecflg_ = false;
                    ConvertLocked();
                    converted = true;
                }
                break;
            }
            case kOffTsc:
                tsc_        = value & kTscWritable;
                raise_touch = PenInterruptAssertedLocked();
                break;
            case kOffDly:
                dly_ = value & kDlyWritable;
                break;
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);
        }
    }
    if (raise_touch)
        emu_.Get<IrqController>().AssertSubIrq(kMainSourceAdc, kSubSourceTc);
    /* UM p. 16-5: after Auto (Sequential) Position Conversion "the Touch
       Screen Controller generates Interrupt source (INT_ADC)". */
    if (converted)
        emu_.Get<IrqController>().AssertSubIrq(kMainSourceAdc, kSubSourceAdc);
}

void S3C2410Adc::SetPen(bool down, uint16_t sample_x, uint16_t sample_y) {
    auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
    bool raise_touch = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        pen_down_   = down;
        pen_x_      = sample_x;
        pen_y_      = sample_y;
        raise_touch = PenInterruptAssertedLocked();
    }
    if (raise_touch)
        emu_.Get<IrqController>().AssertSubIrq(kMainSourceAdc, kSubSourceTc);
}

void S3C2410Adc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.Write<uint32_t>("con", con_);
    w.Write<uint32_t>("tsc", tsc_);
    w.Write<uint32_t>("dly", dly_);
    w.Write<uint32_t>("ecflg", ecflg_ ? 1u : 0u);
    w.Write<uint32_t>("pen_down", pen_down_ ? 1u : 0u);
    w.Write("pen_x", pen_x_);
    w.Write("pen_y", pen_y_);
    w.Write<uint32_t>("x_data", x_data_);
    w.Write<uint32_t>("y_data", y_data_);
}

void S3C2410Adc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    uint32_t v = 0;
    r.Read("con", con_);
    r.Read("tsc", tsc_);
    r.Read("dly", dly_);
    r.Read("ecflg", v); ecflg_ = (v != 0);
    r.Read("pen_down", v); pen_down_ = false;
    r.Read("pen_x", pen_x_);
    r.Read("pen_y", pen_y_);
    r.Read("x_data", x_data_);
    r.Read("y_data", y_data_);
}

void S3C2410Adc::PostRestore() {
    bool raise_touch = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        raise_touch = PenInterruptAssertedLocked();
    }
    if (raise_touch)
        emu_.Get<IrqController>().AssertSubIrq(kMainSourceAdc, kSubSourceTc);
}

REGISTER_SERVICE(S3C2410Adc);
