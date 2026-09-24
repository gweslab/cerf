#include "ucb1x00_codec.h"

#include "ucb1x00_board.h"

#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Register indices, Linux ucb1x00.h; NetBSD ucb1200reg.h:37-52 agrees. */
constexpr uint8_t kRegIoData   = 0x00;
constexpr uint8_t kRegIeFal    = 0x03;   /* IE falling-edge enable */
constexpr uint8_t kRegIeStatus = 0x04;   /* IE status (read) / IE clear (write) */
constexpr uint8_t kRegTsCr     = 0x09;
constexpr uint8_t kRegAdcCr    = 0x0A;
constexpr uint8_t kRegAdcData  = 0x0B;
constexpr uint8_t kRegId       = 0x0C;
constexpr uint8_t kRegNull     = 0x0F;

/* NetBSD ucb1200reg.h:52 - the NULL register "always returns 0xffff". The Nino's
   sib.dll reads it to flush the subframe after tearing the SIB frame down. */
constexpr uint16_t kNullValue = 0xFFFFu;

/* The UCB's two touchscreen interrupt sources (ucb1x00.h UCB_IE_TSPX/TSMX). A
   driver arms pen-detect on whichever plate its panel monitors (Linux ucb1x00-ts
   uses TSPX, the Nino TSMX); CERF's binary pen state cannot tell them apart, so
   enabling either NEGINTEN falling-edge interrupt arms pen-detect. */
constexpr uint16_t kUcbIePenDetect = (1u << 12) | (1u << 13);

/* TS_CR MODE[9:8] and the pen-detect low flags (NetBSD ucb1200reg.h:132-140). */
constexpr uint16_t kTsCrModeMask = 3u << 8;
constexpr uint16_t kTsCrModePres = 1u << 8;
constexpr uint16_t kTsCrTspxLow  = 1u << 12;
constexpr uint16_t kTsCrTsmxLow  = 1u << 13;

/* ADC_CR / ADC_DATA (NetBSD ucb1200reg.h:185-219). */
constexpr uint16_t kAdcStart   = 1u << 7;
constexpr uint16_t kAdcDatVal  = 1u << 15;
constexpr uint16_t kAdcInpMask = 7u << 2;
constexpr uint16_t kAdcInpTspx = 0u << 2;   /* X-plate pin */
constexpr uint16_t kAdcInpTsmx = 1u << 2;
constexpr uint16_t kAdcInpTspy = 2u << 2;   /* Y-plate pin */
constexpr uint16_t kAdcInpTsmy = 3u << 2;
constexpr uint16_t kAdcInpAd0  = 4u << 2;

constexpr uint16_t kAdcDataShift = 5;
constexpr uint16_t kAdcDataMask  = 0x3FFu;

}  /* namespace */

uint16_t Ucb1x00Codec::ReadReg(uint8_t reg) {
    auto& board = emu_.Get<Ucb1x00Board>();
    switch (reg & 0xFu) {
        case kRegIoData:   return board.IoData(regs_[kRegIoData]);
        case kRegIeStatus: return board.PenIrqStatus();
        case kRegTsCr:     return PenDetectTsCr();
        case kRegAdcData:  return adc_data_;
        case kRegId:       return DeviceId();
        case kRegNull:     return kNullValue;
        default:           return regs_[reg & 0xFu];
    }
}

/* The UCB nIRQ asserts while IE_STATUS holds a pending interrupt; CERF models the
   pen-detect source, latched into the board's PenIrqStatus. */
bool Ucb1x00Codec::IrqAsserted() {
    return emu_.Get<Ucb1x00Board>().PenIrqStatus() != 0u;
}

void Ucb1x00Codec::WriteReg(uint8_t reg, uint16_t value) {
    auto& board = emu_.Get<Ucb1x00Board>();
    regs_[reg & 0xFu] = value;

    if ((reg & 0xFu) == kRegAdcCr && (value & kAdcStart)) {
        Convert(value);
    } else if ((reg & 0xFu) == kRegIeFal) {
        board.SetPenIrqArmed(value & kUcbIePenDetect);
    } else if ((reg & 0xFu) == kRegIeStatus) {
        board.ClearPenIrq(value);
    }
}

/* TSPX/TSMX read low while the panel shorts the plates, which is how a driver
   polling TS_CR in interrupt mode sees the pen without starting a conversion. */
uint16_t Ucb1x00Codec::PenDetectTsCr() const {
    uint16_t v = regs_[kRegTsCr];
    if (emu_.Get<Ucb1x00Board>().TouchDown()) v |=  (kTsCrTspxLow | kTsCrTsmxLow);
    else                                      v &= ~(kTsCrTspxLow | kTsCrTsmxLow);
    return v;
}

void Ucb1x00Codec::Convert(uint16_t adc_cr) {
    auto& board = emu_.Get<Ucb1x00Board>();
    const uint16_t mode = regs_[kRegTsCr] & kTsCrModeMask;
    const uint16_t chan = adc_cr & kAdcInpMask;

    /* Reading a floating Y-plate pin (TSPY/TSMY) taps the X gradient, an X-plate
       pin (TSPX/TSMX) the Y gradient (4-wire resistive; ucb1x00.h ADC INP). The
       Nino reads position through the M pins (sib.dll sub_18D1DB4: X=TSMY, Y=TSMX),
       the SIMpad through the P pins. */
    uint16_t s;
    if (chan >= kAdcInpAd0)         s = board.AuxAdc(static_cast<uint8_t>((chan >> 2) - 4u));
    else if (mode == kTsCrModePres) s = board.TouchAdcPressure();
    else if (chan == kAdcInpTspy || chan == kAdcInpTsmy) s = board.TouchAdcX();
    else                                                 s = board.TouchAdcY();

    adc_data_ = static_cast<uint16_t>(kAdcDatVal | ((s & kAdcDataMask) << kAdcDataShift));
}

void Ucb1x00Codec::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_.data(), sizeof(uint16_t) * regs_.size());
    w.Write("adc_data", adc_data_);
}

void Ucb1x00Codec::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_.data(), sizeof(uint16_t) * regs_.size());
    r.Read("adc_data", adc_data_);
}

/* The board's pen_irq_armed_ is computed from a NEGINTEN write; RestoreState
   reloads regs_ but does not replay that write, so the pen IRQ would stay disarmed
   and touch would be dead after a restore. Re-derive it (hibernation.md). */
void Ucb1x00Codec::PostRestore() {
    emu_.Get<Ucb1x00Board>().SetPenIrqArmed(regs_[kRegIeFal] & kUcbIePenDetect);
}
