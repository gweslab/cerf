#include "wm9713_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/symbol_mk500/symbol_mk500_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"

namespace {

/* symbol_mk500 touch.dll FUN_02236e30 @0x02236e30 requires reg 0x7C == 0x574D
   and reg 0x7E == 0x4C13, then decodes reg 0x5A & 0x1C as the revision index
   (0 -> 'A', 4 -> 'B', 8 -> 'C'). */
constexpr uint32_t kRegRevision  = 0x5Au;
constexpr uint32_t kRegVendorId1 = 0x7Cu;
constexpr uint32_t kRegVendorId2 = 0x7Eu;
constexpr uint16_t kWm97xxId1    = 0x574Du;
constexpr uint16_t kWm9713Id2    = 0x4C13u;
constexpr uint16_t kRevisionC    = 0x0008u;

/* Cirrus Logic WM9713L Rev 4.0 Table 68 (page 91): 74h POLL 9, CTC 8, ADCSEL 7:1, COO 0; 76h CR 9:8,
   DEL 7:4, SLEN 3, SLT 2:0; 78h PRP 15:14, PDEN 11, WAIT 9, MSK 7:6; Table 47 (page 70): 3Ch PADCPD
   bit 15, "The pen ADC is powered-down using PADCPD". */
constexpr uint32_t kRegDigitiser1  = 0x74u;
constexpr uint32_t kRegDigitiser2  = 0x76u;
constexpr uint32_t kRegDigitiserRd = 0x7Au;
constexpr uint16_t kPoll = 1u << 9, kCtc = 1u << 8, kSelMask = 0x00FEu, kCoo = 1u << 0;
constexpr uint16_t kSlen = 1u << 3;
constexpr uint16_t kPden = 1u << 11, kWait = 1u << 9, kMskMask = 0x00C0u;
constexpr uint16_t kPadcpd = 1u << 15;
/* Cirrus Logic WM9713L Rev 4.0 Table 48 (page 71): CR 00 every 512, 01 every 400, 10 every 312, 11
   every 256 AC-Link frames; Table 50 (page 73): ADCSRC 001 X, 010 Y. */
constexpr uint32_t kCrFrames[4] = {512u, 400u, 312u, 256u};
constexpr uint8_t  kSrcX = 1u, kSrcY = 2u;
constexpr uint16_t kSelXy = (1u << kSrcX) | (1u << kSrcY);

struct RegDefault {
    uint8_t  reg;
    uint16_t value;
};

/* Cirrus Logic WM9713L Rev 4.0 Table 68 "WM9713L Register Map" (page 91),
   Default column. */
constexpr RegDefault kDefaults[] = {
    {0x00, 0x6174}, {0x02, 0x8080}, {0x04, 0x8080}, {0x06, 0x8080}, {0x08, 0xC880},
    {0x0A, 0xE808}, {0x0C, 0xE808}, {0x0E, 0x0808}, {0x10, 0x00DA}, {0x12, 0x8000},
    {0x14, 0xD600}, {0x16, 0xAAA0}, {0x18, 0xAAA0}, {0x1A, 0xAAA0}, {0x1C, 0x0000},
    {0x1E, 0x0000}, {0x20, 0x0F0F}, {0x22, 0x0040}, {0x24, 0x0000}, {0x26, 0x7F00},
    {0x28, 0x0405}, {0x2A, 0x0410}, {0x2C, 0xBB80}, {0x2E, 0xBB80}, {0x32, 0xBB80},
    {0x36, 0x4523}, {0x3A, 0x2000}, {0x3C, 0xFDFF}, {0x3E, 0xFFFF}, {0x40, 0x0000},
    {0x42, 0x0000}, {0x44, 0x0080}, {0x46, 0x0000}, {0x4C, 0xFFFE}, {0x4E, 0xFFFF},
    {0x50, 0x0000}, {0x52, 0x0000}, {0x56, 0xFFFE}, {0x58, 0x4000}, {0x5A, 0x0000},
    {0x5C, 0x0000}, {0x60, 0xB032}, {0x62, 0x3E00}, {0x64, 0x0000}, {0x74, 0x0000},
    {0x76, 0x0006}, {0x78, 0x0001}, {0x7A, 0x0000},
    {kRegVendorId1, kWm97xxId1}, {kRegVendorId2, kWm9713Id2},
};

/* Cirrus Logic WM9713L Rev 4.0 Table 65 (page 87): register 3Ch bit 7 DACL, bit 6
   DACR, bit 5 ADCL, bit 4 ADCR, "1 = Disabled". */
constexpr uint32_t kRegPowerdown1 = 0x3Cu;
constexpr uint16_t kDacl = 1u << 7;
constexpr uint16_t kDacr = 1u << 6;
constexpr uint16_t kAdcl = 1u << 5;
constexpr uint16_t kAdcr = 1u << 4;
constexpr uint32_t kRegAddFunc2 = 0x5Cu;
constexpr uint16_t kAssMask     = 0x0003u;

/* Cirrus Logic WM9713L Rev 4.0 Table 68 (page 91): 40h LB bit 7 (Figure 9, page 19: "40h:7
   (Loopback)" between the AC'97 link and the DACs), 2Ah SEN bit 2. */
constexpr uint32_t kRegGeneral = 0x40u;
constexpr uint16_t kLb         = 1u << 7;
constexpr uint16_t kSen        = 1u << 2;
/* Cirrus Logic WM9713L Rev 4.0 Table 3 (page 22): 44h SEXT[6:4] 14:12 hi-fi block clock division,
   CLKSRC 7 (1 = external clock), CLKAX2 1, CLKMUX 0; page 21: "AC97 CLK - nominally 24.576MHz,
   used to generate AC97 BITCLK at 12.288MHz". */
constexpr uint32_t kRegClockCtrl   = 0x44u;
constexpr uint16_t kHifiDivMask    = 0x7000u;
constexpr uint16_t kClkPathMask    = 0x0083u;
constexpr uint16_t kClkPathDefault = 0x0080u;
/* Cirrus Logic WM9713L Rev 4.0 Table 21 (page 44): 2Ch, 32h and 2Eh rates 1F40h, 2B11h, 2EE0h, 3E80h,
   5622h, 5DC0h, 7D00h, AC44h, BB80h. */
constexpr uint32_t kRegAuxDacRate = 0x2Eu;
constexpr uint16_t kRates[] = {8000u, 11025u, 12000u, 16000u, 22050u, 24000u, 32000u, 44100u, 48000u};
/* Cirrus Logic WM9713L Rev 4.0 Table 65 (page 87): 3Ch AUXDAC bit 11, "1 = Disabled". */
constexpr uint16_t kAuxdac = 1u << 11;

/* Cirrus Logic WM9713L Rev 4.0 Table 62 (page 84): 4Eh GPn polarity (1 = active high), 50h GSn sticky;
   Table 61 (page 83): GPIO bit 13 "Internal PENDOWN Signal enabled only when pen-down detection is
   active". */
constexpr uint32_t kRegGpioPolarity = 0x4Eu;
constexpr uint32_t kRegGpioSticky   = 0x50u;
constexpr uint32_t kRegGpioStatus   = 0x54u;
constexpr uint16_t kGpioPenDown     = 1u << 13;

}  // namespace

bool Wm9713Codec::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::SymbolMk500;
}

void Wm9713Codec::OnReady() {
    Wm97xxCodec::OnReady();
    ColdReset();
}

void Wm9713Codec::ColdReset() {
    ResetRegisters();
    digitiser_.Clear(pen_down_);
}

void Wm9713Codec::ResetRegisters() {
    stalled_poll_ = false;
    for (uint16_t& r : reg_) r = 0u;
    for (const RegDefault& d : kDefaults) reg_[d.reg] = d.value;
    /* symbol_mk500 touch.dll FUN_022381a0 @0x022381a0 applies the reg 0x5C and
       reg 0x68 errata writes only for revision index 0. */
    reg_[kRegRevision] = kRevisionC;
    ResetRates();
}

const uint16_t* Wm9713Codec::SupportedRates(uint32_t& count) const {
    count = static_cast<uint32_t>(sizeof(kRates) / sizeof(kRates[0]));
    return kRates;
}

bool Wm9713Codec::IsRateRegister(uint32_t reg) const {
    return reg == kRegAuxDacRate || Ac97Codec::IsRateRegister(reg);
}

/* Cirrus Logic WM9713L Rev 4.0 Table 21 note (page 44): a rate change "will only be effective if the ADCs and
   DACs are enabled and powered up before the sample rate is changed". */
bool Wm9713Codec::RateWriteTakesEffect(uint32_t reg) {
    if (reg == kRegDacRate) return DacPowered();
    if (reg == kRegAdcRate) return AdcPowered();
    return (reg_[kRegPowerdown] & kPr3) == 0u && (reg_[kRegPowerdown1] & kAuxdac) == 0u;
}

void Wm9713Codec::RequireRegister(uint32_t reg) {
    if (reg >= kNumRegs) emu_.Get<Fatal>().Die("Wm9713Codec: codec register index 0x%X out of range", reg);
}

uint16_t Wm9713Codec::Peek(uint32_t reg) {
    RequireRegister(reg);
    return reg_[reg];
}

void Wm9713Codec::Poke(uint32_t reg, uint16_t value) {
    RequireRegister(reg);
    reg_[reg] = value;
}

/* WM9713L Rev 4.0 page 86: a block "is active when both the relevant bit in register 26h AND
   the relevant bit in the Powerdown registers 3Ch and 3Eh are set to '0'"; Table 64 PR3
   "disables VREF, input PGAs, DACs, ADCs, mixers and outputs". */
bool Wm9713Codec::PrClear(uint16_t pr_bit) const {
    return (reg_[kRegPowerdown] & (pr_bit | kPr3)) == 0u;
}

bool Wm9713Codec::DacPowered() {
    const uint16_t pd = reg_[kRegPowerdown1];
    const bool     l = (pd & kDacl) == 0u, r = (pd & kDacr) == 0u;
    if (l != r) {
        emu_.Get<Fatal>().Die("Wm9713Codec: register 3Ch 0x%04X powers one DAC channel; not modelled", pd);
    }
    const bool on = PrClear(kPr1) && l;
    if (on && ((reg_[kRegGeneral] & kLb) != 0u || (reg_[kRegExtAudioCtrl] & kSen) != 0u ||
               (reg_[kRegClockCtrl] & kHifiDivMask) != 0u)) {
        emu_.Get<Fatal>().Die("Wm9713Codec: DAC on with 40h 0x%04X, 2Ah 0x%04X, 44h 0x%04X (loopback, "
                              "S/PDIF output or a divided hi-fi clock); not modelled", reg_[kRegGeneral],
                              reg_[kRegExtAudioCtrl], reg_[kRegClockCtrl]);
    }
    return on;
}

/* WM9713L Rev 4.0 page 32: "If only one ADC is running, the same ADC data appears on both the left
   and right AC-Link slots"; Table 10: register 5Ch ASS 00 puts the ADC data on slots 3 and 4. */
bool Wm9713Codec::AdcPowered() {
    const bool on = (reg_[kRegPowerdown1] & (kAdcl | kAdcr)) != (kAdcl | kAdcr);
    if (on && (reg_[kRegAddFunc2] & kAssMask) != 0u) {
        emu_.Get<Fatal>().Die("Wm9713Codec: register 5Ch 0x%04X moves the ADC data off slots 3 and 4; "
                              "not modelled", reg_[kRegAddFunc2]);
    }
    const bool powered = PrClear(kPr0) && on;
    if (powered && (reg_[kRegClockCtrl] & kHifiDivMask) != 0u) {
        emu_.Get<Fatal>().Die("Wm9713Codec: ADC on with 44h 0x%04X dividing the hi-fi clock; not modelled",
                              reg_[kRegClockCtrl]);
    }
    return powered;
}

/* Cirrus Logic WM9713L Rev 4.0 Figure 35 (page 83): a GPIO status bit is the signal XNOR its polarity
   4Eh.n, held in a set-reset latch when 50h.n is set. */
uint16_t Wm9713Codec::GpioSlotStatus(uint64_t frame) {
    if ((reg_[kRegGpioSticky] & kGpioPenDown) != 0u) {
        emu_.Get<Fatal>().Die("Wm9713Codec: register 50h 0x%04X makes the pen-down GPIO sticky; not modelled",
                              reg_[kRegGpioSticky]);
    }
    if ((reg_[kRegDigitiserPower] >> 14) == 0u) return 0u;
    const bool active_high = (reg_[kRegGpioPolarity] & kGpioPenDown) != 0u;
    return digitiser_.PenDownAt(frame) == active_high ? kGpioPenDown : 0u;
}

uint16_t Wm9713Codec::ReadReg(uint32_t reg, uint64_t frame) {
    switch (reg) {
    case kRegGpioStatus:  return GpioSlotStatus(frame);
    case kRegDigitiser1:
        return static_cast<uint16_t>((reg_[reg] & ~kPoll) |
                                     (stalled_poll_ || digitiser_.Polling(frame) ? kPoll : 0u));
    case kRegDigitiserRd: return LastResultWord(frame, reg_[kRegDigitiserRd]);
    default:              return ReadStored(reg);
    }
}

void Wm9713Codec::WriteReg(uint32_t reg, uint16_t value, uint64_t frame) {
    RequireRegister(reg);
    /* WM9713L Rev 4.0 page 92: "Writing any value to this register resets all registers to
       their default, but does not change the contents of reg. 00h." */
    if (reg == kRegReset) {
        ResetRegisters();
        Reconfigure(frame, false);
        return;
    }
    if (reg == kRegClockCtrl && (value & kClkPathMask) != kClkPathDefault) {
        emu_.Get<Fatal>().Die("Wm9713Codec: register 44h 0x%04X changes the AC97 CLK that generates BITCLK; "
                              "not modelled", value);
    }
    if (reg == kRegDigitiserRd) {
        emu_.Get<Fatal>().Die("Wm9713Codec: write 0x%04X to the read-only register 7Ah", value);
    }
    if (WriteRateRegister(reg, value)) return;
    reg_[reg] = value;
    if (reg == kRegExtAudioCtrl) OnExtAudioCtrlWrite();
    if (reg == kRegDigitiser1) {
        stalled_poll_ = false;
        LOG(Periph, "[WM9713] DIG1=0x%04X sel=0x%02X%s%s\n", value, value & kSelMask,
            (value & kCtc) ? " CTC" : "", (value & kPoll) ? " POLL" : "");
    }
    if (reg == kRegDigitiser1 || reg == kRegDigitiser2 || reg == kRegDigitiserPower || reg == kRegPowerdown1) {
        Reconfigure(frame, reg == kRegDigitiser1 && (value & kPoll) != 0u);
    }
}

/* Cirrus Logic WM9713L Rev 4.0 Table 48 (page 71) PDEN: "when CTC=1, measurements are stopped on
   pen-up"; page 72: "If CTC=0 (polling mode) then only one of the ADCSEL[7:1] bits should be set",
   and in continuous mode the selected conversions run "in the following order: X, Y, PRESSURE". */
void Wm9713Codec::Reconfigure(uint64_t frame, bool poll) {
    const uint16_t d74 = reg_[kRegDigitiser1];
    const uint16_t d76 = reg_[kRegDigitiser2];
    const uint16_t d78 = reg_[kRegDigitiserPower];
    if ((d78 & (kWait | kMskMask)) != 0u) {
        emu_.Get<Fatal>().Die("Wm9713Codec: register 78h 0x%04X sets WAIT or MSK; not modelled", d78);
    }
    const bool powered = DigitiserPowered() && (reg_[kRegPowerdown1] & kPadcpd) == 0u;
    if ((d76 & kSlen) != 0u && (d76 & 7u) != 0u) {
        emu_.Get<Fatal>().Die("Wm9713Codec: register 76h 0x%04X routes digitiser data to slot %u; not modelled",
                              d76, 5u + (d76 & 7u));
    }
    Wm97xxDigitiser::Sequence seq;
    seq.to_slot = (d76 & kSlen) != 0u;
    for (uint8_t b = 1u; b <= 7u; ++b) {
        if ((d74 & (1u << b)) != 0u) seq.tags[seq.count++] = b;
    }
    /* Cirrus Logic WM9713L Rev 4.0 page 70: POLL "automatically resets itself when the measurement is
       completed"; Table 47: PRP 01 "Pen digitiser powered off". */
    if (poll || (stalled_poll_ && powered)) {
        if ((d74 & (kCtc | kCoo)) != 0u || seq.count == 0u || ((d78 & kPden) != 0u && !pen_down_)) {
            emu_.Get<Fatal>().Die("Wm9713Codec: polled conversion with 74h 0x%04X, 78h 0x%04X, 3Ch 0x%04X; "
                                  "not modelled", d74, d78, reg_[kRegPowerdown1]);
        }
        stalled_poll_ = !powered;
        if (!powered) {
            digitiser_.SetContinuous(frame, nullptr);
            return;
        }
        seq.delay = DelayFrames((d76 >> 4) & 0xFu, d76);
        digitiser_.StartPolled(frame, seq, seq.count > 1u);
        return;
    }
    if ((d74 & kCtc) == 0u || !powered) {
        digitiser_.SetContinuous(frame, nullptr);
        return;
    }
    if ((d74 & kCoo) != 0u || seq.count == 0u || (d74 & kSelMask & ~kSelXy) != 0u) {
        emu_.Get<Fatal>().Die("Wm9713Codec: continuous conversion with 74h 0x%04X other than X and Y; "
                              "not modelled", d74);
    }
    seq.delay     = DelayFrames((d76 >> 4) & 0xFu, d76);
    seq.period    = kCrFrames[(d76 >> 8) & 3u];
    seq.pen_gated = (d78 & kPden) != 0u;
    digitiser_.SetContinuous(frame, &seq);
}

uint16_t Wm9713Codec::ConversionData(uint8_t tag) {
    switch (tag) {
    case kSrcX: return RawX();
    case kSrcY: return RawY();
    default:
        emu_.Get<Fatal>().Die("Wm9713Codec: conversion of ADC source %u; not modelled", tag);
    }
}

void Wm9713Codec::SaveState(StateWriter& w) {
    w.WriteBytes("reg", reg_, sizeof(reg_));
    w.Write<uint8_t>("stalled_poll", stalled_poll_ ? 1u : 0u);
    SaveRates(w);
    SavePen(w);
}

void Wm9713Codec::RestoreState(StateReader& r) {
    uint8_t stalled = 0;
    r.ReadBytes("reg", reg_, sizeof(reg_));
    r.Read("stalled_poll", stalled);
    stalled_poll_ = stalled != 0u;
    RestoreRates(r);
    RestorePen(r);
}

REGISTER_SERVICE_AS(Wm9713Codec, Ac97Codec);
