#include "wm9705_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/falcon_pc3xx/falcon_4220_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"

namespace {
/* falcon_4220__4_10 touch.dll sub_18E1CE8 requires register 7Ch = 574Dh and 7Eh = 4C05h (WM9705) or
   4C12h before it enables the touch screen. */
constexpr uint32_t kRegVendorId1 = 0x7Cu;
constexpr uint32_t kRegVendorId2 = 0x7Eu;
constexpr uint16_t kWm97xxId1    = 0x574Du;
constexpr uint16_t kWm9705Id2    = 0x4C05u;

/* Wolfson WM9705 page 41 (index 76h): POLL 15, ADR 14:12, COO 11, CTC 10, CR 9:8, DEL 7:4, SLEN 3, SLT
   2:0; page 42 (index 78h): PRP 15:14 (11 = powered up, 01 = wakeup on pen down), PDEN 12, WAIT 8,
   MSK 5:4. */
constexpr uint32_t kRegDigitiser1  = 0x76u;
constexpr uint32_t kRegDigitiserRd = 0x7Au;
constexpr uint16_t kPoll = 1u << 15, kCoo = 1u << 11, kCtc = 1u << 10, kSlen = 1u << 3;
constexpr uint16_t kPden = 1u << 12, kWait = 1u << 8, kMskMask = 0x0030u;
/* Wolfson WM9705 Table 24 (page 43): ADR 001 X-plate, 010 Y-plate, 101 AUXADC; Table 26 (page 46): CR
   00 512, 01 256, 10 128, 11 64 AC link frames. */
constexpr uint8_t  kAdrX = 1u, kAdrY = 2u, kAdrAuxAdc = 5u;
constexpr uint32_t kCrFrames[4] = {512u, 256u, 128u, 64u};
/* falcon_4220__4_10 battdrvr.dll sub_17F1C9C converts this AUXADC result to 3300 * adc / 4096 mV;
   sub_17F1668 reports the backup battery from it, 100 percent at 3100 mV and above. */
constexpr uint16_t kAuxAdcValue = 0x0FFFu;

/* Wolfson WM9705 Table 23 note 2 (page 39): "Register 5Ah is write only. When writing to this register
   all bits except MPM (bit 4) must be written as 0"; falcon_4220__4_10 touch.dll sub_18E1CE8 sets 78h
   |= C000h only when its 5Ah read & 0x60 is 0x20. */
constexpr uint32_t kRegMixerMute  = 0x5Au;
constexpr uint16_t kMixerMuteRead = 0x0020u;

struct RegDefault {
    uint8_t  reg;
    uint16_t value;
};

/* Wolfson WM9705 Production Data Rev 4.5 Table 23 "Serial Interface Register
   Map Description" (page 39), Default column. */
constexpr RegDefault kDefaults[] = {
    {0x00, 0x6150}, {0x02, 0x8000}, {0x04, 0x8000}, {0x06, 0x8000}, {0x0A, 0x8000},
    {0x0C, 0x8008}, {0x0E, 0x8008}, {0x10, 0x8808}, {0x12, 0x8808}, {0x14, 0x8808},
    {0x16, 0x8808}, {0x18, 0x8808}, {0x1A, 0x0000}, {0x1C, 0x8000}, {0x20, 0x0000},
    {0x22, 0x0000}, {0x26, 0x000F}, {0x28, 0x0605}, {0x2A, 0x0000}, {0x2C, 0xBB80},
    {0x32, 0xBB80}, {0x3A, 0x2000}, {0x5A, 0x0000}, {0x5C, 0x0000}, {0x72, 0x0808},
    {0x74, 0x0000}, {0x76, 0x0006}, {0x78, 0x0000}, {0x7A, 0x0000},
    {kRegVendorId1, kWm97xxId1}, {kRegVendorId2, kWm9705Id2},
};

/* Wolfson WM9705 page 35: "only Revision 2.2 recommended rates are supported"; AC '97 Component
   Specification Revision 2.2 section 1.6 (page 14): "8.0, 11.025, 16.0, 22.05, 32.0, 44.1, and 48 kHz". */
constexpr uint16_t kRates[] = {8000u, 11025u, 16000u, 22050u, 32000u, 44100u, 48000u};

/* Wolfson WM9705 Table 4 (page 23): DAC data DSA[1,0] in 28h, ADC data ASS[1,0] in 5Ch; Table 23
   (page 39): 28h DSA1 D5, DSA0 D4, 5Ch ASS1 D1, ASS0 D0; Table 17 (page 35): DSA 00 = slots 3 and 4. */
constexpr uint32_t kRegExtAudioId = 0x28u;
constexpr uint16_t kDsaMask       = 0x0030u;
constexpr uint32_t kRegAddFunc    = 0x5Cu;
constexpr uint16_t kAssMask       = 0x0003u;
/* Wolfson WM9705 Table 23 (page 39): 20h LPBK D7, 2Ah SPDIF D2, 5Ch I2S D6. */
constexpr uint32_t kRegGeneral = 0x20u;
constexpr uint16_t kLpbk       = 1u << 7;
constexpr uint16_t kSpdif      = 1u << 2;
constexpr uint16_t kI2s        = 1u << 6;
}  // namespace

bool Wm9705Codec::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Falcon4220;
}

void Wm9705Codec::OnReady() {
    Wm97xxCodec::OnReady();
    ColdReset();
}

void Wm9705Codec::LoadDefaults() {
    for (uint16_t& r : reg_) r = 0u;
    for (const RegDefault& d : kDefaults) reg_[d.reg] = d.value;
    ResetRates();
}

const uint16_t* Wm9705Codec::SupportedRates(uint32_t& count) const {
    count = static_cast<uint32_t>(sizeof(kRates) / sizeof(kRates[0]));
    return kRates;
}

void Wm9705Codec::ColdReset() {
    LoadDefaults();
    digitiser_.Clear(pen_down_);
}

void Wm9705Codec::RequireRegister(uint32_t reg) {
    if (reg >= kNumRegs) emu_.Get<Fatal>().Die("Wm9705Codec: codec register index 0x%X out of range", reg);
}

uint16_t Wm9705Codec::Peek(uint32_t reg) {
    RequireRegister(reg);
    return reg_[reg];
}

void Wm9705Codec::Poke(uint32_t reg, uint16_t value) {
    RequireRegister(reg);
    reg_[reg] = value;
}

uint16_t Wm9705Codec::ReadReg(uint32_t reg, uint64_t frame) {
    switch (reg) {
    case kRegMixerMute:   return kMixerMuteRead;
    case kRegDigitiser1:  return static_cast<uint16_t>((reg_[reg] & ~kPoll) | (digitiser_.Polling(frame) ? kPoll : 0u));
    case kRegDigitiserRd: return LastResultWord(frame, reg_[kRegDigitiserRd]);
    default:              return ReadStored(reg);
    }
}

/* AC '97 Component Specification Revision 2.1 section 6.3.1 (page 39): "Writing any
   value to this register performs a register reset, which causes all registers to
   revert to their default values." */
void Wm9705Codec::WriteReg(uint32_t reg, uint16_t value, uint64_t frame) {
    if (reg == kRegReset) {
        LoadDefaults();
        Reconfigure(frame, false);
        return;
    }
    if (reg == kRegMixerMute && value != 0u) {
        emu_.Get<Fatal>().Die("Wm9705Codec: register 5Ah write 0x%04X; not modelled", value);
    }
    if (reg == kRegDigitiserRd) {
        emu_.Get<Fatal>().Die("Wm9705Codec: write 0x%04X to the read-only register 7Ah", value);
    }
    if (WriteRateRegister(reg, value)) return;
    Poke(reg, value);
    if (reg == kRegExtAudioCtrl) OnExtAudioCtrlWrite();
    if (reg == kRegDigitiser1 || reg == kRegDigitiserPower) {
        Reconfigure(frame, reg == kRegDigitiser1 && (value & kPoll) != 0u);
    }
}

/* Wolfson WM9705 page 51: "Setting PRP[1:0] to 00 will power off the digitiser and pen down
   detection". */
void Wm9705Codec::Reconfigure(uint64_t frame, bool poll) {
    const uint16_t d1 = reg_[kRegDigitiser1];
    const uint16_t d2 = reg_[kRegDigitiserPower];
    if ((d2 & (kWait | kMskMask)) != 0u) {
        emu_.Get<Fatal>().Die("Wm9705Codec: register 78h 0x%04X sets WAIT or MSK; not modelled", d2);
    }
    const bool    powered = DigitiserPowered();
    const uint8_t adr     = static_cast<uint8_t>((d1 >> 12) & 7u);
    if ((d1 & kSlen) != 0u && (d1 & 7u) != 0u) {
        emu_.Get<Fatal>().Die("Wm9705Codec: register 76h 0x%04X routes digitiser data to slot %u; not modelled",
                              d1, 5u + (d1 & 7u));
    }
    Wm97xxDigitiser::Sequence seq;
    seq.to_slot = (d1 & kSlen) != 0u;
    if (poll) {
        if (!powered || (d1 & kCtc) != 0u || (d2 & kPden) != 0u || ((d1 & kCoo) != 0u) != (adr == 0u)) {
            emu_.Get<Fatal>().Die("Wm9705Codec: polled conversion with 76h 0x%04X, 78h 0x%04X; not modelled",
                                  d1, d2);
        }
        seq.delay   = DelayFrames((d1 >> 4) & 0xFu, d1);
        seq.count   = (d1 & kCoo) != 0u ? 2u : 1u;
        seq.tags[0] = (d1 & kCoo) != 0u ? kAdrX : adr;
        seq.tags[1] = kAdrY;
        digitiser_.StartPolled(frame, seq, false);
        return;
    }
    if ((d1 & kCtc) == 0u || !powered) {
        digitiser_.SetContinuous(frame, nullptr);
        return;
    }
    if ((d1 & kCoo) == 0u || adr != 0u) {
        emu_.Get<Fatal>().Die("Wm9705Codec: continuous conversion with 76h 0x%04X other than X and Y "
                              "co-ordinates; not modelled", d1);
    }
    seq.delay     = DelayFrames((d1 >> 4) & 0xFu, d1);
    seq.period    = kCrFrames[(d1 >> 8) & 3u];
    seq.count     = 2u;
    seq.tags[0]   = kAdrX;
    seq.tags[1]   = kAdrY;
    seq.pen_gated = (d2 & kPden) != 0u;
    digitiser_.SetContinuous(frame, &seq);
}

uint16_t Wm9705Codec::ConversionData(uint8_t tag) {
    switch (tag) {
    case kAdrX:      return RawX();
    case kAdrY:      return RawY();
    case kAdrAuxAdc: return kAuxAdcValue;
    default:
        emu_.Get<Fatal>().Die("Wm9705Codec: conversion of ADR channel %u; not modelled", tag);
    }
}

/* Wolfson WM9705 Table 15 "Powerdown Control Register Function" (page 33): "PR0
   PCM in ADCs and input Mux Powerdown", "PR1 PCM out DACs Powerdown"; "PR0 and
   PR1 control the PCM ADCs and DACs only." */
/* Wolfson WM9705 page 32: "The LPBK bit enables loopback of the ADC output to the DAC input without
   involving the AC-link"; page 21: "WM9705 supports SPDIF and I2S data only at the default 48ks/s
   frame rate". */
bool Wm9705Codec::DacPowered() {
    const bool on = (reg_[kRegPowerdown] & kPr1) == 0u;
    if (on && ((reg_[kRegExtAudioId] & kDsaMask) != 0u || (reg_[kRegGeneral] & kLpbk) != 0u ||
               (reg_[kRegExtAudioCtrl] & kSpdif) != 0u || (reg_[kRegAddFunc] & kI2s) != 0u)) {
        emu_.Get<Fatal>().Die("Wm9705Codec: DAC on with 28h 0x%04X, 20h 0x%04X, 2Ah 0x%04X, 5Ch 0x%04X "
                              "(slot mapping, loopback, SPDIF or I2S output); not modelled",
                              reg_[kRegExtAudioId], reg_[kRegGeneral], reg_[kRegExtAudioCtrl],
                              reg_[kRegAddFunc]);
    }
    return on;
}

/* Wolfson WM9705 page 28: the ADC output "may alternatively be mapped onto slots 6 and 9, or 7 and
   8 under control of the mapping bits ASS[1:0] in register 5Ch". */
bool Wm9705Codec::AdcPowered() {
    const bool on = (reg_[kRegPowerdown] & kPr0) == 0u;
    if (on && (reg_[kRegAddFunc] & kAssMask) != 0u) {
        emu_.Get<Fatal>().Die("Wm9705Codec: register 5Ch 0x%04X moves the ADC data off slots 3 and 4; "
                              "not modelled", reg_[kRegAddFunc]);
    }
    return on;
}

void Wm9705Codec::SaveState(StateWriter& w) {
    w.WriteBytes("reg", reg_, sizeof(reg_));
    SaveRates(w);
    SavePen(w);
}

void Wm9705Codec::RestoreState(StateReader& r) {
    r.ReadBytes("reg", reg_, sizeof(reg_));
    RestoreRates(r);
    RestorePen(r);
}

REGISTER_SERVICE_AS(Wm9705Codec, Ac97Codec);
